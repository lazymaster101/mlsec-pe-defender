#!/usr/bin/env python3
"""Collect a DIVERSE native-EXE goodware corpus (Arp et al. P1; synthesizer plan X2).

Why: v3's binding constraint is FPR on goodware EXEs, measured on only ~430-590 files
from few products. This builds >= 2,000 EXEs from hundreds of products so thresholds
can be calibrated and evaluated on the population whose false positives matter.

Sources (both static downloads; NOTHING is installed or executed):
  github  repositories discovered by GitHub search across languages/domains; latest
          release; Windows .zip/.tar.gz assets are unpacked in memory, bare .exe assets
          (portable tools and installers) are kept as-is.
  choco   Chocolatey community packages ranked by downloads; the vendor download URL
          is read from tools/chocolateyInstall.ps1 (url/url64) and fetched from the
          vendor; binaries embedded in the .nupkg are also taken.
Safety / label hygiene:
  * deny-list on repo/package names, descriptions, topics and tags (RATs, C2, stealers,
    crackers, cheats, miners, red-team tooling... several of our malware families are
    open source on GitHub, so this matters);
  * any file whose sha256 is in our malware corpus is dropped and reported;
  * per-product caps (default 6 EXE + 2 DLL) so no product dominates; size caps;
  * archives are processed in memory and discarded; only PE members are written, as
    <sha256>.bin with provenance in index.jsonl (product = grouping key for CV).

  python dataset/tools/collect_exe_goodware.py --target-exe 2500
"""
from __future__ import annotations
import argparse, concurrent.futures as cf, hashlib, io, json, pathlib, re, ssl, subprocess, sys
import tarfile, threading, time, urllib.parse, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "dataset/goodware2"
GH = "/opt/homebrew/bin/gh"
UA = {"User-Agent": "csce704-goodware-collector/1.0"}
try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()

DENY_TOKENS = {"rat", "c2", "kms", "rdp", "keylogger", "stealer", "crypter", "injector", "cheat",
               "cheats", "aimbot", "trainer", "keygen", "crack", "cracked", "cracker", "miner",
               "xmrig", "botnet", "backdoor", "trojan", "malware", "virus", "ransomware",
               "rootkit", "exploit", "exploits", "payload", "payloads", "shellcode", "mimikatz",
               "pentest", "pentesting", "redteam", "phishing", "spyware", "loader", "bypass",
               "evasion", "obfuscator", "obfuscation", "hacking", "hack", "hacktool", "hacktools",
               "activator", "unlocker", "patcher", "bruteforce", "sniffer", "dumper", "spoofer",
               "beacon", "implant", "persistence", "privesc", "uac", "amsi", "edr", "defender-control",
               "nirsoft", "stresser", "ddos", "booter", "grabber", "clipper", "hvnc", "vnc"}
DENY_SUBSTR = ("red-team", "red team", "command-and-control", "command and control", "remote access tool",
               "remote-access-tool", "penetration test", "privilege escalation", "process hollowing",
               "dll injection", "dll-injection", "password recovery", "password-recovery", "credential",
               "anti-virus evasion", "av evasion", "offensive", "post-exploitation", "post exploitation",
               "game hack", "cheat engine", "windows activation", "license bypass",
               # tools AV vendors flag as HackTool/PUA even though they are not malware:
               "defender-remov", "defender remov", "remove defender", "disable defender", "defender-disab",
               "disable-defender", "windows-defender", "debloat", "anti-telemetry", "privacy tweak")
GH_QUERIES = [
    "topic:windows stars:>300", "topic:windows-app stars:>100", "topic:cli language:Go stars:>800",
    "topic:cli language:Rust stars:>800", "language:C++ topic:windows stars:>150",
    "language:C topic:windows stars:>150", "language:C# topic:windows stars:>300",
    "language:C# topic:wpf stars:>300", "language:Pascal stars:>150", "language:Nim stars:>250",
    "language:Zig stars:>400", "topic:portable stars:>100", "topic:emulator stars:>800",
    "topic:text-editor stars:>400", "topic:utility stars:>300", "topic:desktop-app stars:>800",
    "topic:audio stars:>1500", "topic:video-player stars:>500", "topic:game stars:>2000",
    "topic:devtools stars:>2000", "topic:file-manager stars:>300", "topic:screenshot stars:>300",
    "topic:system-monitor stars:>300", "language:Python topic:windows stars:>400",
    "topic:electron stars:>3000", "topic:gui stars:>1500 language:C++", "topic:qt stars:>800",
    "topic:compression stars:>300", "topic:backup stars:>500", "topic:database-gui stars:>300",
]
WIN_ASSET = re.compile(r"(windows|win64|win32|[-_.]win[-_.]|win-x64|win-x86|pc-windows|_win|-win\b|\.exe$)", re.I)
NOT_WIN = re.compile(r"(linux|darwin|macos|osx|apple|android|ios|freebsd|openbsd|netbsd|solaris|"
                     r"source|src|sources|debug|symbols|pdb|sha256|checksums|\.sig$|\.asc$|\.sbom|\.deb$|\.rpm$)", re.I)
_lock = threading.Lock()


def deny(*texts: str) -> str | None:
    blob = " ".join(t for t in texts if t).lower()
    toks = set(re.split(r"[^a-z0-9]+", blob))
    hit = toks & DENY_TOKENS
    if hit:
        return sorted(hit)[0]
    for s in DENY_SUBSTR:
        if s in blob:
            return s
    return None


def greyware_groups(index_path: pathlib.Path) -> list[str]:
    """Products in an existing index that the CURRENT deny rules would reject (the rules
    grew after collection started); training/eval scripts exclude these groups."""
    out = set()
    for l in open(index_path):
        d = json.loads(l)
        # product identity only: member names like ssh-keygen.exe are legitimate
        if deny(d["product"].split(":", 1)[-1].replace("/", " ")):
            out.add(d["product"])
    return sorted(out)


def gh_json(path: str, retries: int = 4):
    for i in range(retries):
        r = subprocess.run([GH, "api", "-H", "Accept: application/vnd.github+json", path],
                           capture_output=True, text=True, timeout=90)
        if r.returncode == 0:
            return json.loads(r.stdout)
        msg = (r.stderr + r.stdout).lower()
        if "rate limit" in msg or "403" in msg:
            print(f"  gh rate-limited on {path[:60]} (retry {i+1})", flush=True)
            time.sleep(20 * (i + 1)); continue
        return None
    return None


def fetch(url: str, cap: int, timeout: int = 180, accept: str | None = None) -> bytes | None:
    req = urllib.request.Request(url, headers={**UA, **({"Accept": accept} if accept else {})})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        n = int(r.headers.get("Content-Length") or 0)
        if n and n > cap:
            return None
        data = r.read(cap + 1)
    return data if len(data) <= cap else None


def is_pe(b: bytes) -> bool:
    if len(b) < 256 or b[:2] != b"MZ":
        return False
    off = int.from_bytes(b[0x3C:0x40], "little")
    return 0 < off < len(b) - 4 and b[off:off + 4] == b"PE\x00\x00"


def is_dll(b: bytes) -> bool:
    off = int.from_bytes(b[0x3C:0x40], "little")
    return bool(int.from_bytes(b[off + 22:off + 24], "little") & 0x2000)


def pes_from_blob(name: str, blob: bytes, max_member: int):
    """yield (member_name, bytes) for PE files inside a zip / tar.gz, or the blob itself."""
    low = name.lower()
    if low.endswith(".zip") or blob[:4] == b"PK\x03\x04":
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
            for zi in zf.infolist():
                if zi.is_dir() or zi.file_size > max_member or zi.file_size < 256:
                    continue
                if not zi.filename.lower().endswith((".exe", ".dll", ".scr", ".cpl", ".ocx", ".sys")):
                    continue
                try:
                    d = zf.read(zi)
                except Exception:
                    continue
                if is_pe(d):
                    yield zi.filename, d
        except Exception:
            return
    elif low.endswith((".tar.gz", ".tgz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and 256 <= m.size <= max_member and m.name.lower().endswith((".exe", ".dll")):
                        d = tf.extractfile(m).read()
                        if is_pe(d):
                            yield m.name, d
        except Exception:
            return
    elif is_pe(blob) and len(blob) <= max_member:
        yield name, blob


class Store:
    def __init__(self, out: pathlib.Path, block: set[str]):
        self.out = out; (out / "pe").mkdir(parents=True, exist_ok=True)
        self.index = out / "index.jsonl"; self.state = out / "done_products.txt"
        self.have = {json.loads(l)["sha256"] for l in self.index.open()} if self.index.exists() else set()
        self.done = set(self.state.read_text().split("\n")) if self.state.exists() else set()
        self.block = block; self.n_exe = sum(1 for l in self.index.open() if not json.loads(l)["is_dll"]) if self.index.exists() else 0
        self.blocked_hits = []
        self.total = sum(f.stat().st_size for f in (out / "pe").iterdir())

    def add(self, b: bytes, meta: dict) -> bool:
        h = hashlib.sha256(b).hexdigest()
        with _lock:
            if h in self.block:
                self.blocked_hits.append((h, meta.get("product"))); return False
            if h in self.have:
                return False
            self.have.add(h)
            (self.out / "pe" / f"{h}.bin").write_bytes(b)
            self.total += len(b)
            rec = {"sha256": h, "bytes": len(b), "is_dll": is_dll(b), **meta}
            with self.index.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
            if not rec["is_dll"]:
                self.n_exe += 1
            return True

    def mark(self, product: str):
        with _lock:
            self.done.add(product)
            with self.state.open("a") as fh:
                fh.write(product + "\n")


def take(store: Store, product: str, source: str, url: str, name: str, blob: bytes, args, counts):
    for member, d in pes_from_blob(name, blob, args.max_member):
        dll = is_dll(d)
        if dll and counts["dll"] >= args.max_dll:
            continue
        if not dll and counts["exe"] >= args.max_exe:
            continue
        if store.add(d, {"source": source, "product": product, "url": url, "asset": name, "member": member}):
            counts["dll" if dll else "exe"] += 1
        if counts["exe"] >= args.max_exe and counts["dll"] >= args.max_dll:
            break


def do_github_repo(store: Store, repo: dict, args) -> tuple[str, int]:
    full = repo["full_name"]; product = f"github:{full}"
    if product in store.done:
        return full, 0
    why = deny(full, repo.get("description") or "", " ".join(repo.get("topics") or []))
    if why:
        store.mark(product); return f"{full} (denied: {why})", 0
    rel = gh_json(f"repos/{full}/releases/latest")
    counts = {"exe": 0, "dll": 0}
    if rel and isinstance(rel, dict):
        assets = [a for a in rel.get("assets", []) if WIN_ASSET.search(a["name"]) and not NOT_WIN.search(a["name"])
                  and a["name"].lower().endswith((".zip", ".exe", ".tar.gz", ".tgz")) and a.get("size", 0) <= args.max_asset]
        assets.sort(key=lambda a: (not a["name"].lower().endswith(".zip"), "arm" in a["name"].lower(), a.get("size", 0)))
        for a in assets[:2]:
            try:
                blob = fetch(a["browser_download_url"], args.max_asset)
            except Exception:
                continue
            if blob:
                take(store, product, "github", a["browser_download_url"], a["name"], blob, args, counts)
    store.mark(product)
    return full, counts["exe"] + counts["dll"]


URL_RE = re.compile(r"(?i)\$?(?:url64bit|url64|url)\s*=\s*['\"](https?://[^'\"\s]+)['\"]")


def do_choco_pkg(store: Store, pkg: dict, args) -> tuple[str, int]:
    pid = pkg["id"]; product = f"choco:{pid}"
    if product in store.done:
        return pid, 0
    why = deny(pid, pkg.get("title", ""), pkg.get("tags", ""), pkg.get("summary", ""))
    if why:
        store.mark(product); return f"{pid} (denied: {why})", 0
    counts = {"exe": 0, "dll": 0}
    try:
        nupkg = fetch(f"https://community.chocolatey.org/api/v2/package/{pid}", 80 << 20)
    except Exception:
        nupkg = None
    urls = []
    if nupkg:
        take(store, product, "choco-embedded", f"nupkg:{pid}", f"{pid}.nupkg", nupkg, args, counts)
        try:
            zf = zipfile.ZipFile(io.BytesIO(nupkg))
            for n in zf.namelist():
                if n.lower().endswith("chocolateyinstall.ps1"):
                    urls = URL_RE.findall(zf.read(n).decode("utf-8", "ignore"))
        except Exception:
            pass
    urls = sorted(set(u for u in urls if not u.lower().split("?")[0].endswith((".msi", ".7z", ".rar", ".msix", ".appx"))),
                  key=lambda u: ("64" not in u, u))
    for u in urls[:2]:
        if counts["exe"] >= args.max_exe:
            break
        try:
            blob = fetch(u, args.max_asset)
        except Exception:
            continue
        if blob:
            take(store, product, "choco-vendor", u, urllib.parse.urlparse(u).path.rsplit("/", 1)[-1] or "download", blob, args, counts)
    store.mark(product)
    return pid, counts["exe"] + counts["dll"]


def github_repos(limit_per_query: int, n_queries: int):
    cache = OUT / "gh_repos.json"
    if cache.exists():
        return json.load(open(cache))
    seen = {}
    for qi, q in enumerate(GH_QUERIES[:n_queries]):
        t = time.time()
        for page in range(1, limit_per_query // 100 + 1):
            res = gh_json(f"search/repositories?q={urllib.parse.quote(q)}&sort=stars&order=desc&per_page=100&page={page}")
            time.sleep(2.2)  # search API: 30 req/min
            if not res or not res.get("items"):
                break
            for r in res["items"]:
                seen.setdefault(r["full_name"], {k: r.get(k) for k in ("full_name", "description", "topics", "stargazers_count")})
            if len(res["items"]) < 100:
                break
        print(f"  query {qi+1}/{n_queries} '{q}': {len(seen)} repos so far ({time.time()-t:.0f}s)", flush=True)
    json.dump(list(seen.values()), open(cache, "w"))
    return list(seen.values())


def choco_packages(n: int):
    """Page the community OData feed by download count. The feed answers 406 unless it
    gets an explicit Atom Accept header and %20 (not '+') in $orderby."""
    from xml.etree import ElementTree as ET
    A = "{http://www.w3.org/2005/Atom}"
    M = "{http://schemas.microsoft.com/ado/2007/08/dataservices/metadata}"
    D = "{http://schemas.microsoft.com/ado/2007/08/dataservices}"
    out, seen, skip = [], set(), 0
    while len(out) < n:
        q = urllib.parse.urlencode({"$filter": "IsLatestVersion", "$orderby": "DownloadCount desc", "$top": 100,
                                    "$skip": skip}, safe="$", quote_via=urllib.parse.quote)
        try:
            body = fetch(f"https://community.chocolatey.org/api/v2/Packages()?{q}", 50 << 20, timeout=120,
                         accept="application/atom+xml,application/xml;q=0.9,*/*;q=0.8")
            root = ET.fromstring(body)
        except Exception as e:
            print(f"  choco feed skip={skip} failed: {e}", flush=True); break
        entries = root.findall(f"{A}entry")
        if not entries:
            break
        skip += len(entries)   # the feed may return fewer than $top per page
        for e in entries:
            pid = e.findtext(f"{A}title")
            props = e.find(f".//{M}properties")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            g = (lambda t: (props.findtext(f"{D}{t}") or "") if props is not None else "")
            out.append({"id": pid, "title": g("Title"), "tags": g("Tags"), "summary": g("Summary")})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-exe", type=int, default=2500)
    ap.add_argument("--max-exe", type=int, default=6)
    ap.add_argument("--max-dll", type=int, default=2)
    ap.add_argument("--max-asset", type=int, default=80 << 20)
    ap.add_argument("--max-member", type=int, default=64 << 20)
    ap.add_argument("--gh-per-query", type=int, default=300)
    ap.add_argument("--choco", type=int, default=900)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--queries", type=int, default=len(GH_QUERIES))
    ap.add_argument("--max-total-gb", type=float, default=8.0)
    args = ap.parse_args()
    block = set()
    for c in ("malware", "grading"):
        p = ROOT / f"dataset/work/live_cache/meta_{c}.jsonl"
        if p.exists():
            block |= {json.loads(l)["sha256"] for l in p.open()}
    store = Store(OUT, block)
    for c in ("goodware", "local", "course"):   # don't re-collect what we already have
        p = ROOT / f"dataset/work/live_cache/meta_{c}.jsonl"
        if p.exists():
            store.have |= {json.loads(l)["sha256"] for l in p.open()}
    print(f"start: {store.n_exe} EXEs in goodware2; blocklist {len(block)} malware/grading hashes", flush=True)

    t0 = time.time()
    repos = github_repos(args.gh_per_query, args.queries)
    print(f"github: {len(repos)} candidate repos from {len(GH_QUERIES)} queries ({time.time()-t0:.0f}s)", flush=True)
    pkgs = choco_packages(args.choco)
    print(f"choco: {len(pkgs)} packages", flush=True)
    gj = [("gh", r) for r in repos]; cj = [("choco", p) for p in pkgs]
    # interleave sources so an early stop still yields a mix
    jobs = [j for pair in zip(gj, cj) for j in pair] + gj[len(cj):] + cj[len(gj):]
    done = 0
    with cf.ThreadPoolExecutor(args.workers) as ex:
        futs = {}
        it = iter(jobs)
        for _ in range(args.workers * 2):
            j = next(it, None)
            if j:
                futs[ex.submit(do_github_repo if j[0] == "gh" else do_choco_pkg, store, j[1], args)] = j
        while futs:
            fin, _ = cf.wait(futs, return_when=cf.FIRST_COMPLETED)
            for f in fin:
                futs.pop(f); done += 1
                try:
                    name, n = f.result()
                except Exception as e:
                    name, n = f"error {e!r}"[:80], 0
                if n or done % 50 == 0:
                    print(f"[{done}/{len(jobs)}] {name}: +{n} | EXEs={store.n_exe} | {store.total/2**30:.2f} GB | {time.time()-t0:.0f}s", flush=True)
                if store.n_exe < args.target_exe and store.total < args.max_total_gb * 2**30:
                    j = next(it, None)
                    if j:
                        futs[ex.submit(do_github_repo if j[0] == "gh" else do_choco_pkg, store, j[1], args)] = j
    print(f"finished: EXEs={store.n_exe}, total PEs={len(store.have)} known; "
          f"malware/grading hash collisions dropped: {len(store.blocked_hits)} {store.blocked_hits[:5]}", flush=True)


if __name__ == "__main__":
    main()
