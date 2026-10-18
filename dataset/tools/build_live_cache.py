#!/usr/bin/env python3
"""Build the live feature cache every v3 experiment trains/evaluates from.

For each sample, using EXACTLY the serving code path (submission/defender: vendored
EMBER extractor + ember_compat, NFS features, deployed ember_gbdt + rf_adv):
  X        EMBER-2381 vector (lief-0.17, as served)
  e, r     deployed ember_gbdt / rf_adv scores
  nfs      NFS attribute dict (JSON) so NFS-space models can be retrained
  meta     label, group (malware family / goodware package), source, first_seen,
           Authenticode facts (signature present, LIEF verification flags, signer +
           chain subjects/issuers/fingerprints), file-type facts (.NET, DLL, machine,
           overlay size, max section entropy, size).

Corpora: quarantine malware (decrypted in memory, never written or executed),
goodware/pe, the 7 course goodware exes, and the course grading set, which is written
to its OWN file and is never to be used for training, selection or calibration.

Bytes are only parsed. Nothing is executed.
"""
from __future__ import annotations
import argparse, hashlib, json, math, multiprocessing as mp, os, pathlib, sys, time
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "dataset/work/live_cache"
GS = ROOT / "csce704-blackbox-validation-100-samples-20261014-corrected"
_W = {}


def _init():
    sys.path.insert(0, str(ROOT / "submission"))
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    import lightgbm as lgb
    from defender import ember_features, ember_compat  # noqa: F401
    from defender import features as nfs_features
    from defender.model import Model
    import lief
    lief.logging.disable()
    _W["ext"] = ember_features.PEFeatureExtractor(2, print_feature_warning=False)
    _W["gbdt"] = lgb.Booster(model_file=str(ROOT / "submission/models/ember_gbdt/ember_gbdt.txt"))
    _W["rf"] = Model(str(ROOT / "submission/models/rf_adv"), "training")
    _W["nfs"] = nfs_features
    _W["lief"] = lief


def _load(item):
    kind, ref = item["kind"], item["ref"]
    if kind == "zip":
        import pyzipper
        with pyzipper.AESZipFile(ref) as a:
            a.setpassword(b"infected")
            return a.read(a.infolist()[0])
    return pathlib.Path(ref).read_bytes()


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(np.float64)
    p = c[c > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def _pe_facts(bytez: bytes) -> dict:
    lief = _W["lief"]
    f = {"parsed": False}
    try:
        pe = lief.PE.parse(bytez)
    except Exception:
        pe = None
    if pe is None:
        return f
    f["parsed"] = True
    try:
        f["machine"] = str(pe.header.machine).split(".")[-1]
        f["is_dll"] = bool(pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL))
        f["is_dotnet"] = bool(pe.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER).size > 0)
        f["overlay"] = int(len(pe.overlay))
        f["n_sections"] = len(pe.sections)
        f["max_sec_entropy"] = max((float(s.entropy) for s in pe.sections), default=0.0)
        f["sec_names"] = [s.name for s in pe.sections][:16]
    except Exception as e:
        f["facts_err"] = repr(e)[:120]
    # Authenticode
    try:
        f["has_sig"] = bool(pe.has_signatures)
        if pe.has_signatures:
            vf = pe.verify_signature()
            f["sig_verify"] = str(vf).split(".")[-1]
            sig = pe.signatures[0]
            certs = []
            for c in sig.certificates:
                try:
                    der = bytes(c.raw)
                except Exception:
                    der = b""
                certs.append({"subject": c.subject, "issuer": c.issuer,
                              "sha256": hashlib.sha256(der).hexdigest() if der else ""})
            f["certs"] = certs
            try:
                s0 = sig.signers[0]
                f["signer_issuer"] = s0.issuer
                f["signer_subject"] = s0.cert.subject if s0.cert else ""
            except Exception:
                pass
    except Exception as e:
        f["sig_err"] = repr(e)[:120]
    return f


def work(item):
    t0 = time.time()
    rec = {k: v for k, v in item.items() if k not in ("ref",)}
    try:
        b = _load(item)
    except Exception as e:
        rec["err"] = "load:" + repr(e)[:100]
        return rec, None
    rec["size"] = len(b)
    rec["file_entropy"] = _entropy(b)
    try:
        v = np.asarray(_W["ext"].feature_vector(b), dtype=np.float32)
        rec["e"] = float(_W["gbdt"].predict(v.reshape(1, -1))[0])
    except Exception as e:
        v = None
        rec["e"] = 1.0
        rec["ember_err"] = repr(e)[:120]
    try:
        a = _W["nfs"].extract(b, "training")
        rec["r"] = float(_W["rf"].probability(_W["rf"].vectorize(a)))
        rec["nfs"] = a
    except Exception as e:
        rec["r"] = 1.0
        rec["nfs_err"] = repr(e)[:120]
    rec["pe"] = _pe_facts(b)
    rec["secs"] = round(time.time() - t0, 3)
    return rec, v


def _jsonable(o):
    """bytes (e.g. raw section names / NFS strings) -> latin-1 text; anything else -> str."""
    if isinstance(o, (bytes, bytearray)):
        return o.decode("latin-1")
    if isinstance(o, (np.integer, np.floating)):
        return o.item()
    return str(o)


def items_for(corpus: str):
    out = []
    if corpus == "malware":
        for l in open(ROOT / "dataset/quarantine/index.jsonl"):
            d = json.loads(l)
            z = ROOT / f"dataset/quarantine/archives/{d['sha256']}.zip"
            if z.exists():
                out.append({"kind": "zip", "ref": str(z), "sha256": d["sha256"], "label": 1,
                            "group": d.get("family") or "unknown", "first_seen": d.get("first_seen"),
                            "mb_code_sign": bool(d.get("code_sign")), "imphash": d.get("imphash")})
    elif corpus == "goodware":
        for l in open(ROOT / "dataset/goodware/index.jsonl"):
            d = json.loads(l)
            p = ROOT / f"dataset/goodware/pe/{d['sha256']}.bin"
            if p.exists():
                out.append({"kind": "file", "ref": str(p), "sha256": d["sha256"], "label": 0,
                            "group": f"{d.get('source')}:{d.get('package')}", "source": d.get("source"),
                            "member": d.get("member")})
    elif corpus == "course":
        for p in sorted((ROOT / "ml-cybersecuritiy-course/datasets/samples/pe").iterdir()):
            if p.is_file():
                out.append({"kind": "file", "ref": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                            "label": 0, "group": "course:" + p.name, "source": "course"})
    elif corpus == "local":
        # Windows PE files already installed on this machine by legitimate software
        # (JetBrains, Office, VS Code extensions, NuGet cache...). Independent goodware.
        for r in json.load(open(OUT / "local_index.json")):
            out.append({"kind": "file", "ref": r["path"], "sha256": r["sha256"], "label": 0,
                        "group": r["group"], "source": "local"})
    elif corpus == "goodware2":
        # diverse native-EXE goodware collected by collect_exe_goodware.py (GitHub releases,
        # Chocolatey vendor downloads); group = product, the unit for held-out splits
        for l in open(ROOT / "dataset/goodware2/index.jsonl"):
            d = json.loads(l)
            p = ROOT / f"dataset/goodware2/pe/{d['sha256']}.bin"
            if p.exists():
                out.append({"kind": "file", "ref": str(p), "sha256": d["sha256"], "label": 0,
                            "group": d["product"], "source": d["source"], "member": d.get("member")})
    elif corpus == "grading":
        man = json.load(open(GS / "manifest.json"))["samples"]
        for s in man:
            sub = "malware" if s["is_malware"] else "goodware"
            out.append({"kind": "file", "ref": str(GS / sub / f"{s['sha256']}.bin"), "sha256": s["sha256"],
                        "label": int(s["is_malware"]), "group": s.get("family") or s.get("source_name") or "unlabeled"})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpora", default="course,malware,goodware,grading")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    for corpus in args.corpora.split(","):
        items = items_for(corpus)
        t0 = time.time()
        recs, X = [], []
        with mp.Pool(args.workers, initializer=_init, maxtasksperchild=200) as pool:
            for i, (rec, v) in enumerate(pool.imap(work, items, chunksize=4)):
                recs.append(rec)
                X.append(v if v is not None else np.full(2381, np.nan, dtype=np.float32))
                if (i + 1) % 250 == 0:
                    print(f"[{corpus}] {i+1}/{len(items)} {time.time()-t0:.0f}s", flush=True)
        np.save(OUT / f"X_{corpus}.npy", np.stack(X).astype(np.float32))
        with open(OUT / f"meta_{corpus}.jsonl", "w") as fh:
            for r in recs:
                fh.write(json.dumps(r, default=_jsonable) + "\n")
        bad = sum(1 for r in recs if "ember_err" in r or "err" in r)
        print(f"[{corpus}] done {len(recs)} in {time.time()-t0:.0f}s, extraction errors={bad}", flush=True)


if __name__ == "__main__":
    main()
