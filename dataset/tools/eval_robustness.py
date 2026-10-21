#!/usr/bin/env python3
"""Problem-space robustness suite (Shallow Security, GAMMA, Lucas et al. 2023, Arp P10).

Applies functionality-preserving byte edits IN MEMORY to held-out malware (recent_test,
de-duplicated) and re-scores with the full serving pipeline. Nothing is written to
disk, nothing is executed, no attack binary leaves this process.

Attacks (all keep the original code path intact):
  overlay_64k / overlay_1m / overlay_4m : append benign goodware bytes as overlay
  strings_10k                            : append 10k printable strings harvested from goodware
  section_inject                         : add a benign donor's .rdata-like content as a new section (lief builder)
  header_copy                            : copy mutable header metadata (timestamp, linker/OS/image versions) from a donor
  cert_blob                              : append a real goodware Authenticode blob (signature theft without re-signing)
Compares v3 (defender.ensemble) with the deployed v2 rule (6.73e + 9.25r - 5.42 > 1.80).
"""
from __future__ import annotations
import json, multiprocessing as mp, os, pathlib, random, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROD = ROOT / "defender_product"
_S = {}


VARIANTS = {
    "v3": {"DF_EMBER_FT": "models/ember_ft/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion.json"},
    "v4": {"DF_EMBER_FT": "models/ember_ft_v4/ember_ft.txt", "DF_RF_DIR": "models/rf_v4", "DF_FUSION": "models/fusion_v4.json"},
    "v41": {"DF_EMBER_FT": "models/ember_ft_v41/ember_ft.txt", "DF_RF_DIR": "models/rf_v41", "DF_FUSION": "models/fusion_v41.json"},
    "v31": {"DF_EMBER_FT": "models/ember_ft_v31/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion_v31.json"},
    "v32": {"DF_EMBER_FT": "models/ember_ft_v32/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion_v32.json"},
    "v33": {"DF_EMBER_FT": "models/ember_ft_v33/ember_ft.txt", "DF_RF_DIR": "models/rf_adv", "DF_FUSION": "models/fusion_v33.json"},
}
VARIANT = os.environ.get("ROBUST_VARIANT", "v3")


def _init():
    sys.path.insert(0, str(PROD))
    os.environ.update(DF_EMBER_MODEL=str(PROD / "models/ember_gbdt/ember_gbdt.txt"), OMP_NUM_THREADS="1",
                      **{k: str(PROD / v) for k, v in VARIANTS[VARIANT].items()})
    import lief
    lief.logging.disable()
    from defender.ensemble import Ensemble
    _S["m"] = Ensemble(); _S["lief"] = lief
    rng = random.Random(7)
    good = [json.loads(l) for l in open(ROOT / "dataset/work/live_cache/meta_goodware.jsonl")]
    exes = [d for d in good if not d["pe"].get("is_dll") and not d["pe"].get("is_dotnet")]
    _S["donors"] = [pathlib.Path(ROOT / f"dataset/goodware/pe/{d['sha256']}.bin").read_bytes() for d in rng.sample(exes, 12)]
    signed = [d for d in exes if d["pe"].get("sig_verify") == "OK"]
    _S["signed"] = [pathlib.Path(ROOT / f"dataset/goodware/pe/{d['sha256']}.bin").read_bytes() for d in rng.sample(signed, 4)]


def v2(m, b):
    try:
        e, _ = m._ember_members(b)
    except Exception:
        e = 1.0
    try:
        r = m._rf_member(b)
    except Exception:
        r = 1.0
    return int(6.73086 * e + 9.25215 * r - 5.41572 > 1.80)


def _strings(donor: bytes, n: int) -> bytes:
    import re
    ss = re.findall(rb"[\x20-\x7e]{6,40}", donor)
    out = []
    while len(out) < n and ss:
        out.extend(ss)
    return b"\x00".join(out[:n])


def attack(name: str, b: bytes, rng: random.Random) -> bytes | None:
    lief = _S["lief"]
    donor = rng.choice(_S["donors"])
    if name == "clean":
        return b
    if name.startswith("overlay_"):
        n = {"overlay_64k": 64 << 10, "overlay_1m": 1 << 20, "overlay_4m": 4 << 20}[name]
        pad = (donor * (n // max(1, len(donor)) + 1))[:n]
        return b + pad
    if name == "strings_10k":
        return b + _strings(donor, 10000)
    if name == "cert_blob":
        sd = rng.choice(_S["signed"])
        pe = lief.PE.parse(sd)
        cd = pe.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        return b + sd[cd.rva:cd.rva + cd.size]
    pe = lief.PE.parse(b)
    if pe is None:
        return None
    if name == "header_copy":
        dp = lief.PE.parse(donor)
        pe.header.time_date_stamps = dp.header.time_date_stamps
        for f in ("major_linker_version", "minor_linker_version", "major_operating_system_version",
                  "minor_operating_system_version", "major_image_version", "minor_image_version"):
            setattr(pe.optional_header, f, getattr(dp.optional_header, f))
    elif name == "section_inject":
        dp = lief.PE.parse(donor)
        src = next((s for s in dp.sections if s.name.startswith(".rdata")), dp.sections[-1])
        sec = lief.PE.Section(".rdata2")
        sec.content = list(bytes(src.content)[:256 << 10])
        sec.characteristics = int(lief.PE.Section.CHARACTERISTICS.MEM_READ) | int(lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA)
        pe.add_section(sec)
    # rebuild entirely in memory (never written to disk)
    bld = lief.PE.Builder(pe, lief.PE.Builder.config_t())
    bld.build()
    return bytes(bld.bytes())


ATTACKS = ["clean", "overlay_64k", "overlay_1m", "overlay_4m", "strings_10k", "section_inject", "header_copy", "cert_blob"]


def work(sha):
    import pyzipper
    with pyzipper.AESZipFile(ROOT / f"dataset/quarantine/archives/{sha}.zip") as a:
        a.setpassword(b"infected"); b = a.read(a.infolist()[0])
    rng = random.Random(sha)
    res = {}
    for name in ATTACKS:
        try:
            x = attack(name, b, rng)
        except Exception:
            x = None
        if x is None:
            res[name] = None
            continue
        t = time.time()
        res[name] = (_S["m"].predict(x), v2(_S["m"], x), round(time.time() - t, 3))
    return res


def main():
    rt = [json.loads(l)["sha256"] for l in open(ROOT / "dataset/work/recent_test.jsonl") if json.loads(l)["label"] == 1]
    dups = set(json.load(open(ROOT / "dataset/work/exp/recent_test_nfs_dups.json")))
    shas = [s for s in rt if s not in dups]
    with mp.Pool(8, initializer=_init) as pool:
        rows = pool.map(work, shas, chunksize=4)
    print(f"held-out malware: {len(shas)} (recent_test minus feature-duplicates)")
    print(f"variant under test: {VARIANT} (column 'v3 TPR' = this variant)")
    print(f"{'attack':16s} {'n':>4s} | {'v3 TPR':>7s} | {'v2 TPR':>7s} | max latency")
    out = {}
    for name in ATTACKS:
        ok = [r[name] for r in rows if r[name] is not None]
        if not ok:
            print(f"{name:16s} n/a"); continue
        v3 = sum(x[0] for x in ok) / len(ok); v2r = sum(x[1] for x in ok) / len(ok)
        out[name] = {"n": len(ok), "v3_tpr": v3, "v2_tpr": v2r}
        print(f"{name:16s} {len(ok):4d} | {v3:7.3f} | {v2r:7.3f} | {max(x[2] for x in ok):.2f}s")
    json.dump(out, open(ROOT / f"dataset/work/exp/robustness_{VARIANT}.json", "w"), indent=2)


if __name__ == "__main__":
    main()
