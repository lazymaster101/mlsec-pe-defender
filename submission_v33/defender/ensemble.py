#!/usr/bin/env python3
"""v3 detector: layered static PE classification (see dataset/docs/V3_DETECTOR.md).

Decision order for one file:
  1. Authenticode TRUST  - a valid signature chaining (cryptographically) to a pinned
     Microsoft first-party code-signing PCA, with no bytes appended after it -> benign.
  2. Authenticode TAMPER - a signature that is present but broken (digest mismatch,
     missing signer cert, invalid signer) -> malicious. 95/1,455 recent malware vs
     0/11,385 goodware carry one; it is the classic "stolen signature blob" tell.
  2b. (v3.1) EMBEDDED COMMAND LINE - the file's own bytes contain a PowerShell command
     line that bypasses the execution policy AND hides its window -> malicious
     (defender/cmdline.py: 0/13,503 goodware, 4/1,455 training malware). Deterministic,
     additive only: it never clears a file.
  3. ML fusion - log-odds logistic fusion of up to three members, fitted on
     out-of-fold scores:  e = ember_gbdt (EMBER-2381, EMBER 2018)
                          r = rf_adv     (NFS header/imports, recent + adversarial)
                          f = ember_gbdt + ember_ft (continued boosting on live
                              recent malware + live goodware, stratum-balanced)
     If one extractor fails the matching fallback fusion is used (EMBER-only 'ef' or
     NFS-only 'r'). A body LIEF cannot parse as a PE is flagged without scoring
     (v3.3; fail toward detection for malformed input), as is a file no extractor can read.

Config via env:
  DF_EMBER_MODEL   ember_gbdt LightGBM text model
  DF_EMBER_FT      ember_ft continued-boosting model (optional; without it 'f' == 'e')
  DF_RF_DIR        rf_adv exported arrays (NFS runtime)
  DF_FUSION        fusion.json (coefficients + thresholds per member subset)
  DF_THRESHOLD_OFFSET  added to every fusion threshold (operator knob; default 0)
"""
from __future__ import annotations
import json
import math
import os

import numpy as np

from defender import cmdline
from defender import features as nfs_features
from defender import trust
from defender.model import Model

_BROKEN_FLAGS = ("BAD_DIGEST", "CERT_NOT_FOUND", "INVALID_SIGNER")


def _logit(p: float, clip: float) -> float:
    p = min(max(p, clip), 1.0 - clip)
    return math.log(p / (1.0 - p))


class Ensemble:
    def __init__(self) -> None:
        import lightgbm as lgb
        import lief
        from defender import ember_features  # vendored EMBER PEFeatureExtractor (no ember pkg)
        from defender import ember_compat  # noqa: F401  patches it for lief-0.17 / numpy-2
        lief.logging.disable()
        self._lief = lief
        self._ext = ember_features.PEFeatureExtractor(2, print_feature_warning=False)
        self._ember = lgb.Booster(model_file=os.environ["DF_EMBER_MODEL"])
        ft_path = os.environ.get("DF_EMBER_FT", "")
        self._ft = lgb.Booster(model_file=ft_path) if ft_path and os.path.exists(ft_path) else None
        self._rf = Model(os.environ["DF_RF_DIR"], "training")
        with open(os.environ["DF_FUSION"]) as fh:
            self._fusion = json.load(fh)
        self._clip = float(self._fusion.get("logit_clip", 1e-6))
        self._offset = float(os.environ.get("DF_THRESHOLD_OFFSET", 0.0))
        self._t = self._fusion["models"]["efr"]["threshold"] + self._offset

    # -- members -------------------------------------------------------------------
    def _ember_members(self, bytez: bytes, pe=None):
        raw_obj = self._ext.raw_features(bytez, pe) if pe is not None else self._ext.raw_features(bytez)
        v = np.asarray(self._ext.process_raw_features(raw_obj), dtype=np.float32).reshape(1, -1)
        raw = float(self._ember.predict(v, raw_score=True)[0])
        e = 1.0 / (1.0 + math.exp(-raw))
        if self._ft is None:
            return e, e
        raw_f = raw + float(self._ft.predict(v, raw_score=True)[0])
        return e, 1.0 / (1.0 + math.exp(-raw_f))

    def _rf_member(self, bytez: bytes, pe=None) -> float:
        a = nfs_features.extract(bytez, "training", pe=pe)
        return float(self._rf.probability(self._rf.vectorize(a)))

    def _parse(self, bytez: bytes):
        """Parse once; every layer reuses this binary (it used to be parsed 3x, which
        cost seconds on large files against the 4 s request budget)."""
        try:
            return self._lief.PE.parse(bytez)
        except Exception:
            return None

    def _signature(self, bytez: bytes, pe=None) -> tuple[bool, bool, str]:
        """-> (microsoft_trusted, tampered, verify_flags)."""
        try:
            if pe is None or not pe.has_signatures:
                return False, False, "NONE"
            flags = str(pe.verify_signature()).split(".")[-1]
            tampered = any(f in flags for f in _BROKEN_FLAGS)
            return (not tampered) and trust.is_trusted_microsoft(bytez, pe), tampered, flags
        except Exception:
            return False, False, "ERROR"

    # -- decision ------------------------------------------------------------------
    def analyze(self, bytez: bytes) -> dict:
        pe = self._parse(bytez)
        trusted, tampered, flags = self._signature(bytez, pe)
        out = {"signature": flags, "trusted_microsoft": trusted, "tampered_signature": tampered}
        if trusted:
            out.update(verdict=0, reason="trusted_microsoft_signature")
            return out
        if tampered:
            out.update(verdict=1, reason="tampered_signature")
            return out
        tell = cmdline.embedded_powershell_bypass(bytez)
        if tell:
            out.update(verdict=1, reason="embedded_powershell_bypass", tell=tell)
            return out
        if pe is None:
            # v3.3: fail toward detection as documented. Before this, a body LIEF could not
            # parse still reached the EMBER byte-level features (histograms, entropy, strings
            # need no PE structure), so random / non-PE blobs >= ~512 KB were ML-scored benign
            # (review 2026-10-20). 0 of 13,503 goodware in our corpora are LIEF-unparseable.
            out.update(verdict=1, reason="unparseable")
            return out
        m = {}
        try:
            m["e"], m["f"] = self._ember_members(bytez, pe)
        except Exception:
            pass
        try:
            m["r"] = self._rf_member(bytez, pe)
        except Exception:
            pass
        out.update({k: round(v, 6) for k, v in m.items()})
        subset = "efr" if len(m) == 3 else ("ef" if "e" in m else ("r" if "r" in m else None))
        if subset is None:
            out.update(verdict=1, reason="unparseable")
            return out
        fm = self._fusion["models"][subset]
        score = fm["intercept"] + sum(c * _logit(m[k], self._clip) for c, k in zip(fm["coef"], fm["order"]))
        thr = fm["threshold"] + self._offset
        out.update(subset=subset, score=round(score, 4), threshold=round(thr, 4),
                   verdict=int(score > thr), reason="ml_fusion")
        return out

    def predict(self, bytez: bytes) -> int:
        return self.analyze(bytez)["verdict"]

    def info(self) -> dict:
        efr = self._fusion["models"]["efr"]
        mem = self._fusion["members"]
        version = self._fusion.get("version", "v4" if mem.get("r") == "rf_v4" else "v3")
        return {"model_name": f"ensemble-{version}",
                "layers": ["authenticode_trust(microsoft_pinned_pca)", "authenticode_tamper",
                           "embedded_powershell_bypass",
                           f"logodds_fusion({mem.get('e')}, {mem.get('r')}, {mem.get('f')})"],
                "members": self._fusion["members"], "fallbacks": ["ef", "r"],
                "fusion": {k: efr[k] for k in ("order", "coef", "intercept")},
                "threshold": self._t, "threshold_offset": self._offset,
                "rule": "benign if Microsoft-trusted; malicious if signature tampered or if an "
                        "embedded hidden PowerShell bypass command line is present; "
                        "else malicious if intercept + sum(coef*logit(member)) > threshold"}
