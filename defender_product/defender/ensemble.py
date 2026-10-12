#!/usr/bin/env python3
"""Diversified-ensemble detector: ember_gbdt (EMBER-2381 rich features) OR rf_adv
(NFS header/imports, recent + adversarially hardened). Flags malicious if EITHER
model exceeds its threshold. This is the research-backed 'best of both' (MLSEC was
won by a diversified ensemble): ember_gbdt supplies benchmark accuracy and byte-level
signal; rf_adv supplies recent-malware coverage, hardening, and immunity to overlay
appends (NFS features ignore overlay bytes).

Config via env:
  DF_EMBER_MODEL      path to ember_gbdt LightGBM text model
  DF_RF_DIR           path to rf_adv exported arrays (NFS runtime)
  DF_EMBER_THRESHOLD  ember score cutoff  (default 0.98; FPR-safe point, native 0.83% / all 0.71%)
  DF_RF_THRESHOLD     rf_adv score cutoff (default 0.75)

Requires the ember feature extractor (see ember_compat for lief-0.17/numpy-2 patches),
lightgbm, and lief. Fail-toward-detection: any extraction/scoring error -> malicious.
"""
from __future__ import annotations
import os
import numpy as np

from defender import features as nfs_features
from defender.model import Model


class Ensemble:
    def __init__(self) -> None:
        import lightgbm as lgb
        from defender import ember_compat  # noqa: F401  applies lief-0.17 / numpy-2 patches
        import ember
        self._ext = ember.PEFeatureExtractor(2, print_feature_warning=False)
        self._ember = lgb.Booster(model_file=os.environ["DF_EMBER_MODEL"])
        self._rf = Model(os.environ["DF_RF_DIR"], "training")
        self._tE = float(os.environ.get("DF_EMBER_THRESHOLD", 0.98))
        self._tR = float(os.environ.get("DF_RF_THRESHOLD", 0.75))

    def scores(self, bytez: bytes) -> tuple[float, float]:
        try:
            v = np.asarray(self._ext.feature_vector(bytez), dtype=np.float32).reshape(1, -1)
            e = float(self._ember.predict(v)[0])
        except Exception:
            e = 1.0
        try:
            a = nfs_features.extract(bytez, "training")
            r = float(self._rf.probability(self._rf.vectorize(a)))
        except Exception:
            r = 1.0
        return e, r

    def predict(self, bytez: bytes) -> int:
        e, r = self.scores(bytez)
        return 1 if (e > self._tE or r > self._tR) else 0

    def info(self) -> dict:
        return {"model_name": "ensemble", "members": ["ember_gbdt", "rf_adv"],
                "ember_threshold": self._tE, "rf_threshold": self._tR,
                "rule": "malicious if ember>tE OR rf>tR"}
