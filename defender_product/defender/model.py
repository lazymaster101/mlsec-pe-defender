"""Forest inference over exported arrays, with no scikit-learn at runtime.

Reproduces ``NeedForSpeedModel.predict_threshold``: one-hot + hashed-text features,
MaxAbsScaler, then the mean class-1 probability across the random forest.
Arrays are memory-mapped so the resident set stays proportional to the nodes
actually visited rather than to the 380 MB on disk.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

import numpy as np

from defender import features as feature_extraction
from defender import hashing

ARRAY_NAMES = ("children_left", "children_right", "features", "thresholds",
               "probabilities", "scales", "tree_roots")


class Model:
    def __init__(self, directory: str | Path, feature_mode: str = "training") -> None:
        directory = Path(directory)
        self.schema: dict[str, Any] = json.loads((directory / "schema.json").read_text())
        if self.schema.get("format_version") != 1:
            raise ValueError("Unsupported model format version")
        # Averaged forest (the supplied model) or additive boosting; both are
        # flat arrays of binary trees, they differ only in how leaves combine.
        self.ensemble = self.schema.get("ensemble", "forest_mean")
        if self.ensemble not in ("forest_mean", "gbdt_logistic"):
            raise ValueError(f"Unsupported ensemble {self.ensemble!r}")
        self._base_score = float(self.schema.get("base_score", 0.0))
        if feature_mode not in ("training", "legacy"):
            raise ValueError("DF_FEATURE_MODE must be 'training' or 'legacy'")
        self.feature_mode = feature_mode
        self.name = self.schema["model_name"]

        # Integrity: the manifest's SHA-256 digests are verified at load time (review
        # 2026-09-21, finding 9: the digests used to be documentation only). Hashing the
        # ~60 MB of arrays costs ~0.1 s once at startup. DF_SKIP_MANIFEST_VERIFY=1 disables
        # it for experiments on hand-edited arrays and is logged in info().
        self.manifest_verified = False
        manifest_path = directory / "manifest.json"
        if os.environ.get("DF_SKIP_MANIFEST_VERIFY") != "1":
            if not manifest_path.is_file():
                raise ValueError(f"{directory}: manifest.json is missing (set DF_SKIP_MANIFEST_VERIFY=1 to load unverified)")
            self._verify_manifest(directory, json.loads(manifest_path.read_text()))
            self.manifest_verified = True

        arrays = {name: np.load(directory / f"{name}.npy", mmap_mode="r", allow_pickle=False)
                  for name in ARRAY_NAMES}
        self._left = arrays["children_left"]
        self._right = arrays["children_right"]
        self._feature = arrays["features"]
        self._threshold = arrays["thresholds"]
        self._probability = arrays["probabilities"]
        self._roots = np.asarray(arrays["tree_roots"], dtype=np.int32)

        self.n_features = int(self.schema["n_features"])
        self._numerical = list(self.schema["numerical_attributes"])
        self._categorical = list(self.schema["categorical_attributes"])
        self._textual = list(self.schema["textual_attributes"])
        self._hashing = self.schema["hashing"]

        # MaxAbsScaler on sparse input scales by the reciprocal, not by division;
        # reproduce that exactly so float32 rounding lands where the forest expects.
        self._inverse_scale = (1.0 / np.asarray(arrays["scales"], dtype=np.float64)).astype(np.float64)

        offset = len(self._numerical)
        self._category_index: list[dict[str, int]] = []
        for column in self.schema["categorical_categories"]:
            self._category_index.append({value: offset + i for i, value in enumerate(column)})
            offset += len(column)
        self._text_offsets: list[tuple[str, int, int]] = []
        for attribute in self._textual:
            width = int(self._hashing[attribute]["n_features"])
            self._text_offsets.append((attribute, width, offset))
            offset += width
        if offset != self.n_features:
            raise ValueError("Feature layout does not match the declared width")

        if self._roots.shape != (int(self.schema["n_trees"]),):
            raise ValueError("Unexpected tree root count")
        for array in (self._left, self._right, self._feature, self._threshold, self._probability):
            if array.shape != (int(self.schema["n_nodes"]),):
                raise ValueError("Unexpected forest array shape")
        if self._inverse_scale.shape != (self.n_features,):
            raise ValueError("Unexpected scaling vector shape")

    @staticmethod
    def _verify_manifest(directory: Path, manifest: dict[str, Any]) -> None:
        files = manifest.get("files") or {}
        expected = {f"{name}.npy" for name in ARRAY_NAMES} | {"schema.json"}
        missing = expected - set(files)
        if missing:
            raise ValueError(f"manifest.json does not cover {sorted(missing)}")
        for name, entry in files.items():
            path = directory / name
            if not path.is_file():
                raise ValueError(f"manifest lists {name} but it is missing")
            digest = hashlib.sha256()
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
            if digest.hexdigest() != entry.get("sha256"):
                raise ValueError(f"{name}: SHA-256 does not match manifest.json")
            if "bytes" in entry and path.stat().st_size != int(entry["bytes"]):
                raise ValueError(f"{name}: size {path.stat().st_size} != manifest {entry['bytes']}")

    def vectorize(self, attributes: dict[str, Any]) -> np.ndarray:
        """Build the scaled float32 row the forest was trained to consume."""
        row = np.zeros(self.n_features, dtype=np.float64)
        for index, name in enumerate(self._numerical):
            row[index] = float(attributes[name])
        for column, index in enumerate(self._category_index):
            # handle_unknown='ignore' leaves the whole block at zero.
            position = index.get(str(attributes[self._categorical[column]]))
            if position is not None:
                row[position] = 1.0
        for attribute, width, offset in self._text_offsets:
            hashing.transform(str(attributes[attribute]), width, row, offset)
        row *= self._inverse_scale
        return row.astype(np.float32)

    def probability(self, row: np.ndarray) -> float:
        """Probability of class 1, advancing every tree one level per step."""
        nodes = self._roots.copy()
        left, right = self._left, self._right
        feature, threshold = self._feature, self._threshold
        active = left[nodes] != -1
        while active.any():
            current = nodes[active]
            take_left = row[feature[current]] <= threshold[current]
            nodes[active] = np.where(take_left, left[current], right[current])
            active = left[nodes] != -1
        leaves = self._probability[nodes]
        if self.ensemble == "forest_mean":
            return float(np.mean(leaves))
        # Boosted trees sum raw log-odds contributions, then squash.
        total = float(np.sum(leaves)) + self._base_score
        if total >= 0.0:
            return 1.0 / (1.0 + math.exp(-total))
        exponential = math.exp(total)      # avoids overflow for large negatives
        return exponential / (1.0 + exponential)

    def predict(self, bytez: bytes) -> dict[str, Any]:
        attributes = feature_extraction.extract(bytez, self.feature_mode)
        score = self.probability(self.vectorize(attributes))
        return {"malware_probability": score, "attributes": attributes}

    def info(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "n_features": self.n_features,
            "n_trees": int(self.schema["n_trees"]),
            "n_nodes": int(self.schema["n_nodes"]),
            "ensemble": self.ensemble,
            "feature_mode": self.feature_mode,
            "source_sha256": self.schema.get("source_sha256"),
            "manifest_verified": self.manifest_verified,
        }
