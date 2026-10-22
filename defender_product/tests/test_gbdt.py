"""The gbdt_logistic ensemble sums leaf log-odds then squashes; verify that path.

The supplied model is an averaged forest; a retrained GBDT combines leaves
differently. This pins the additive+sigmoid math on a hand-built model so the
serving path is trusted independently of any training run.
"""
from __future__ import annotations

import json
import math
import pathlib
import tempfile
import unittest

import numpy as np

from defender.model import Model


def build_two_stump_model(directory: pathlib.Path, base_score: float) -> None:
    # Two stumps over two numeric features; child indices are GLOBAL, as the
    # exporters emit them (tree 1's nodes start at offset 3).
    np.save(directory / "children_left.npy", np.array([1, -1, -1, 4, -1, -1], "<i4"))
    np.save(directory / "children_right.npy", np.array([2, -1, -1, 5, -1, -1], "<i4"))
    np.save(directory / "features.npy", np.array([0, -1, -1, 1, -1, -1], "<i4"))
    np.save(directory / "thresholds.npy", np.array([0.5, 0, 0, 0.5, 0, 0], "<f8"))
    np.save(directory / "probabilities.npy", np.array([0.0, 0.4, -0.3, 0.0, -0.2, 0.7], "<f8"))
    np.save(directory / "tree_roots.npy", np.array([0, 3], "<i4"))
    np.save(directory / "scales.npy", np.array([1.0, 1.0], "<f8"))
    (directory / "schema.json").write_text(json.dumps({
        "format_version": 1, "ensemble": "gbdt_logistic", "base_score": base_score,
        "model_name": "synthetic", "classes": [0, 1], "malicious_class_index": 1,
        "n_features": 2, "n_trees": 2, "n_nodes": 6,
        "numerical_attributes": ["f0", "f1"], "categorical_attributes": [],
        "categorical_categories": [], "categorical_handle_unknown": "ignore",
        "textual_attributes": [], "hashing": {}}))
    write_manifest(directory)


def write_manifest(directory: pathlib.Path) -> None:
    """The loader verifies every artifact against manifest.json (review 2026-09-21, finding 9)."""
    import hashlib
    files = {}
    for path in sorted(directory.iterdir()):
        if path.suffix in (".npy", ".json") and path.name != "manifest.json":
            files[path.name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
    (directory / "manifest.json").write_text(json.dumps({"format_version": 1, "files": files}))


class GbdtServingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp())
        build_two_stump_model(self.dir, base_score=0.1)
        self.model = Model(self.dir, "training")

    def test_sums_leaf_logodds_then_sigmoid(self) -> None:
        for f0 in (0.0, 1.0):
            for f1 in (0.0, 1.0):
                raw = (0.4 if f0 <= 0.5 else -0.3) + (-0.2 if f1 <= 0.5 else 0.7) + 0.1
                expected = 1.0 / (1.0 + math.exp(-raw))
                row = self.model.vectorize({"f0": f0, "f1": f1})
                with self.subTest(f0=f0, f1=f1):
                    self.assertAlmostEqual(self.model.probability(row), expected, places=12)

    def test_large_negative_score_does_not_overflow(self) -> None:
        np.save(self.dir / "probabilities.npy",
                np.array([0.0, -1000.0, -1000.0, 0.0, -1000.0, -1000.0], "<f8"))
        write_manifest(self.dir)
        model = Model(self.dir, "training")
        probability = model.probability(model.vectorize({"f0": 0.0, "f1": 0.0}))
        self.assertGreaterEqual(probability, 0.0)
        self.assertLess(probability, 1e-6)

    def test_unknown_ensemble_is_rejected(self) -> None:
        schema = json.loads((self.dir / "schema.json").read_text())
        schema["ensemble"] = "mystery"
        (self.dir / "schema.json").write_text(json.dumps(schema))
        write_manifest(self.dir)
        with self.assertRaises(ValueError):
            Model(self.dir, "training")

    def test_forest_mean_is_still_the_default(self) -> None:
        schema = json.loads((self.dir / "schema.json").read_text())
        del schema["ensemble"]
        (self.dir / "schema.json").write_text(json.dumps(schema))
        write_manifest(self.dir)
        model = Model(self.dir, "training")
        self.assertEqual(model.ensemble, "forest_mean")
        # Mean of the two reached leaves, no sigmoid.
        row = model.vectorize({"f0": 0.0, "f1": 0.0})
        self.assertAlmostEqual(model.probability(row), (0.4 + -0.2) / 2, places=12)


if __name__ == "__main__":
    unittest.main()
