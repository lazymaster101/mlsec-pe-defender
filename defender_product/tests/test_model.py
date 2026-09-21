"""End-to-end scoring must reproduce the original scikit-learn NFS pipeline.

Expected probabilities were cross-checked against the supplied pickle itself:
scikit-learn's own HashingVectorizer/OneHotEncoder/MaxAbsScaler feeding a
traversal of the pickle's tree state, agreeing to 0.0 absolute error.
"""
from __future__ import annotations

import hashlib
import unittest

import numpy as np

from defender import features
from tests.common import MODEL_DIR, SAMPLE_DIR, fixture, model_available


@unittest.skipUnless(model_available(), f"model arrays not found in {MODEL_DIR}")
class ModelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from defender.model import Model
        cls.golden = fixture("samples_golden.json")
        cls.models = {mode: Model(MODEL_DIR, mode) for mode in ("training", "legacy")}

    def test_layout_matches_schema(self) -> None:
        model = self.models["training"]
        self.assertEqual(model.n_features, 250041)
        self.assertEqual(model.n_features,
                         22 + 16 + 3 + 5 * 50000)
        self.assertEqual(len(model._roots), 100)

    def test_golden_attribute_vectors(self) -> None:
        model = self.models["training"]
        for case in self.golden["cases"]:
            if case["kind"] != "attributes":
                continue
            with self.subTest(case=case["name"]):
                row = model.vectorize(case["attributes"])
                self.assertEqual(row.dtype, np.float32)
                self.assertAlmostEqual(model.probability(row), case["probability"], places=12)

    def test_golden_pe_samples(self) -> None:
        if not SAMPLE_DIR.is_dir():
            self.skipTest(f"PE samples not found in {SAMPLE_DIR}")
        for case in self.golden["cases"]:
            if case["kind"] != "file":
                continue
            path = SAMPLE_DIR / case["name"]
            if not path.is_file():
                self.skipTest(f"missing sample {path}")
            bytez = path.read_bytes()
            with self.subTest(sample=case["name"], mode=case["mode"]):
                self.assertEqual(hashlib.sha256(bytez).hexdigest(), case["sha256"],
                                 "sample bytes differ from the ones that were validated")
                got = self.models[case["mode"]].predict(bytez)["malware_probability"]
                self.assertAlmostEqual(got, case["probability"], places=12)

    def test_training_mode_clears_known_goodware(self) -> None:
        """The shipped deployment extractor flags all of it; the training schema does not."""
        if not SAMPLE_DIR.is_dir():
            self.skipTest(f"PE samples not found in {SAMPLE_DIR}")
        threshold = self.golden["threshold"]
        for case in self.golden["cases"]:
            if case["kind"] != "file" or case["mode"] != "training":
                continue
            path = SAMPLE_DIR / case["name"]
            if not path.is_file():
                continue
            with self.subTest(sample=case["name"]):
                probability = self.models["training"].predict(path.read_bytes())["malware_probability"]
                self.assertLessEqual(probability, threshold,
                                     f"{case['name']} is a false positive at {threshold}")

    def test_unknown_category_is_ignored_not_an_error(self) -> None:
        model = self.models["training"]
        base = dict(self.golden["cases"][-1]["attributes"])
        base["machine"] = "NOT_A_REAL_MACHINE"
        row = model.vectorize(base)
        block = row[22:22 + 16]
        self.assertTrue(np.all(block == 0.0))

    def test_rejects_non_pe_input(self) -> None:
        for payload in (b"", b"MZ", b"not a pe", b"\x00" * 4096, b"MZ" + b"\xff" * 1024):
            with self.subTest(payload=payload[:8]):
                with self.assertRaises(ValueError):
                    features.extract(payload, "training")

    def test_feature_mode_is_validated(self) -> None:
        from defender.model import Model
        with self.assertRaises(ValueError):
            Model(MODEL_DIR, "nonsense")


if __name__ == "__main__":
    unittest.main()
