"""The hashed-text block must match scikit-learn's HashingVectorizer exactly.

Golden vectors were produced by scikit-learn itself, so these run without it.
"""
import unittest

import numpy as np

from defender import hashing
from tests.common import fixture


class HashingGoldenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = fixture("hashing_golden.json")

    def test_token_pattern_matches_the_trained_model(self) -> None:
        self.assertEqual(hashing.TOKEN_PATTERN, self.golden["token_pattern"])

    def test_vectors_match_scikit_learn(self) -> None:
        for case in self.golden["cases"]:
            width = case["n_features"]
            expected = np.zeros(width, dtype=np.float64)
            expected[case["indices"]] = case["values"]
            actual = np.zeros(width, dtype=np.float64)
            hashing.transform(case["document"], width, actual, 0)
            with self.subTest(document=case["document"][:40]):
                np.testing.assert_array_equal(actual, expected)

    def test_unpadded_text_drops_boundary_tokens(self) -> None:
        # The learned token pattern needs whitespace on both sides, which is why
        # the deployment-mode extractor loses information the model was trained on.
        self.assertEqual(hashing.tokenize("A B"), [])
        self.assertEqual(hashing.tokenize(" a b "), ["a", "b"])
        self.assertEqual(hashing.tokenize("a b c"), ["b"])

    def test_writes_are_confined_to_the_block(self) -> None:
        buffer = np.zeros(120, dtype=np.float64)
        hashing.transform(" alpha beta gamma ", 50, buffer, 40)
        self.assertTrue(np.all(buffer[:40] == 0.0))
        self.assertTrue(np.all(buffer[90:] == 0.0))
        self.assertAlmostEqual(float(np.linalg.norm(buffer[40:90])), 1.0, places=12)

    def test_l2_norm_is_unit_for_non_cancelling_documents(self) -> None:
        buffer = np.zeros(50000, dtype=np.float64)
        hashing.transform(" kernel32.dll user32.dll advapi32.dll ", 50000, buffer, 0)
        self.assertAlmostEqual(float(np.linalg.norm(buffer)), 1.0, places=12)

    def test_int32_min_fold_matches_scikit_learn_guard(self) -> None:
        # Unreachable by random tokens, so assert the documented substitution.
        self.assertEqual(hashing._fold(-(2 ** 31), 50000), (2 ** 31) % 50000)
        self.assertEqual(hashing._fold(-(2 ** 31), 50000), 33648)


if __name__ == "__main__":
    unittest.main()
