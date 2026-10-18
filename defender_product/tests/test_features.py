"""Attribute extraction must follow the schema the forest was trained on."""
from __future__ import annotations

import unittest

from defender import features
from tests.common import SAMPLE_DIR


@unittest.skipUnless(SAMPLE_DIR.is_dir(), f"PE samples not found in {SAMPLE_DIR}")
class FeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.samples = sorted(SAMPLE_DIR.glob("*.exe"))
        if not cls.samples:
            raise unittest.SkipTest("no PE samples")

    def test_training_mode_pads_the_hashed_import_fields(self) -> None:
        """Padding is what keeps the first and last token visible to the tokenizer."""
        for path in self.samples:
            attributes = features.extract(path.read_bytes(), "training")
            with self.subTest(sample=path.name):
                for field in ("libraries", "functions"):
                    self.assertTrue(attributes[field].startswith(" "))
                    self.assertTrue(attributes[field].endswith(" "))

    def test_training_mode_uses_the_trainer_field_assignment(self) -> None:
        """JSONAttributeExtractor stores function names under 'libraries'."""
        attributes = features.extract((SAMPLE_DIR / "7z.exe").read_bytes(), "training")
        self.assertIn("KERNEL32.dll", attributes["functions"])
        self.assertNotIn("KERNEL32.dll", attributes["libraries"])

    def test_all_required_attributes_are_present(self) -> None:
        expected = set(features.OPTIONAL_NUMERIC) | {
            "virtual_size", "has_debug", "imports", "exports", "has_relocations",
            "has_resources", "has_signature", "has_tls", "symbols", "timestamp",
            "numberof_sections", "machine", "magic", "characteristics_list",
            "dll_characteristics_list", "exports_list", "libraries", "functions"}
        for path in self.samples:
            for mode in ("training", "legacy"):
                attributes = features.extract(path.read_bytes(), mode)
                with self.subTest(sample=path.name, mode=mode):
                    self.assertEqual(set(attributes), expected)

    def test_categorical_values_are_known_to_the_encoder(self) -> None:
        for path in self.samples:
            attributes = features.extract(path.read_bytes(), "training")
            with self.subTest(sample=path.name):
                self.assertIn(attributes["machine"], {"AMD64", "I386", "ARM", "ARMNT", "IA64", "THUMB"})
                self.assertIn(attributes["magic"], {"PE32", "PE32_PLUS"})


if __name__ == "__main__":
    unittest.main()
