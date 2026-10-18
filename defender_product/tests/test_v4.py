"""v4 serving optimizations must be pure refactors: identical features, faster."""
from __future__ import annotations

import re
import unittest

import lief
import numpy as np

from defender import ember_compat, ember_features, features
from tests.common import SAMPLE_DIR


class _ReferenceStrings:
    """EMBER's original StringExtractor.raw_features (regex + per-char loop), verbatim."""
    _allstrings = re.compile(b'[\x20-\x7f]{5,}')
    _paths = re.compile(b'c:\\\\', re.IGNORECASE)
    _urls = re.compile(b'https?://', re.IGNORECASE)
    _registry = re.compile(b'HKEY_')
    _mz = re.compile(b'MZ')

    def raw_features(self, bytez):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted_string = [b - ord(b'\x20') for b in b''.join(allstrings)]
            c = np.bincount(as_shifted_string, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh]))
        else:
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            H = 0
            csum = 0
        return {'numstrings': len(allstrings), 'avlength': avlength, 'printabledist': c.tolist(),
                'printables': int(csum), 'entropy': float(H),
                'paths': len(self._paths.findall(bytez)), 'urls': len(self._urls.findall(bytez)),
                'registry': len(self._registry.findall(bytez)), 'MZ': len(self._mz.findall(bytez))}


CASES = [b"", b"abcd", b"abcde", b"\x00abcde\x00", b"abcdefgh" * 3, b"\x7f" * 5, b"\x1fabcde\x80fghij",
         bytes(range(256)) * 50, b"C:\\x c:\\ HTTP://a HtTpS://b http:/ HKEY_ hkey_ MZMZM ZMZ",
         b"MZMZMZ", b"https://http://", b"\x00" * 4096]


class VectorizedStringsTest(unittest.TestCase):
    def test_patch_is_installed(self):
        self.assertIs(ember_features.StringExtractor.raw_features, ember_compat._strings_raw)

    def _same(self, b):
        ref = _ReferenceStrings().raw_features(b)
        new = ember_features.StringExtractor().raw_features(b, None)
        self.assertEqual(ref, new)
        self.assertIs(type(ref["avlength"]), type(new["avlength"]))
        self.assertEqual([type(x) for x in ref["printabledist"]], [type(x) for x in new["printabledist"]])

    def test_edge_cases_identical(self):
        for b in CASES:
            with self.subTest(len=len(b)):
                self._same(b)

    def test_random_bytes_identical(self):
        rng = np.random.default_rng(0)
        for _ in range(25):
            self._same(rng.integers(0, 256, size=int(rng.integers(1, 20000)), dtype=np.uint8).tobytes())

    def test_real_binaries_identical(self):
        for p in sorted(SAMPLE_DIR.iterdir()):
            with self.subTest(p.name):
                self._same(p.read_bytes())


class StringsMemoryTest(unittest.TestCase):
    """Regression: a fully vectorised variant allocated int64 arrays for EVERY printable run
    (~650 MB on a 60 MB file) and was OOM-killed under the 1 GiB container limit."""

    def test_peak_allocation_is_bounded(self):
        import tracemalloc
        rng = np.random.default_rng(1)
        b = rng.integers(0, 256, size=32 << 20, dtype=np.uint8).tobytes()   # ~7M short printable runs
        tracemalloc.start()
        ember_features.StringExtractor().raw_features(b, None)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 3 * len(b), f"peak {peak / 2**20:.0f} MiB for a {len(b) / 2**20:.0f} MiB input")


class SharedParseTest(unittest.TestCase):
    """Passing one pre-parsed lief binary must give the same features as parsing inside."""

    def test_nfs_and_ember_identical_with_shared_parse(self):
        ext = ember_features.PEFeatureExtractor(2, print_feature_warning=False)
        for p in sorted(SAMPLE_DIR.iterdir()):
            b = p.read_bytes()
            pe = lief.PE.parse(b)
            with self.subTest(p.name):
                self.assertEqual(features.extract(b, "training"), features.extract(b, "training", pe=pe))
                np.testing.assert_array_equal(ext.process_raw_features(ext.raw_features(b)),
                                              ext.process_raw_features(ext.raw_features(b, pe)))


if __name__ == "__main__":
    unittest.main()
