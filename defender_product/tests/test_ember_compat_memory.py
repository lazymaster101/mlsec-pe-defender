"""The chunked byte histogram (defender/ember_compat.py) must equal EMBER's original
bincount exactly, with a bounded transient (verification 2026-10-22: the original
allocated 8 bytes per input byte, 509 MiB on a 67 MB file)."""
from __future__ import annotations

import os
import tracemalloc
import unittest

import numpy as np

from tests.common import SAMPLE_DIR
from defender import ember_features as F, ember_compat  # noqa: F401  (applies the patch)


def _original(bytez: bytes):
    return np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).tolist()


class ByteHistogramTest(unittest.TestCase):
    def test_identical_to_the_original_on_synthetic_inputs(self):
        hist = F.ByteHistogram()
        rng = np.random.default_rng(3)
        for body in (b"", b"\x00", bytes(range(256)) * 1000, rng.integers(0, 256, 5_000_003, dtype=np.uint8).tobytes(),
                     rng.integers(0, 256, (4 << 20) + 1, dtype=np.uint8).tobytes()):
            self.assertEqual(hist.raw_features(body, None), _original(body))

    @unittest.skipUnless(SAMPLE_DIR.is_dir(), "course samples not present")
    def test_identical_on_real_pe_files(self):
        hist = F.ByteHistogram()
        for p in sorted(SAMPLE_DIR.iterdir()):
            b = p.read_bytes()
            self.assertEqual(hist.raw_features(b, None), _original(b), p.name)

    def test_transient_is_bounded(self):
        body = os.urandom(32 << 20)                       # 32 MiB: the original would allocate 256 MiB
        hist = F.ByteHistogram()
        tracemalloc.start()
        hist.raw_features(body, None)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 48 << 20, f"peak {peak / 1048576:.0f} MiB")


if __name__ == "__main__":
    unittest.main()
