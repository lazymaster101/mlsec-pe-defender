"""v3 layers: enum-crash regression, Authenticode trust/tamper, fusion fallbacks."""
from __future__ import annotations

import os
import unittest

import lief

from defender import features, trust
from tests.common import ROOT, SAMPLE_DIR

MS_SIGNED = SAMPLE_DIR / "iexplore.exe"      # Microsoft-signed (PCA 2011 chain)
OTHER_SIGNED = SAMPLE_DIR / "chrome.exe"     # validly signed by Google, not Microsoft
MODELS = {
    "DF_EMBER_MODEL": ROOT / "models/ember_gbdt/ember_gbdt.txt",
    "DF_EMBER_FT": ROOT / "models/ember_ft/ember_ft.txt",
    "DF_RF_DIR": ROOT / "models/rf_adv",
    "DF_FUSION": ROOT / "models/fusion.json",
}


class EnumNameTest(unittest.TestCase):
    MT = lief.PE.Header.MACHINE_TYPES

    def test_readytorun_os_variants_map_to_real_arch(self):
        self.assertEqual(features._enum_name(0xAA64 ^ 0x4644, self.MT), "ARM64")   # macOS arm64 R2R
        self.assertEqual(features._enum_name(0x8664 ^ 0x4644, self.MT), "AMD64")   # macOS x64 R2R
        self.assertEqual(features._enum_name(0x8664 ^ 0x7B79, self.MT), "AMD64")   # Linux x64 R2R

    def test_unknown_value_is_stable_token_not_crash(self):
        self.assertEqual(features._enum_name(0x0F0F), "UNKNOWN_3855")

    def test_known_enum_passthrough(self):
        self.assertEqual(features._enum_name(self.MT.I386, self.MT), "I386")


@unittest.skipUnless(MS_SIGNED.is_file() and OTHER_SIGNED.is_file(), "course samples not present")
class TrustTest(unittest.TestCase):
    def setUp(self):
        self.ms = MS_SIGNED.read_bytes()

    def test_microsoft_signed_is_trusted(self):
        self.assertTrue(trust.is_trusted_microsoft(self.ms))

    def test_other_vendor_is_not_trusted(self):
        self.assertFalse(trust.is_trusted_microsoft(OTHER_SIGNED.read_bytes()))

    def test_data_appended_after_signature_is_not_trusted(self):   # CVE-2013-3900
        self.assertFalse(trust.is_trusted_microsoft(self.ms + b"\x90" * 4096))

    def test_modified_code_is_not_trusted(self):
        pe = lief.PE.parse(self.ms)
        b = bytearray(self.ms); b[pe.sections[0].offset + 64] ^= 0xFF
        self.assertFalse(trust.is_trusted_microsoft(bytes(b)))

    def test_leaf_must_be_signed_by_pinned_pca(self):
        pe = lief.PE.parse(self.ms)
        sig = pe.signatures[0]
        leaf = bytes(sig.signers[0].cert.raw)
        pca = next(bytes(c.raw) for c in sig.certificates
                   if __import__("hashlib").sha256(bytes(c.raw)).hexdigest() in trust.PINNED_PCA_FULL)
        self.assertTrue(trust.rsa_signed_by(leaf, pca))
        forged = bytearray(leaf); i = leaf.find(b"Microsoft"); forged[i] ^= 1
        self.assertFalse(trust.rsa_signed_by(bytes(forged), pca))

    def test_garbage_is_not_trusted(self):
        self.assertFalse(trust.is_trusted_microsoft(b"MZ" + b"\x00" * 512))


@unittest.skipUnless(all(p.exists() for p in MODELS.values()) and MS_SIGNED.is_file(), "v3 models not present")
class EnsembleV3Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for k, v in MODELS.items():
            os.environ[k] = str(v)
        from defender.ensemble import Ensemble
        cls.m = Ensemble()

    def test_course_goodware_is_benign(self):
        for p in sorted(SAMPLE_DIR.iterdir()):
            with self.subTest(p.name):
                self.assertEqual(self.m.predict(p.read_bytes()), 0)

    def test_trusted_short_circuits(self):
        self.assertEqual(self.m.analyze(MS_SIGNED.read_bytes())["reason"], "trusted_microsoft_signature")

    def test_tampered_signed_file_is_flagged(self):
        b = bytearray(MS_SIGNED.read_bytes()); pe = lief.PE.parse(bytes(b))
        b[pe.sections[0].offset + 64] ^= 0xFF
        out = self.m.analyze(bytes(b))
        self.assertEqual((out["reason"], out["verdict"]), ("tampered_signature", 1))

    def test_unparseable_fails_toward_detection(self):
        out = self.m.analyze(b"MZ" + b"\x00" * 200)
        self.assertEqual(out["verdict"], 1)

    def test_nfs_failure_falls_back_to_ember_fusion(self):
        b = OTHER_SIGNED.read_bytes()
        orig = self.m._rf_member
        self.m._rf_member = lambda _b: (_ for _ in ()).throw(RuntimeError("nfs down"))
        try:
            out = self.m.analyze(b)
        finally:
            self.m._rf_member = orig
        self.assertEqual(out["subset"], "ef")
        self.assertEqual(out["verdict"], 0)

    def test_ember_failure_falls_back_to_nfs_fusion(self):
        b = OTHER_SIGNED.read_bytes()
        orig = self.m._ember_members
        self.m._ember_members = lambda _b: (_ for _ in ()).throw(RuntimeError("ember down"))
        try:
            out = self.m.analyze(b)
        finally:
            self.m._ember_members = orig
        self.assertEqual(out["subset"], "r")


if __name__ == "__main__":
    unittest.main()
