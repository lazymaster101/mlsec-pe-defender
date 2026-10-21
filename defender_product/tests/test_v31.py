"""v3.1 layers: legacy Microsoft PCA pins (with cryptographic provenance) and the embedded
hidden-PowerShell command-line tell."""
from __future__ import annotations

import hashlib
import os
import pathlib
import unittest

import lief

from defender import cmdline, trust
from tests.common import FIXTURES, ROOT, SAMPLE_DIR

PKI = FIXTURES / "ms_pki"
VALIDATION = pathlib.Path(os.environ.get(
    "DF_TEST_VALIDATION_DIR", ROOT.parent / "csce704-blackbox-validation-100-samples-20261014-corrected"))
MODELS = {
    "DF_EMBER_MODEL": ROOT / "models/ember_gbdt/ember_gbdt.txt",
    "DF_EMBER_FT": ROOT / "models/ember_ft/ember_ft.txt",
    "DF_RF_DIR": ROOT / "models/rf_adv",
    "DF_FUSION": ROOT / "models/fusion.json",
}


class LegacyPinTest(unittest.TestCase):
    """The two pre-2010 'Microsoft Code Signing PCA' issues are pinned, and each pin's
    authenticity is established independently of any evaluation sample."""

    def test_pins_match_fixtures(self):
        for name in ("ms_code_signing_pca_2000", "ms_code_signing_pca_2006", "ms_code_signing_pca_2010"):
            der = (PKI / f"{name}.der").read_bytes()
            self.assertIn(hashlib.sha256(der).hexdigest(), trust.PINNED_PCA_FULL, name)

    def test_2006_pca_is_signed_by_microsoft_root_certificate_authority(self):
        root = (PKI / "ms_root_certificate_authority_2001.der").read_bytes()
        self.assertEqual(hashlib.sha1(root).hexdigest(), "cdd4eeae6000ac7f40c3802c171e30148030c072")
        pca = (PKI / "ms_code_signing_pca_2006.der").read_bytes()
        self.assertTrue(trust.rsa_signed_by(pca, root))
        bad = bytearray(pca); i = pca.find(b"Microsoft"); bad[i] ^= 1
        self.assertFalse(trust.rsa_signed_by(bytes(bad), root))

    def test_2010_reissue_chains_to_the_same_root(self):
        root = (PKI / "ms_root_certificate_authority_2001.der").read_bytes()
        self.assertTrue(trust.rsa_signed_by((PKI / "ms_code_signing_pca_2010.der").read_bytes(), root))

    def test_2000_pca_is_microsofts_published_certificate(self):
        der = (PKI / "ms_code_signing_pca_2000.der").read_bytes()
        self.assertEqual(hashlib.sha1(der).hexdigest(), "d07ea64088a80085f01bd40aa4ead82f470482a6")  # CodeSignPCA2.crt

    def test_pinned_pcas_are_distinct_keys(self):
        # the 2006 and 2010 issues share a subject but not a key: pinning by DER is required
        p06 = trust._cert_parts((PKI / "ms_code_signing_pca_2006.der").read_bytes())
        p10 = trust._cert_parts((PKI / "ms_code_signing_pca_2010.der").read_bytes())
        self.assertNotEqual(p06[3], p10[3])


@unittest.skipUnless((VALIDATION / "manifest.json").is_file(), "validation set not present")
class LegacyChainIntegrationTest(unittest.TestCase):
    """2006-2012 Microsoft-signed Sysinternals binaries are now cleared by the trust layer."""

    def _file(self, prefix):
        return next((VALIDATION / "goodware").glob(prefix + "*")).read_bytes()

    def test_portmon_2012_leaf_under_2006_pca_is_trusted(self):
        self.assertTrue(trust.is_trusted_microsoft(self._file("0e848a391107")))

    def test_ldmdump_2006_leaf_under_2000_pca_is_trusted(self):
        self.assertTrue(trust.is_trusted_microsoft(self._file("980e64020cfc")))

    def test_appended_bytes_still_break_trust(self):
        self.assertFalse(trust.is_trusted_microsoft(self._file("0e848a391107") + b"\x00" * 64))


class CmdlineTellTest(unittest.TestCase):
    def test_classic_dropper_line_ascii(self):
        b = b"\x00" * 100 + b'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "x.ps1"' + b"\x00" * 100
        self.assertIsNotNone(cmdline.embedded_powershell_bypass(b))

    def test_python_list_literal_form(self):
        b = b'subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", _s])'
        self.assertIsNotNone(cmdline.embedded_powershell_bypass(b))

    def test_utf16_form(self):
        b = "powershell -w hidden -ep bypass -c calc".encode("utf-16le")
        self.assertIsNotNone(cmdline.embedded_powershell_bypass(b))

    def test_requires_both_options(self):
        self.assertIsNone(cmdline.embedded_powershell_bypass(b"powershell -ExecutionPolicy Bypass -File a.ps1"))
        self.assertIsNone(cmdline.embedded_powershell_bypass(b"powershell -WindowStyle Hidden -File a.ps1"))
        self.assertIsNone(cmdline.embedded_powershell_bypass(b"powershell.exe Get-Process | Out-Null"))

    def test_options_far_apart_do_not_match(self):
        b = b"powershell -ExecutionPolicy Bypass" + b"A" * 2000 + b"-WindowStyle Hidden"
        self.assertIsNone(cmdline.embedded_powershell_bypass(b))

    def test_empty_and_garbage(self):
        self.assertIsNone(cmdline.embedded_powershell_bypass(b""))
        self.assertIsNone(cmdline.embedded_powershell_bypass(b"MZ" + b"\x90" * 4096))

    @unittest.skipUnless(SAMPLE_DIR.is_dir(), "course samples not present")
    def test_course_goodware_clean(self):
        for p in sorted(SAMPLE_DIR.iterdir()):
            with self.subTest(p.name):
                self.assertIsNone(cmdline.embedded_powershell_bypass(p.read_bytes()))


@unittest.skipUnless(all(p.exists() for p in MODELS.values()) and SAMPLE_DIR.is_dir(), "v3 models not present")
class EnsembleV31Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for k, v in MODELS.items():
            os.environ[k] = str(v)
        from defender.ensemble import Ensemble
        cls.m = Ensemble()

    def test_layer_listed(self):
        self.assertIn("embedded_powershell_bypass", self.m.info()["layers"])

    def test_tell_fires_before_ml_on_unsigned_file(self):
        # a course goodware file that is NOT Microsoft-trusted, with the tell appended into its overlay:
        # the rule must flag it before the fusion runs (deterministic, additive)
        for p in sorted(SAMPLE_DIR.iterdir()):
            b = p.read_bytes()
            if self.m.analyze(b)["reason"] == "ml_fusion":
                out = self.m.analyze(b + b'\x00powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -c x\x00')
                self.assertEqual((out["reason"], out["verdict"]), ("embedded_powershell_bypass", 1))
                return
        self.skipTest("no course goodware reaches the ML layer")

    def test_random_and_non_pe_bodies_fail_toward_detection(self):
        # v3.3: LIEF-unparseable input is flagged without ML scoring (review finding: random
        # blobs >= 512 KB used to be scored benign through the EMBER byte features)
        import random
        rng = random.Random(7)
        for body in (bytes(rng.getrandbits(8) for _ in range(1 << 20)),
                     b"MZ" + bytes(rng.getrandbits(8) for _ in range(1 << 20)),
                     b"%PDF-1.7\n" + bytes(rng.getrandbits(8) for _ in range(600_000)),
                     b"PK\x03\x04" + bytes(rng.getrandbits(8) for _ in range(600_000))):
            out = self.m.analyze(body)
            self.assertEqual((out["reason"], out["verdict"]), ("unparseable", 1))

    def test_trusted_file_is_not_scanned_for_the_tell(self):
        # the trust layer comes first: a Microsoft-trusted file is benign regardless of strings
        for p in sorted(SAMPLE_DIR.iterdir()):
            b = p.read_bytes()
            if self.m.analyze(b)["reason"] == "trusted_microsoft_signature":
                self.assertEqual(self.m.analyze(b)["verdict"], 0)
                return


if __name__ == "__main__":
    unittest.main()
