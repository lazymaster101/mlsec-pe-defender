"""Model artifacts are integrity-checked at load (review 2026-09-21, finding 9)."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.common import DEPLOYED_MODEL_DIR, MODEL_DIR, model_available
from defender.model import Model


@unittest.skipUnless(model_available(DEPLOYED_MODEL_DIR), "deployed model arrays not present")
class ManifestTest(unittest.TestCase):
    def test_deployed_model_manifest_verifies(self):
        model = Model(DEPLOYED_MODEL_DIR, "training")
        self.assertTrue(model.manifest_verified)
        self.assertTrue(model.info()["manifest_verified"])

    def _copy(self):
        tmp = tempfile.mkdtemp(prefix="rf_adv_")
        for name in os.listdir(DEPLOYED_MODEL_DIR):
            shutil.copy2(DEPLOYED_MODEL_DIR / name, tmp)
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return tmp

    def test_tampered_array_is_refused(self):
        tmp = self._copy()
        with open(os.path.join(tmp, "tree_roots.npy"), "r+b") as fh:
            fh.seek(200); b = fh.read(1); fh.seek(200); fh.write(bytes([b[0] ^ 1]))
        with self.assertRaises(ValueError):
            Model(tmp, "training")

    def test_tampered_schema_is_refused(self):
        tmp = self._copy()
        schema = json.loads(open(os.path.join(tmp, "schema.json")).read())
        schema["n_trees"] = int(schema["n_trees"])  # unchanged value, changed bytes
        open(os.path.join(tmp, "schema.json"), "w").write(json.dumps(schema, indent=1))
        with self.assertRaises(ValueError):
            Model(tmp, "training")

    def test_manifest_must_cover_every_array(self):
        tmp = self._copy()
        manifest = json.loads(open(os.path.join(tmp, "manifest.json")).read())
        del manifest["files"]["scales.npy"]
        open(os.path.join(tmp, "manifest.json"), "w").write(json.dumps(manifest))
        with self.assertRaises(ValueError):
            Model(tmp, "training")

    def test_skip_switch_is_explicit_and_reported(self):
        tmp = self._copy()
        with open(os.path.join(tmp, "tree_roots.npy"), "r+b") as fh:
            fh.seek(200); b = fh.read(1); fh.seek(200); fh.write(bytes([b[0] ^ 1]))
        os.environ["DF_SKIP_MANIFEST_VERIFY"] = "1"
        try:
            self.assertFalse(Model(tmp, "training").manifest_verified)
        finally:
            os.environ.pop("DF_SKIP_MANIFEST_VERIFY", None)


if __name__ == "__main__":
    unittest.main()
