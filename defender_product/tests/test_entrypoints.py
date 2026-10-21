"""Both module entry points must start, answer /health, and shut down (a startup TypeError in
main() is invisible to tests that only call build(); review follow-up 2026-10-21)."""
from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

from tests.common import DEPLOYED_MODEL_DIR, DEPLOYED_THRESHOLD, ROOT, model_available

ENSEMBLE = {"DF_EMBER_MODEL": ROOT / "models/ember_gbdt/ember_gbdt.txt", "DF_EMBER_FT": ROOT / "models/ember_ft_v33/ember_ft.txt",
            "DF_RF_DIR": ROOT / "models/rf_adv", "DF_FUSION": ROOT / "models/fusion_v33.json"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(module: str, env: dict, timeout: float = 90.0):
    port = _free_port()
    full = {**os.environ, **{k: str(v) for k, v in env.items()}, "DF_HOST": "127.0.0.1", "DF_PORT": str(port),
            "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen([sys.executable, "-m", module], cwd=str(ROOT), env=full,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise AssertionError(f"{module} exited early with {proc.returncode}:\n{proc.stdout.read()[-3000:]}")
            try:
                with urllib.request.urlopen(url + "/health", timeout=2) as r:
                    if json.loads(r.read()).get("status") == "ok":
                        return proc, url
            except Exception:
                time.sleep(0.25)
        raise AssertionError(f"{module} did not become healthy in {timeout}s")
    except Exception:
        proc.kill(); proc.wait(5)
        raise


class EntryPointTest(unittest.TestCase):
    def _check(self, proc, url, expect_threshold=None):
        try:
            with urllib.request.urlopen(url + "/model", timeout=10) as r:
                info = json.loads(r.read())
            self.assertEqual(info["workers"]["mode"], "process")
            self.assertGreaterEqual(info["workers"]["live"], 1)
            if expect_threshold is not None:
                self.assertAlmostEqual(info["threshold"], expect_threshold, places=6)
            req = urllib.request.Request(url + "/", data=b"MZ" + b"\x00" * 300, headers={"Content-Type": "application/octet-stream"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                self.assertEqual(json.loads(r.read()), {"result": 1})
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()

    @unittest.skipUnless(model_available(DEPLOYED_MODEL_DIR), "deployed model arrays not present")
    def test_single_model_entry_point_starts(self):
        proc, url = _run("defender.server", {"DF_MODEL_DIR": DEPLOYED_MODEL_DIR, "DF_MALWARE_THRESHOLD": DEPLOYED_THRESHOLD, "DF_WORKERS": 1})
        self._check(proc, url, DEPLOYED_THRESHOLD)

    @unittest.skipUnless(all(pathlib.Path(p).exists() for p in ENSEMBLE.values()), "v3.3 ensemble artifacts not present")
    def test_ensemble_entry_point_starts(self):
        proc, url = _run("defender.ensemble_server", {**ENSEMBLE, "DF_WORKERS": 1})
        self._check(proc, url)


if __name__ == "__main__":
    unittest.main()
