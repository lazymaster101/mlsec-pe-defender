"""HTTP-level deadline behaviour and the deployed single-model configuration."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest
import urllib.request

from tests.common import DEPLOYED_MODEL_DIR, DEPLOYED_THRESHOLD, SAMPLE_DIR, model_available
from defender import server as server_module


def _serve(defender):
    os.environ["DF_PORT"] = "0"
    os.environ["DF_HOST"] = "127.0.0.1"
    srv = server_module.serve(defender)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://%s:%d" % srv.server_address[:2]


def fast_scorer(body: bytes) -> int:
    if body.startswith(b"SLOW"):
        time.sleep(5)
    return int(body.startswith(b"MAL"))


class DeadlineHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defender = server_module.Defender(fast_scorer, lambda: {"model_name": "stub"}, 0.5,
                                              workers=1, mode="process", budget_seconds=1.0)
        cls.server, cls.url = _serve(cls.defender)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.defender.close()

    def _raw(self, request: bytes, wait: float) -> bytes:
        host, port = self.server.server_address[:2]
        with socket.create_connection((host, port), timeout=wait + 2) as s:
            s.sendall(request)
            s.settimeout(wait)
            out = b""
            try:
                while b"\r\n\r\n" not in out or len(out.split(b"\r\n\r\n", 1)[1]) < 13:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    out += chunk
            except socket.timeout:
                pass
            return out

    def test_stalled_upload_is_answered_within_the_budget(self):
        # declares 4 bytes, sends 2, then stalls (finding 2: no response after 5.2 s before)
        t = time.monotonic()
        out = self._raw(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
                        b"Content-Length: 4\r\n\r\nMZ", wait=3.0)
        elapsed = time.monotonic() - t
        self.assertIn(b"200", out.split(b"\r\n", 1)[0])
        self.assertIn(b'{"result": 1}', out)
        self.assertLess(elapsed, 2.5)
        self.assertGreaterEqual(self.defender.stats()["slow_upload"], 1)

    def test_overrun_is_answered_within_the_budget(self):
        t = time.monotonic()
        req = urllib.request.Request(self.url + "/", data=b"SLOW" + b"\x00" * 100,
                                     headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(json.loads(r.read()), {"result": 1})
        self.assertLess(time.monotonic() - t, 2.5)
        self.assertGreaterEqual(self.defender.stats()["overrun"], 1)
        # the killed worker is replaced and the next request is scored normally
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            req = urllib.request.Request(self.url + "/", data=b"benign", headers={"Content-Type": "application/octet-stream"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                if json.loads(r.read()) == {"result": 0}:
                    return
            time.sleep(0.1)
        self.fail("worker did not recover")

    def test_model_endpoint_reports_budget_and_workers(self):
        with urllib.request.urlopen(self.url + "/model", timeout=5) as r:
            info = json.loads(r.read())
        self.assertEqual(info["budget_seconds"], 1.0)
        self.assertEqual(info["workers"]["mode"], "process")
        for key in ("overrun", "saturated", "slow_upload", "worker_failed"):
            self.assertIn(key, info["counts"])


@unittest.skipUnless(model_available(DEPLOYED_MODEL_DIR), "deployed model arrays not present")
class DeployedConfigurationTest(unittest.TestCase):
    """The Dockerfile's configuration (rf_adv at 0.820932), not the supplied model's."""

    @classmethod
    def setUpClass(cls):
        os.environ["DF_MALWARE_THRESHOLD"] = str(DEPLOYED_THRESHOLD)
        cls.server, cls.defender = server_module.build(str(DEPLOYED_MODEL_DIR), workers=1)
        os.environ.pop("DF_MALWARE_THRESHOLD", None)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://%s:%d" % cls.server.server_address[:2]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.defender.close()

    def test_model_endpoint_reports_the_deployed_model(self):
        with urllib.request.urlopen(self.url + "/model", timeout=10) as r:
            info = json.loads(r.read())
        self.assertEqual(info["threshold"], DEPLOYED_THRESHOLD)
        self.assertEqual(info["n_features"], 250037)
        self.assertEqual(info["n_trees"], 100)

    def test_course_goodware_is_benign_and_garbage_is_flagged(self):
        if not SAMPLE_DIR.is_dir():
            self.skipTest("no PE samples")
        for p in sorted(SAMPLE_DIR.glob("*.exe")):
            req = urllib.request.Request(self.url + "/", data=p.read_bytes(), headers={"Content-Type": "application/octet-stream"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                self.assertEqual(json.loads(r.read()), {"result": 0}, p.name)
        req = urllib.request.Request(self.url + "/", data=b"garbage" * 1000, headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            self.assertEqual(json.loads(r.read()), {"result": 1})


if __name__ == "__main__":
    unittest.main()


class DripUploadTest(unittest.TestCase):
    """A client sending one byte at a time must not stretch the request past its budget
    (buffered reads retried per byte; verification 2026-10-22)."""

    @classmethod
    def setUpClass(cls):
        cls.defender = server_module.Defender(fast_scorer, lambda: {"model_name": "stub"}, 0.5,
                                              workers=1, mode="process", budget_seconds=1.0)
        cls.server, cls.url = _serve(cls.defender)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.defender.close()

    def test_drip_upload_is_answered_at_the_budget(self):
        host, port = self.server.server_address[:2]
        t = time.monotonic()
        with socket.create_connection((host, port), timeout=10) as s:
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 40\r\n\r\n")
            out = b""
            s.settimeout(0.25)
            for _ in range(40):                       # one byte every 0.25 s = 10 s total
                try:
                    s.sendall(b"M")
                except OSError:
                    break
                try:
                    chunk = s.recv(4096)
                    if chunk:
                        out += chunk
                        if b"result" in out:
                            break
                except socket.timeout:
                    pass
            if b"result" not in out:
                s.settimeout(3)
                try:
                    while b"result" not in out:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        out += chunk
                except socket.timeout:
                    pass
        elapsed = time.monotonic() - t
        self.assertIn(b'{"result": 1}', out)
        self.assertLess(elapsed, 3.0, f"drip upload took {elapsed:.1f}s")
        self.assertGreaterEqual(self.defender.stats()["slow_upload"], 1)
