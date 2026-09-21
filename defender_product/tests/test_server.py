"""HTTP contract: the MLSEC endpoint, and the fail-toward-detection behaviour."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from tests.common import MODEL_DIR, SAMPLE_DIR, model_available

OCTET = {"Content-Type": "application/octet-stream"}


def post(url: str, body: bytes, headers: dict | None = None):
    request = urllib.request.Request(url, data=body, headers=headers or OCTET, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            return error.code, json.loads(payload)
        except ValueError:
            return error.code, {}


@unittest.skipUnless(model_available(), f"model arrays not found in {MODEL_DIR}")
class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import os
        os.environ.setdefault("DF_MODEL_DIR", str(MODEL_DIR))
        os.environ["DF_PORT"] = "0"           # let the OS pick a free port
        os.environ["DF_HOST"] = "127.0.0.1"
        from defender import server as server_module
        cls.server, cls.defender = server_module.build(str(MODEL_DIR))
        host, port = cls.server.server_address[:2]
        cls.url = f"http://{host}:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_and_model_endpoints(self) -> None:
        with urllib.request.urlopen(f"{self.url}/health", timeout=10) as response:
            self.assertEqual(json.loads(response.read())["status"], "ok")
        with urllib.request.urlopen(f"{self.url}/model", timeout=10) as response:
            info = json.loads(response.read())
        self.assertEqual(info["n_features"], 250041)
        self.assertEqual(info["feature_mode"], "training")
        self.assertEqual(info["threshold"], 0.25)

    def test_goodware_is_not_flagged(self) -> None:
        if not SAMPLE_DIR.is_dir():
            self.skipTest("no PE samples")
        for path in sorted(SAMPLE_DIR.glob("*.exe")):
            status, payload = post(self.url + "/", path.read_bytes())
            with self.subTest(sample=path.name):
                self.assertEqual(status, 200)
                self.assertEqual(payload, {"result": 0})

    def test_unparseable_input_is_reported_malicious(self) -> None:
        # A response of 1 is the safe answer: a missing answer scores as an evasion.
        for payload in (b"", b"MZ", b"garbage" * 100, b"\x00" * 65536):
            status, body = post(self.url + "/", payload)
            with self.subTest(payload=payload[:8]):
                self.assertEqual(status, 200)
                self.assertEqual(body, {"result": 1})

    def test_result_is_always_a_plain_zero_or_one(self) -> None:
        _, body = post(self.url + "/", b"MZ\x90\x00")
        self.assertIsInstance(body["result"], int)
        self.assertIn(body["result"], (0, 1))

    def test_wrong_content_type_is_rejected(self) -> None:
        status, _ = post(self.url + "/", b"MZ", {"Content-Type": "text/plain"})
        self.assertEqual(status, 400)

    def test_content_type_parameters_are_tolerated(self) -> None:
        status, body = post(self.url + "/", b"MZ",
                            {"Content-Type": "application/octet-stream; charset=binary"})
        self.assertEqual(status, 200)
        self.assertEqual(body["result"], 1)

    def test_unknown_routes_are_404(self) -> None:
        self.assertEqual(post(self.url + "/predict", b"MZ")[0], 404)
        request = urllib.request.Request(self.url + "/nope")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(caught.exception.code, 404)

    def test_oversized_body_still_gets_a_clean_answer(self) -> None:
        """Closing the socket mid-upload would reset the connection and lose the reply."""
        from defender import server as server_module
        status, body = post(self.url + "/", b"\x00" * (server_module.MAX_BODY_BYTES + 1))
        self.assertEqual(status, 200)
        self.assertEqual(body, {"result": 1})

    def test_concurrent_requests_all_answer(self) -> None:
        if not SAMPLE_DIR.is_dir():
            self.skipTest("no PE samples")
        samples = [p.read_bytes() for p in sorted(SAMPLE_DIR.glob("*.exe"))]
        results: list[tuple[int, dict]] = []
        lock = threading.Lock()

        errors: list[str] = []

        def worker(payload: bytes) -> None:
            try:
                outcome = post(self.url + "/", payload)
            except Exception as error:      # a dropped connection must fail the test
                with lock:
                    errors.append(f"{type(error).__name__}: {error}")
                return
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(samples[i % len(samples)],))
                   for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 16)
        for status, payload in results:
            self.assertEqual(status, 200)
            self.assertEqual(payload, {"result": 0})


if __name__ == "__main__":
    unittest.main()
