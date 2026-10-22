"""The HTTP evaluators must not credit late, missing, malformed or non-200 answers
(review 2026-09-21, finding 4; re-verification 2026-10-22: booleans and HTTP 500 bodies)."""
from __future__ import annotations

import http.server
import importlib.util
import json
import os
import pathlib
import shutil
import tempfile
import threading
import time
import unittest

from tests.common import ROOT, SAMPLE_DIR

spec = importlib.util.spec_from_file_location("evaluate_tool", ROOT / "tools" / "evaluate.py")
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)


class MockHandler(http.server.BaseHTTPRequestHandler):
    """Behaviour keyed on the body length modulo 7 (the test names its files so)."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: D401
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        mode = len(body) % 7
        if mode == 1:                       # late: a 1 after 1.3 s (deadline 1.0 in the test)
            time.sleep(1.3); payload, status = b'{"result": 1}', 200
        elif mode == 2:                     # drop the connection without a response
            self.close_connection = True; self.connection.close(); return
        elif mode == 3:                     # malformed JSON
            payload, status = b"{not json", 200
        elif mode == 4:                     # boolean is not an answer
            payload, status = b'{"result": true}', 200
        elif mode == 5:                     # non-200 status with a plausible body
            payload, status = b'{"result": 1}', 500
        else:
            payload, status = b'{"result": 0}', 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class EvaluatorDeadlineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        # one file per mock behaviour: body length % 7 selects it
        cls.files = {}
        for mode, name in ((1, "late"), (2, "drop"), (3, "malformed"), (4, "boolean"), (5, "http500"), (0, "ok")):
            p = cls.tmp / f"{name}.bin"
            p.write_bytes(b"M" * (7 * 100 + mode))
            cls.files[name] = p

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_non_answer_counts_against_the_detector_and_nothing_aborts(self):
        rows = list(evaluate.score_over_http(list(self.files.values()), self.url, deadline=1.0))
        self.assertEqual(len(rows), 6, "every submitted sample stays in the denominator")
        by_name = {p.name.split(".")[0]: (score, failed, secs) for p, score, failed, secs in rows}
        self.assertEqual(by_name["ok"][:2], (0.0, False))
        for name in ("late", "drop", "malformed", "boolean", "http500"):
            score, failed, _ = by_name[name]
            self.assertIsNone(score, name)
            self.assertTrue(failed, name)
        self.assertTrue(any(k in by_name["late"][1].lower() for k in ("late", "timed out")), by_name["late"][1])

    def test_unreadable_local_file_does_not_abort_the_run(self):
        missing = self.tmp / "missing.bin"
        rows = list(evaluate.score_over_http([missing, self.files["ok"]], self.url, deadline=1.0))
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0][1]); self.assertTrue(rows[0][2])
        self.assertEqual(rows[1][1], 0.0)


class GradeHttpTest(unittest.TestCase):
    """grade_http.py: a late or non-integer answer is no answer (counted against us)."""

    def test_grade_http_counts_non_answers_against_the_detector(self):
        import subprocess, sys
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            (tmp / "malware").mkdir(); (tmp / "goodware").mkdir()
            samples = []
            for i, (mode, is_mal) in enumerate(((0, False), (0, True), (1, True), (4, True), (5, False), (2, False))):
                sha = f"{i:064x}"
                (tmp / ("malware" if is_mal else "goodware") / f"{sha}.bin").write_bytes(b"M" * (7 * 50 + mode))
                samples.append({"sha256": sha, "is_malware": is_mal, "family": "synthetic" if is_mal else None, "source_name": "synthetic"})
            (tmp / "manifest.json").write_text(json.dumps({"samples": samples}))
            out = subprocess.run([sys.executable, "-I", str(ROOT.parent / "dataset/tools/grade_http.py"), str(tmp), "mock", url, "1.0"],
                                 capture_output=True, text=True, timeout=60)
            line = out.stdout.strip().splitlines()[0]
            # ok-malware detected? mode 0 answers 0 -> FN. late(1) -> FN, boolean(4) -> FN: TP=0 FN=3; goodware: ok -> TN, http500 -> FP, drop -> FP
            self.assertIn("TP=0 FN=3 FP=2 TN=1", line, out.stdout + out.stderr)
            self.assertIn("errors=4", line)
        finally:
            server.shutdown(); server.server_close(); shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
