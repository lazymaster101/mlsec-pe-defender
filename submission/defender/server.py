"""MLSEC defender HTTP endpoint on the standard library.

Implements the competition contract: ``POST /`` with an ``application/octet-stream``
body returns ``{"result": 0|1}``. Every failure mode -- unparseable input, an
oversized body, or work that overruns the latency budget -- answers 1 within the
budget, because a response that never arrives is scored as a successful evasion.
"""
from __future__ import annotations

import concurrent.futures
import http.server
import json
import os
import socket
import sys
import threading
import time
from typing import Any

import numpy as np

from defender.model import Model

MAX_BODY_BYTES = int(os.environ.get("DF_MAX_BODY_BYTES", 64 * 1024 * 1024))
# Beyond this we stop reading and drop the connection; a body that large is not a
# sample under test, and draining it forever would deny service to the next one.
MAX_DRAIN_BYTES = int(os.environ.get("DF_MAX_DRAIN_BYTES", 256 * 1024 * 1024))
REQUEST_BUDGET_SECONDS = float(os.environ.get("DF_REQUEST_BUDGET_SECONDS", 4.0))
WORKERS = int(os.environ.get("DF_WORKERS", 2))
OCTET_STREAM = "application/octet-stream"


def log(message: str, **fields: Any) -> None:
    payload = {"ts": round(time.time(), 3), "msg": message, **fields}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


class Defender:
    def __init__(self, model: Model, threshold: float) -> None:
        self.model = model
        self.threshold = threshold
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=WORKERS, thread_name_prefix="infer")
        self._counts = {"benign": 0, "malicious": 0, "unparseable": 0, "overrun": 0}
        self._lock = threading.Lock()

    def _score(self, bytez: bytes) -> int:
        probability = self.model.predict(bytez)["malware_probability"]
        # NeedForSpeedModel.predict_threshold: int(P(benign) < benign_threshold).
        return int(probability > self.threshold)

    def classify(self, bytez: bytes) -> tuple[int, str]:
        future = self._pool.submit(self._score, bytez)
        try:
            return future.result(timeout=REQUEST_BUDGET_SECONDS), "scored"
        except concurrent.futures.TimeoutError:
            # The worker keeps running; the pool bounds how many can pile up.
            return 1, "overrun"
        except Exception as error:  # malformed PE, parser rejection, truncation
            log("unparseable", error=f"{type(error).__name__}: {error}")
            return 1, "unparseable"

    def record(self, result: int, reason: str) -> None:
        key = reason if reason in ("unparseable", "overrun") else ("malicious" if result else "benign")
        with self._lock:
            self._counts[key] += 1

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mlsec-defender"
    sys_version = ""
    defender: Defender

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logging
        pass

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/health":
            self._respond(200, {"status": "ok"})
        elif path == "/model":
            self._respond(200, {**self.defender.model.info(),
                                "threshold": self.defender.threshold,
                                "counts": self.defender.stats()})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if (self.path.split("?", 1)[0].rstrip("/") or "/") != "/":
            self._respond(404, {"error": "not found"})
            return
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != OCTET_STREAM:
            # Be liberal in what we accept: the body is the sample whatever the client
            # declared (e.g. curl --data-binary sends form-urlencoded). Rejecting would
            # leave the sample unanswered, which scores as an evasion.
            log("non_octet_content_type", content_type=content_type or "<none>")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._respond(411, {"error": "Content-Length required"})
            return
        if length < 0:
            self._respond(400, {"error": "invalid Content-Length"})
            return
        if length > MAX_BODY_BYTES:
            # Answer 1 rather than erroring: an unanswered sample scores as an evasion.
            # The body is discarded as it arrives, so memory stays flat.
            drained = self._drain(length)
            self.defender.record(1, "oversize")
            log("oversize", bytes=length, drained=drained)
            if not drained:
                self.close_connection = True
            self._respond(200, {"result": 1})
            return

        started = time.perf_counter()
        bytez = self._read_exactly(length)
        if bytez is None:
            self.close_connection = True
            self._respond(400, {"error": "truncated body"})
            return

        result, reason = self.defender.classify(bytez)
        self.defender.record(result, reason)
        elapsed = time.perf_counter() - started
        log("classified", result=result, reason=reason, bytes=length,
            seconds=round(elapsed, 4))
        self._respond(200, {"result": result})

    def _drain(self, length: int) -> bool:
        """Discard an oversized body in bounded chunks so the reply still gets through."""
        if length > MAX_DRAIN_BYTES:
            return False
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                return False
            remaining -= len(chunk)
        return True

    def _read_exactly(self, length: int) -> bytes | None:
        chunks, remaining = [], length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET
    # The stdlib default of 5 makes concurrent graders lose connections to the
    # accept backlog before the handler ever sees them.
    request_queue_size = 128


def build(model_dir: str | None = None) -> tuple[Server, Defender]:
    directory = model_dir or os.environ.get("DF_MODEL_DIR", "models/nfs")
    threshold = float(os.environ.get("DF_MALWARE_THRESHOLD", 0.25))
    mode = os.environ.get("DF_FEATURE_MODE", "training")
    model = Model(directory, mode)
    defender = Defender(model, threshold)
    handler = type("BoundHandler", (Handler,), {"defender": defender})
    host = os.environ.get("DF_HOST", "0.0.0.0")
    port = int(os.environ.get("DF_PORT", 8080))
    return Server((host, port), handler), defender


def main() -> None:
    server, defender = build()
    info = defender.model.info()
    # Touch the forest once so the first graded sample does not pay page-fault cost.
    warm = time.perf_counter()
    defender.model.probability(np.zeros(defender.model.n_features, dtype=np.float32))
    log("ready", **info, threshold=defender.threshold,
        warmup_seconds=round(time.perf_counter() - warm, 3),
        address="%s:%d" % server.server_address[:2],
        max_body_bytes=MAX_BODY_BYTES, budget_seconds=REQUEST_BUDGET_SECONDS)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutdown", counts=defender.stats())
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
