"""MLSEC defender HTTP endpoint on the standard library.

Implements the competition contract: ``POST /`` with an ``application/octet-stream``
body returns ``{"result": 0|1}``. Every failure mode -- unparseable input, an
oversized body, a stalled upload, a saturated server, or work that overruns the
budget -- answers 1 inside the budget, because a response that never arrives is
scored as a successful evasion.

Budget accounting (review 2026-09-21, finding 2): ``DF_REQUEST_BUDGET_SECONDS``
(default 4.0 of the harness's 5.0) is measured from the moment the request headers are
in, and covers reading the body, waiting for an inference worker, and inference. The
body is read under a socket deadline; inference runs in a forked worker process that is
SIGKILLed at the deadline (defender/workers.py), so a native call that holds the
interpreter lock cannot push the answer past the budget; and admission is bounded by the
number of workers, so nothing queues beyond its own deadline and no input buffer outlives
its request. Time spent before the headers arrive (connection accept, TLS, client-side
upload stalls before the request line) is outside the server's control.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import sys
import threading
import time
from typing import Any, Callable

from defender.model import Model
from defender.workers import WorkerPool

MAX_BODY_BYTES = int(os.environ.get("DF_MAX_BODY_BYTES", 64 * 1024 * 1024))
# Beyond this we stop reading and drop the connection; a body that large is not a
# sample under test, and draining it forever would deny service to the next one.
MAX_DRAIN_BYTES = int(os.environ.get("DF_MAX_DRAIN_BYTES", 256 * 1024 * 1024))
REQUEST_BUDGET_SECONDS = float(os.environ.get("DF_REQUEST_BUDGET_SECONDS", 4.0))
WORKERS = int(os.environ.get("DF_WORKERS", 2))
WORKER_MODE = os.environ.get("DF_WORKER_MODE", "process")   # 'process' (killable) or 'thread'
# Bodies up to this size are read fully in this process before a worker is reserved, so
# a stalled or slow small upload never holds the (single) worker; larger bodies are
# streamed straight into the worker to keep this process's memory flat.
STREAM_THRESHOLD = int(os.environ.get("DF_STREAM_THRESHOLD", 8 * 1024 * 1024))
# Idle keep-alive sockets wait this long for the next request line; the request budget
# starts only once a request's headers are in.
KEEPALIVE_IDLE_SECONDS = float(os.environ.get("DF_KEEPALIVE_IDLE_SECONDS", 60.0))
OCTET_STREAM = "application/octet-stream"


def log(message: str, **fields: Any) -> None:
    payload = {"ts": round(time.time(), 3), "msg": message, **fields}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


class Defender:
    """Owns the worker pool and the counters. ``score_fn(bytes) -> 0|1`` runs in workers."""

    REASONS = ("benign", "malicious", "unparseable", "overrun", "saturated", "slow_upload",
               "worker_failed", "oversize")

    def __init__(self, score_fn: Callable[[bytes], int], info: Callable[[], dict],
                 threshold: float, workers: int = WORKERS, mode: str = WORKER_MODE,
                 budget_seconds: float = REQUEST_BUDGET_SECONDS, model: Any = None) -> None:
        self.model = model                      # kept for /model and for in-process tools
        self.threshold = threshold
        self.budget_seconds = float(budget_seconds)
        self._info = info
        self._pool = WorkerPool(score_fn, n_workers=workers, mode=mode)
        if self._pool.mode != "process":
            log("warning", detail="DF_WORKER_MODE=thread cannot interrupt a native call: the request "
                "budget is NOT enforceable against hostile input; the shipped images use process mode")
        self._counts = {k: 0 for k in self.REASONS}
        self._lock = threading.Lock()

    @classmethod
    def for_model(cls, model: Model, threshold: float, **kw: Any) -> "Defender":
        def score(bytez: bytes) -> int:
            # NeedForSpeedModel.predict_threshold: int(P(benign) < benign_threshold).
            return int(model.predict(bytez)["malware_probability"] > threshold)
        return cls(score, model.info, threshold, model=model, **kw)

    def _finish(self, result: int, reason: str) -> tuple[int, str]:
        if reason.startswith("unparseable"):
            log("unparseable", error=reason.partition(":")[2] or "parser rejected input")
            reason = "unparseable"
        elif reason not in ("scored",):
            log(reason, workers=self._pool.stats())
        return result, reason

    def classify(self, bytez: bytes, deadline: float | None = None) -> tuple[int, str]:
        """In-memory body. -> (result, reason). ``deadline`` is a time.monotonic() instant;
        default = now + budget."""
        if deadline is None:
            deadline = time.monotonic() + self.budget_seconds
        return self._finish(*self._pool.classify(bytez, deadline))

    def classify_stream(self, reader: Callable[[int], bytes], length: int,
                        deadline: float | None = None) -> tuple[int, str]:
        """Body relayed from ``reader`` (the client socket) straight into a worker."""
        if deadline is None:
            deadline = time.monotonic() + self.budget_seconds
        return self._finish(*self._pool.classify_stream(reader, length, deadline))

    def record(self, result: int, reason: str) -> None:
        key = reason if reason in self._counts else ("malicious" if result else "benign")
        with self._lock:
            self._counts[key] += 1

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def info(self) -> dict:
        return {**self._info(), "threshold": self.threshold, "counts": self.stats(),
                "budget_seconds": self.budget_seconds, "workers": self._pool.stats()}

    def close(self) -> None:
        self._pool.close()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mlsec-defender"
    sys_version = ""
    defender: Defender

    def setup(self) -> None:
        super().setup()
        # Between requests a keep-alive socket may idle; a request line, once started, is
        # read under this timeout too (a slow-loris holds a handler thread, never a worker).
        self.connection.settimeout(KEEPALIVE_IDLE_SECONDS)

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
            self._respond(200, self.defender.info())
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if (self.path.split("?", 1)[0].rstrip("/") or "/") != "/":
            self._respond(404, {"error": "not found"})
            return
        started = time.monotonic()
        deadline = started + self.defender.budget_seconds
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
            drained = self._drain(length, deadline)
            self.defender.record(1, "oversize")
            log("oversize", bytes=length, drained=drained)
            if not drained:
                self.close_connection = True
            self._respond(200, {"result": 1})
            return

        consumed = 0

        def reader(n: int) -> bytes:
            nonlocal consumed
            budget = deadline - time.monotonic()
            if budget <= 0:
                return b""
            self.connection.settimeout(budget)
            # read1: at most ONE underlying recv, so a client dripping bytes cannot stretch
            # the request past its deadline (rfile.read(n) would loop per byte with the
            # timeout applied to each recv; verification 2026-10-22)
            chunk = self.rfile.read1(n)
            consumed += len(chunk)
            return chunk

        if length <= STREAM_THRESHOLD:
            # Small body: buffer it here first, so the worker is reserved only for inference
            # and a stalled client cannot hold it (single-flight images, DF_WORKERS=1).
            bytez = self._read_exactly(length, deadline)
            consumed = length if bytez is not None else consumed
            if bytez is None:
                result, reason = 1, "slow_upload"
            else:
                result, reason = self.defender.classify(bytez, deadline)
                del bytez
        else:
            # Large body: streamed from the client socket straight into the worker; this
            # process never holds a whole sample (memory headroom under the 1 GiB cap).
            result, reason = self.defender.classify_stream(reader, length, deadline)
        if reason in ("slow_upload", "saturated", "overrun", "worker_failed"):
            # Part of the body may still be in flight. Drain what we can inside the deadline
            # so the client reads our answer instead of a reset, then close.
            if reason != "slow_upload":
                self._drain(length - consumed, deadline)
            self.close_connection = True
        self.defender.record(result, reason)
        log("classified" if reason == "scored" else reason, result=result, reason=reason,
            bytes=length, seconds=round(time.monotonic() - started, 4))
        self._respond(200, {"result": result})

    def _drain(self, length: int, deadline: float) -> bool:
        """Discard up to ``length`` body bytes in bounded chunks, inside the deadline, so the
        reply still gets through (oversize bodies; unread remainders after a refusal)."""
        if length <= 0:
            return True
        if length > MAX_DRAIN_BYTES:
            return False
        remaining = length
        while remaining > 0:
            budget = deadline - time.monotonic()
            if budget <= 0:
                return False
            self.connection.settimeout(budget)
            try:
                chunk = self.rfile.read1(min(remaining, 1 << 20))
            except (socket.timeout, OSError):
                return False
            if not chunk:
                return False
            remaining -= len(chunk)
        return True

    def _read_exactly(self, length: int, deadline: float) -> bytes | None:
        chunks, remaining = [], length
        while remaining > 0:
            budget = deadline - time.monotonic()
            if budget <= 0:
                return None
            self.connection.settimeout(budget)
            try:
                chunk = self.rfile.read1(min(remaining, 1 << 20))
            except (socket.timeout, OSError):
                return None
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


def serve(defender: Defender) -> Server:
    handler = type("BoundHandler", (Handler,), {"defender": defender})
    host = os.environ.get("DF_HOST", "0.0.0.0")
    port = int(os.environ.get("DF_PORT", 8080))
    return Server((host, port), handler)


def build(model_dir: str | None = None, **kw: Any) -> tuple[Server, Defender]:
    directory = model_dir or os.environ.get("DF_MODEL_DIR", "models/nfs")
    threshold = float(os.environ.get("DF_MALWARE_THRESHOLD", 0.25))
    mode = os.environ.get("DF_FEATURE_MODE", "training")
    model = Model(directory, mode)
    defender = Defender.for_model(model, threshold, **kw)
    return serve(defender), defender


def main() -> None:
    server, defender = build()
    # Workers warmed themselves at fork time (defender/workers.py); the parent never scores.
    log("ready", **defender.info(), address="%s:%d" % server.server_address[:2],
        max_body_bytes=MAX_BODY_BYTES)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutdown", counts=defender.stats())
    finally:
        defender.close()
        server.server_close()


if __name__ == "__main__":
    main()
