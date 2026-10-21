"""Terminable inference workers with a hard per-request deadline.

Why a process and not a thread: a thread that is inside a native call (LIEF parsing a
hostile PE, a LightGBM predict) cannot be interrupted from Python, so a thread-pool
``future.result(timeout=...)`` only abandons the *caller*; the work keeps running, keeps
its input buffer, and keeps the worker slot (review 2026-09-21, finding 2). A child
process can be killed with SIGKILL at the deadline and replaced.

Design:
  * The parent loads the models once and forks ``n_workers`` children; the model pages
    are shared copy-on-write, so a replacement after a kill costs a fork (milliseconds),
    not a model load. The parent itself never runs the scoring function, so OpenMP /
    BLAS thread pools are only ever created inside children (fork after an OpenMP
    parallel region can deadlock the child).
  * Each child owns one end of a socketpair. The parent sends a length-prefixed body
    with ``sendall`` under a socket timeout and waits for the length-prefixed reply
    under the remaining budget. Every blocking step is bounded by the deadline.
  * Admission is bounded by the number of workers: a request waits for an idle worker
    at most until its own deadline, then is answered ``1`` ("saturated"). Nothing is
    queued beyond that, so no input buffer outlives its request.
  * A worker that overruns is SIGKILLed and replaced asynchronously; a worker that dies
    (e.g. a native crash on hostile input) is detected by the broken socket and replaced.

Fallback: ``mode="thread"`` keeps the old in-process thread pool for platforms where
fork is unavailable; it cannot enforce the deadline against native calls and says so.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import socket
import struct
import threading
import time
from typing import Callable, Optional

_HEADER = struct.Struct("!Q")
WARMUP_BYTES = b"MZ" + b"\x00" * 128


def _send_frame(sock: socket.socket, payload: bytes, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("deadline passed before send")
    sock.settimeout(remaining)
    sock.sendall(_HEADER.pack(len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int, deadline: Optional[float]) -> bytes:
    """Receive exactly n bytes into ONE preallocated buffer (a 64 MB body costs one copy,
    not a chunk list plus a join)."""
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("deadline passed during receive")
            sock.settimeout(remaining)
        k = sock.recv_into(view[got:], min(n - got, 1 << 20))
        if not k:
            raise EOFError("peer closed")
        got += k
    return bytes(buf) if n < (1 << 16) else buf   # small frames as bytes; large ones stay a bytearray


def _recv_frame(sock: socket.socket, deadline: Optional[float]) -> bytes:
    (length,) = _HEADER.unpack(_recv_exact(sock, _HEADER.size, deadline))
    return _recv_exact(sock, length, deadline)


def _child_loop(sock: socket.socket, parent_end: socket.socket, score_fn: Callable[[bytes], int]) -> None:
    """Runs in the child: read a body, score it, reply; repeat until the parent goes away."""
    parent_end.close()            # inherited across fork; the child must not hold the parent's end
    sock.settimeout(None)
    while True:
        try:
            body = _recv_frame(sock, None)
        except (EOFError, OSError):
            return
        if isinstance(body, bytearray):
            body = bytes(body)        # one copy; the bytearray is released at the rebind
        try:
            result, reason = int(score_fn(body)), "scored"
            if result not in (0, 1):
                result, reason = 1, "invalid_result"
        except Exception as error:                     # malformed PE, parser rejection
            result, reason = 1, "unparseable:" + type(error).__name__
        try:
            _send_frame(sock, json.dumps([result, reason]).encode(), time.monotonic() + 30.0)
        except OSError:
            return


class _Worker:
    __slots__ = ("process", "sock", "born")

    def __init__(self, process, sock: socket.socket) -> None:
        self.process, self.sock, self.born = process, sock, time.monotonic()

    def kill(self) -> None:
        """SIGKILL and close; does not wait (reaping happens in the respawn thread)."""
        try:
            self.process.kill()
        except Exception:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def reap(self) -> None:
        try:
            self.process.join(2.0)
        except Exception:
            pass


class WorkerPool:
    """``classify(body, deadline)`` -> (result, reason), never later than ``deadline``."""

    def __init__(self, score_fn: Callable[[bytes], int], n_workers: int = 2,
                 mode: str = "process", warmup: bytes | None = WARMUP_BYTES) -> None:
        if mode not in ("process", "thread"):
            raise ValueError("mode must be 'process' or 'thread'")
        if mode == "process" and not hasattr(os, "fork"):
            mode = "thread"
        self.mode = mode
        self.n_workers = max(1, int(n_workers))
        self._score_fn = score_fn
        self._warmup = warmup
        self._idle: "queue.Queue[_Worker]" = queue.Queue()
        self._lock = threading.Lock()
        self._live: set[_Worker] = set()
        self._stats = {"spawned": 0, "killed_overrun": 0, "died": 0}
        if mode == "process":
            self._ctx = multiprocessing.get_context("fork")
            for _ in range(self.n_workers):
                self._spawn(block=True)
        else:
            import concurrent.futures
            self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.n_workers,
                                                               thread_name_prefix="infer")
            self._slots = threading.BoundedSemaphore(self.n_workers)

    # -- process mode ------------------------------------------------------------------
    def _spawn(self, block: bool) -> None:
        parent_sock, child_sock = socket.socketpair()
        process = self._ctx.Process(target=_child_loop, args=(child_sock, parent_sock, self._score_fn), daemon=True)
        process.start()
        child_sock.close()
        worker = _Worker(process, parent_sock)
        with self._lock:
            self._live.add(worker)
            self._stats["spawned"] += 1
        if self._warmup is not None:
            try:  # first prediction pays import / page-fault / thread-pool costs; do it off the request path
                _send_frame(worker.sock, self._warmup, time.monotonic() + 30.0)
                _recv_frame(worker.sock, time.monotonic() + 30.0)
            except (OSError, EOFError):
                self._retire(worker, "died")
                if block:
                    raise RuntimeError("inference worker failed its warm-up")
                return
        self._idle.put(worker)

    def _spawn_async(self, reap: Optional[_Worker] = None) -> None:
        def run() -> None:
            if reap is not None:
                reap.reap()          # off the request path: the overrun answer is not delayed
            self._spawn(block=False)
        threading.Thread(target=run, daemon=True, name="respawn").start()

    def _retire(self, worker: _Worker, why: str) -> None:
        with self._lock:
            self._live.discard(worker)
            self._stats["killed_overrun" if why == "overrun" else "died"] += 1
        worker.kill()

    def classify(self, body: bytes, deadline: float) -> tuple[int, str]:
        """In-memory body (tools, tests)."""
        if self.mode == "thread":
            return self._classify_thread(body, deadline)
        view, pos = memoryview(body), 0

        def reader(n: int) -> bytes:
            nonlocal pos
            chunk = view[pos:pos + n].tobytes()
            pos += len(chunk)
            return chunk
        return self.classify_stream(reader, len(body), deadline)

    def classify_stream(self, reader: Callable[[int], bytes], length: int, deadline: float) -> tuple[int, str]:
        """Relay ``length`` bytes from ``reader(n)`` (which may raise socket.timeout / OSError
        or return b"" when the upload stalls) straight into a worker, so the parent never
        holds the whole body. -> (result, reason)."""
        if self.mode == "thread":
            chunks, remaining = [], length
            try:
                while remaining > 0:
                    chunk = reader(min(remaining, 1 << 20))
                    if not chunk:
                        return 1, "slow_upload"
                    chunks.append(chunk); remaining -= len(chunk)
            except (socket.timeout, OSError):
                return 1, "slow_upload"
            return self._classify_thread(b"".join(chunks), deadline)
        wait = max(0.0, deadline - time.monotonic())
        try:
            worker = self._idle.get(timeout=wait)
        except queue.Empty:
            return 1, "saturated"
        try:
            remaining_bytes = length
            worker.sock.settimeout(max(0.0, deadline - time.monotonic()))
            worker.sock.sendall(_HEADER.pack(length))
            while remaining_bytes > 0:
                try:
                    chunk = reader(min(remaining_bytes, 1 << 20))
                except (socket.timeout, OSError):
                    chunk = b""
                if not chunk:
                    # the client stalled: the worker is mid-frame and cannot be reused
                    self._retire(worker, "died")
                    self._spawn_async(reap=worker)
                    return 1, "slow_upload"
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise socket.timeout("deadline passed during relay")
                worker.sock.settimeout(budget)
                worker.sock.sendall(chunk)
                remaining_bytes -= len(chunk)
            reply = _recv_frame(worker.sock, deadline)
        except socket.timeout:
            self._retire(worker, "overrun")
            self._spawn_async(reap=worker)
            return 1, "overrun"
        except (EOFError, OSError):
            self._retire(worker, "died")
            self._spawn_async(reap=worker)
            return 1, "worker_failed"
        self._idle.put(worker)
        try:
            result, reason = json.loads(bytes(reply))
            return int(result), str(reason)
        except (ValueError, TypeError):
            return 1, "invalid_reply"

    # -- thread mode (fallback; cannot interrupt native calls) -------------------------
    def _classify_thread(self, body: bytes, deadline: float) -> tuple[int, str]:
        wait = max(0.0, deadline - time.monotonic())
        if not self._slots.acquire(timeout=wait):
            return 1, "saturated"
        done = threading.Event()

        def run() -> tuple[int, str]:
            try:
                try:
                    return int(self._score_fn(body)), "scored"
                except Exception as error:
                    return 1, "unparseable:" + type(error).__name__
            finally:
                done.set()
                self._slots.release()

        future = self._pool.submit(run)
        if done.wait(timeout=max(0.0, deadline - time.monotonic())):
            return future.result()
        return 1, "overrun"              # the thread keeps running: thread mode cannot kill it

    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "live": len(self._live), "mode": self.mode, "workers": self.n_workers}

    def close(self) -> None:
        if self.mode == "thread":
            self._pool.shutdown(wait=False, cancel_futures=True)
            return
        with self._lock:
            workers = list(self._live)
            self._live.clear()
        for worker in workers:
            worker.kill()
        for worker in workers:
            worker.reap()
