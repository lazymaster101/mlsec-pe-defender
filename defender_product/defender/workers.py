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
REPLY_TIMEOUT = 30.0          # child -> parent reply and warm-up round trip
MAX_REQUESTS_PER_WORKER = 50  # recycle the worker after this many requests ...
RECYCLE_BODY_BYTES = 8 << 20  # ... or after one body this large (heap fragmentation)
RESPAWN_ATTEMPTS = 5


def _send_frame(sock: socket.socket, payload: bytes, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("deadline passed before send")
    sock.settimeout(remaining)
    sock.sendall(_HEADER.pack(len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int, deadline: Optional[float]) -> bytes:
    """Receive exactly n bytes into ONE preallocated buffer (a 64 MB body costs one copy,
    not a chunk list plus a join). ``deadline=None`` means block indefinitely: the timeout
    is reset explicitly because an earlier send on the same socket left one behind
    (verification 2026-10-22: idle workers were timing out after 30 s and exiting)."""
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    if deadline is None:
        sock.settimeout(None)
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
    """Runs in the child: read a body, score it, reply; repeat until the parent goes away
    or the worker asks to be recycled (its reply then carries retire=True and it exits
    after sending; the parent replaces it without losing a request)."""
    parent_end.close()            # inherited across fork; the child must not hold the parent's end
    _close_inherited_sockets(keep=sock.fileno())
    served = 0
    try:
        _serve_loop(sock, score_fn)
    finally:
        sock.close()


def _close_inherited_sockets(keep: int) -> None:
    """Linux: a forked worker inherits the listening socket and any in-flight client
    sockets; close them so they are not held open until the worker dies."""
    fd_dir = "/proc/self/fd"
    if not os.path.isdir(fd_dir):
        return
    import stat
    for name in os.listdir(fd_dir):
        try:
            fd = int(name)
            if fd <= 2 or fd == keep:
                continue
            if stat.S_ISSOCK(os.fstat(fd).st_mode):
                os.close(fd)
        except OSError:
            pass


def _serve_loop(sock: socket.socket, score_fn: Callable[[bytes], int]) -> None:
    served = 0
    while True:
        try:
            body = _recv_frame(sock, None)
        except (EOFError, OSError):
            return
        if isinstance(body, bytearray):
            body = bytes(body)        # one copy; the bytearray is released at the rebind
        size = len(body)
        try:
            result, reason = int(score_fn(body)), "scored"
            if result not in (0, 1):
                result, reason = 1, "invalid_result"
        except Exception as error:                     # malformed PE, parser rejection
            result, reason = 1, "unparseable:" + type(error).__name__
        del body
        served += 1
        retire = served >= MAX_REQUESTS_PER_WORKER or size >= RECYCLE_BODY_BYTES
        try:
            _send_frame(sock, json.dumps([result, reason, retire]).encode(), time.monotonic() + REPLY_TIMEOUT)
        except OSError:
            return
        if retire:
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
        self._stats = {"spawned": 0, "killed_overrun": 0, "died": 0, "recycled": 0, "respawn_failed": 0}
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
        """Fork one worker and warm it up. In the background (block=False) failures are
        retried with backoff; in the foreground (startup) they raise."""
        last: Optional[BaseException] = None
        for attempt in range(1 if block else RESPAWN_ATTEMPTS):
            try:
                parent_sock, child_sock = socket.socketpair()
                process = self._ctx.Process(target=_child_loop, args=(child_sock, parent_sock, self._score_fn), daemon=True)
                process.start()
                child_sock.close()
            except Exception as error:               # fork/EAGAIN, fd exhaustion
                last = error
                time.sleep(0.2 * (attempt + 1))
                continue
            worker = _Worker(process, parent_sock)
            with self._lock:
                self._live.add(worker)
                self._stats["spawned"] += 1
            if self._warmup is not None:
                try:  # first prediction pays import / page-fault / thread-pool costs; do it off the request path
                    _send_frame(worker.sock, self._warmup, time.monotonic() + REPLY_TIMEOUT)
                    _recv_frame(worker.sock, time.monotonic() + REPLY_TIMEOUT)
                except (OSError, EOFError) as error:
                    last = error
                    self._retire(worker, "died")
                    worker.reap()
                    time.sleep(0.2 * (attempt + 1))
                    continue
            self._idle.put(worker)
            return
        with self._lock:
            self._stats["respawn_failed"] += 1
        if block:
            raise RuntimeError(f"inference worker failed to start: {last!r}")

    def _spawn_async(self, reap: Optional[_Worker] = None) -> None:
        def run() -> None:
            if reap is not None:
                reap.reap()          # off the request path: the overrun answer is not delayed
            self._spawn(block=False)
        threading.Thread(target=run, daemon=True, name="respawn").start()

    def _retire(self, worker: _Worker, why: str) -> None:
        with self._lock:
            self._live.discard(worker)
            self._stats[{"overrun": "killed_overrun", "recycled": "recycled"}.get(why, "died")] += 1
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
        except BaseException:                 # never leak a worker out of the pool
            self._retire(worker, "died")
            self._spawn_async(reap=worker)
            raise
        try:
            decoded = json.loads(bytes(reply))
            result, reason = int(decoded[0]), str(decoded[1])
            retire = bool(decoded[2]) if len(decoded) > 2 else False
        except (ValueError, TypeError, IndexError):
            self._retire(worker, "died")
            self._spawn_async(reap=worker)
            return 1, "invalid_reply"
        if retire:                            # the child exits after this reply: replace it now
            self._retire(worker, "recycled")
            self._spawn_async(reap=worker)
        else:
            self._idle.put(worker)
        return result, reason

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
