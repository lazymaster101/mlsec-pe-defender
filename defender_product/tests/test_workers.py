"""Deadline enforcement (review 2026-09-21, finding 2): work that overruns is killed, not
abandoned; admission is bounded; a dead worker is replaced; the answer is always on time."""
from __future__ import annotations

import ctypes
import os
import threading
import time
import unittest

from tests import common  # noqa: F401  (sets single-threaded BLAS/OpenMP before any fork)
from defender.workers import WorkerPool


def scorer(body: bytes) -> int:
    if body == b"slow":
        time.sleep(5)
    elif body == b"native-slow":
        ctypes.PyDLL(None).sleep(5)        # holds the GIL inside a native call
    elif body == b"crash":
        os._exit(7)
    elif body == b"boom":
        raise ValueError("not a PE")
    elif body == b"mal":
        return 1
    return 0


def wait_live(pool: WorkerPool, n: int, seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pool.stats()["live"] >= n and pool._idle.qsize() >= n:
            return True
        time.sleep(0.05)
    return False


class ProcessPoolTest(unittest.TestCase):
    def setUp(self):
        self.pool = WorkerPool(scorer, n_workers=1, mode="process", warmup=b"warm")

    def tearDown(self):
        self.pool.close()

    def test_scores_and_fails_toward_detection(self):
        self.assertEqual(self.pool.classify(b"benign", time.monotonic() + 2)[0], 0)
        self.assertEqual(self.pool.classify(b"mal", time.monotonic() + 2), (1, "scored"))
        result, reason = self.pool.classify(b"boom", time.monotonic() + 2)
        self.assertEqual(result, 1)
        self.assertTrue(reason.startswith("unparseable"))

    def test_overrun_is_killed_and_answered_on_time(self):
        t = time.monotonic()
        self.assertEqual(self.pool.classify(b"slow", t + 0.5), (1, "overrun"))
        self.assertLess(time.monotonic() - t, 1.5)
        self.assertEqual(self.pool.stats()["killed_overrun"], 1)
        self.assertTrue(wait_live(self.pool, 1), "replacement worker did not come up")
        self.assertEqual(self.pool.classify(b"benign", time.monotonic() + 2), (0, "scored"))

    def test_native_call_holding_the_gil_cannot_push_past_the_deadline(self):
        t = time.monotonic()
        self.assertEqual(self.pool.classify(b"native-slow", t + 0.5), (1, "overrun"))
        self.assertLess(time.monotonic() - t, 1.5)
        self.assertTrue(wait_live(self.pool, 1))
        self.assertEqual(self.pool.classify(b"benign", time.monotonic() + 2)[0], 0)

    def test_dead_worker_is_detected_and_replaced(self):
        result, reason = self.pool.classify(b"crash", time.monotonic() + 2)
        self.assertEqual((result, reason), (1, "worker_failed"))
        self.assertTrue(wait_live(self.pool, 1))
        self.assertEqual(self.pool.classify(b"benign", time.monotonic() + 2), (0, "scored"))

    def test_admission_is_bounded_by_the_deadline(self):
        # one worker, busy for 5 s: a second request must not queue past its own deadline
        busy = threading.Thread(target=self.pool.classify, args=(b"slow", time.monotonic() + 3))
        busy.start()
        time.sleep(0.2)
        t = time.monotonic()
        self.assertEqual(self.pool.classify(b"benign", t + 0.3), (1, "saturated"))
        self.assertLess(time.monotonic() - t, 1.0)
        busy.join()
        self.assertTrue(wait_live(self.pool, 1))

    def test_no_input_buffer_outlives_its_request(self):
        # twelve timed-out requests leave nothing queued (finding 2: ten stayed queued before)
        for _ in range(3):
            self.pool.classify(b"slow", time.monotonic() + 0.2)
            self.assertTrue(wait_live(self.pool, 1))
        self.assertEqual(self.pool._idle.qsize(), 1)
        self.assertEqual(self.pool.stats()["live"], 1)


class ThreadPoolFallbackTest(unittest.TestCase):
    def test_thread_mode_still_answers_on_time_but_cannot_kill(self):
        pool = WorkerPool(scorer, n_workers=1, mode="thread", warmup=None)
        try:
            t = time.monotonic()
            self.assertEqual(pool.classify(b"slow", t + 0.3), (1, "overrun"))
            self.assertLess(time.monotonic() - t, 1.0)
            # the slot is still held by the runaway thread: the next request is 'saturated'
            self.assertEqual(pool.classify(b"benign", time.monotonic() + 0.2), (1, "saturated"))
        finally:
            pool.close()


if __name__ == "__main__":
    unittest.main()
