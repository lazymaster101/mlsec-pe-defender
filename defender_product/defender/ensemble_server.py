#!/usr/bin/env python3
"""HTTP server for the diversified ensemble (ember_gbdt OR rf_adv). Reuses the
hardened Handler/Server from defender.server (timeouts, oversize draining,
fail-toward-detection) but scores with the ensemble instead of a single model.
"""
from __future__ import annotations
import concurrent.futures
import threading
import time

from defender import server as base
from defender.ensemble import Ensemble


class EnsembleDefender(base.Defender):
    def __init__(self, ensemble: Ensemble) -> None:
        self.ensemble = ensemble
        self.model = ensemble                    # Handler /model calls model.info()
        self.threshold = "ember>tE OR rf>tR"     # not a single threshold
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=base.WORKERS, thread_name_prefix="infer")
        self._counts = {"benign": 0, "malicious": 0, "unparseable": 0, "overrun": 0}
        self._lock = threading.Lock()

    def _score(self, bytez: bytes) -> int:
        return self.ensemble.predict(bytez)      # already 0/1, fail-toward-detection


def main() -> None:
    import os
    ensemble = Ensemble()
    defender = EnsembleDefender(ensemble)
    handler = type("BoundHandler", (base.Handler,), {"defender": defender})
    host = os.environ.get("DF_HOST", "0.0.0.0")
    port = int(os.environ.get("DF_PORT", 8080))
    server = base.Server((host, port), handler)
    # warm both pipelines so the first graded sample doesn't pay import/page-fault cost
    warm = time.perf_counter()
    try:
        ensemble.predict(b"MZ" + b"\x00" * 128)
    except Exception:
        pass
    base.log("ready", **ensemble.info(),
             warmup_seconds=round(time.perf_counter() - warm, 3),
             host=host, port=port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
