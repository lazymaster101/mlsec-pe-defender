#!/usr/bin/env python3
"""HTTP server for the layered ensemble (defender.ensemble.Ensemble). Reuses the
hardened Handler/Server from defender.server (read deadline, bounded admission,
killable worker processes, oversize draining, fail-toward-detection) but scores with
the ensemble instead of a single model.
"""
from __future__ import annotations
import os

from defender import server as base
from defender.ensemble import Ensemble


def main(ensemble_factory=Ensemble) -> None:
    ensemble = ensemble_factory()
    # ensemble.predict is already 0/1 and fails toward detection; it runs in the forked
    # workers only (the parent never predicts: OpenMP pools must not exist before fork).
    defender = base.Defender(ensemble.predict, ensemble.info, ensemble._t, model=ensemble)
    server = base.serve(defender)
    base.log("ready", **defender.info(), host=server.server_address[0], port=server.server_address[1],
             max_body_bytes=base.MAX_BODY_BYTES, worker_mode=base.WORKER_MODE)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        defender.close()
        server.server_close()


if __name__ == "__main__":
    main()
