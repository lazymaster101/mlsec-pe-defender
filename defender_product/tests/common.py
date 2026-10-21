"""Shared locations and fixture loading for the defender test suite."""
from __future__ import annotations

import json
import os
import pathlib

# Workers are forked from the test process: keep BLAS/OpenMP single-threaded so no
# thread pool exists before the fork (same settings as the Dockerfiles).
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
# The supplied model: golden vectors in tests/fixtures were generated for it.
MODEL_DIR = pathlib.Path(os.environ.get("DF_TEST_MODEL_DIR", ROOT / "models" / "nfs"))
# The deployed single-model configuration (Dockerfile): rf_adv at its calibrated threshold.
DEPLOYED_MODEL_DIR = pathlib.Path(os.environ.get("DF_TEST_DEPLOYED_MODEL_DIR", ROOT / "models" / "rf_adv"))
DEPLOYED_THRESHOLD = float(os.environ.get("DF_TEST_DEPLOYED_THRESHOLD", "0.820932"))
SAMPLE_DIR = pathlib.Path(os.environ.get(
    "DF_TEST_SAMPLE_DIR",
    ROOT.parent / "ml-cybersecuritiy-course" / "datasets" / "samples" / "pe"))


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def model_available(directory: pathlib.Path = MODEL_DIR) -> bool:
    return (directory / "schema.json").is_file()
