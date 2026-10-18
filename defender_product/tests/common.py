"""Shared locations and fixture loading for the defender test suite."""
from __future__ import annotations

import json
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
MODEL_DIR = pathlib.Path(os.environ.get("DF_TEST_MODEL_DIR", ROOT / "models" / "nfs"))
SAMPLE_DIR = pathlib.Path(os.environ.get(
    "DF_TEST_SAMPLE_DIR",
    ROOT.parent / "ml-cybersecuritiy-course" / "datasets" / "samples" / "pe"))


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def model_available() -> bool:
    return (MODEL_DIR / "schema.json").is_file()
