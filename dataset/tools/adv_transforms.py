#!/usr/bin/env python3
"""Functionality-preserving adversarial transforms on NFS attribute dicts.

Single source of truth shared by adversarial *training* (train_nfs_adversarial.py)
and adversarial *evaluation* (evaluate_adversarial.py), so the model is never
trained and tested on subtly different attacks.

Everything here edits an already-extracted attribute dict the way a
functionality-preserving PE rewrite would edit the corresponding fields. No PE bytes
are produced, decrypted, or executed.

Attacks and how they are used:
  A additive-imports  — append a benign file's imports (unused/dead). REALIZABLE. In training.
  B header-metadata   — rewrite mutable header fields to a benign file's. REALIZABLE. In training.
  C combined          — A + B. REALIZABLE. In training.
  E packer-shrink     — shrink the visible import table to an unpacker-stub set, as a
                        packed binary would. REALIZABLE. In training (part of mode 'all').
  F section-inject    — add benign sections (structural). REALIZABLE, and deliberately
                        HELD OUT of training, so a detection gain on F is genuine
                        generalization to an attack MECHANISM the model never saw.
  D full-mimicry      — copy EVERY model-input feature (all numeric + categorical +
                        textual) from a benign donor. Feature-space UPPER BOUND; may
                        NOT be problem-space realizable (Pierazzi et al.). Never trained.

Training mode 'all' draws from {A,B,C,E} (all realizable append/rewrite/shrink attacks).
D and F are evaluation-only: D bounds the worst case, F tests held-out-mechanism transfer.
"""
from __future__ import annotations
import random

# The model's full input feature set (must match schema.json for a true upper bound).
NUMERIC_ALL = [
    "virtual_size", "has_debug", "imports", "exports", "has_relocations",
    "has_resources", "has_signature", "has_tls", "symbols", "timestamp",
    "numberof_sections", "major_image_version", "minor_image_version",
    "major_linker_version", "minor_linker_version", "major_operating_system_version",
    "minor_operating_system_version", "major_subsystem_version",
    "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
]
CATEGORICAL = ["machine", "magic"]
TEXT_FIELDS = ["libraries", "functions", "exports_list",
               "dll_characteristics_list", "characteristics_list"]
# Header fields an attacker can rewrite without changing execution.
MUTABLE_NUMERIC = ["timestamp", "major_linker_version", "minor_linker_version",
                   "major_image_version", "minor_image_version",
                   "major_operating_system_version", "minor_operating_system_version",
                   "major_subsystem_version", "minor_subsystem_version",
                   "sizeof_heap_commit"]


def toks(s) -> list[str]:
    return [t for t in str(s).split(" ") if t]


def _pad(tokens: list[str]) -> str:
    """Re-emit tokens with the surrounding-space padding the NFS tokenizer needs."""
    return " " + " ".join(tokens) + " " if tokens else " "


def attack_A(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Additive dead-import mimicry: keep real imports, append a benign file's."""
    a = dict(mal)
    add_fn = toks(donor.get("functions", ""))    # benign DLL names
    add_lib = toks(donor.get("libraries", ""))    # benign API names
    a["functions"] = _pad(toks(mal.get("functions", "")) + add_fn)
    a["libraries"] = _pad(toks(mal.get("libraries", "")) + add_lib)
    a["imports"] = int(mal.get("imports", 0)) + len(add_lib)
    return a


def attack_B(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Rewrite freely-mutable header metadata to a benign donor's values."""
    a = dict(mal)
    for k in MUTABLE_NUMERIC:
        if k in donor:
            a[k] = donor[k]
    return a


def attack_C(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Combined append-imports + header-rewrite (cheap, realistic, strongest of A/B/C)."""
    return attack_B(attack_A(mal, donor, rng), donor, rng)


def attack_E(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Packer-mimicry: shrink the visible import table to a small benign-stub set, as a
    packed binary would (real imports hidden in the packed payload, resolved at runtime).
    Realizable; a distinct mechanism from A/B/C. Included in 'all' training."""
    a = dict(mal)
    stub_fn = toks(donor.get("functions", ""))[:3] or ["KERNEL32.dll"]
    stub_lib = toks(donor.get("libraries", ""))[:8] or ["LoadLibraryA", "GetProcAddress"]
    a["functions"] = _pad(stub_fn)
    a["libraries"] = _pad(stub_lib)
    a["imports"] = len(stub_lib)
    a["has_resources"] = 1              # packers typically carry a resource blob
    return a


def attack_F(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Section-injection: add benign sections/resources (structural). Adding unused
    sections is functionality-preserving. HELD OUT of training on purpose — a detection
    gain here is generalization to an attack mechanism the model never trained on."""
    a = dict(mal)
    a["numberof_sections"] = int(mal.get("numberof_sections", 1)) + rng.choice([2, 3, 4])
    a["has_resources"] = 1
    a["has_relocations"] = 1
    a["sizeof_headers"] = max(int(mal.get("sizeof_headers", 1024)),
                              int(donor.get("sizeof_headers", 1024) or 1024))
    a["virtual_size"] = int(mal.get("virtual_size", 0)) + int(donor.get("sizeof_code", 0) or 0)
    return a


def attack_D(mal: dict, donor: dict, rng: random.Random) -> dict:
    """Feature-space UPPER BOUND: copy EVERY model-input feature from a benign donor
    (all numeric + categorical + textual). The sample keeps only its malicious label;
    every value the model can see is a benign file's. Bounds attacker power in feature
    space (not necessarily problem-space realizable). Never trained on."""
    a = dict(mal)
    for k in NUMERIC_ALL + CATEGORICAL + TEXT_FIELDS:
        if k in donor:
            a[k] = donor[k]
    return a


TRANSFORMS = {"A": attack_A, "B": attack_B, "C": attack_C,
              "E": attack_E, "F": attack_F, "D": attack_D}


def make_adversarial(mal: dict, donor: dict, mode: str, rng: random.Random) -> dict:
    """Apply transform ``mode``.

    'A'|'B'|'C'|'D'|'E'|'F' — a specific transform.
    'mix' — random A/B/C (append/rewrite family), combined attack weighted.
    'all' — random A/B/C/E: every realizable append/rewrite/shrink attack. D (upper
            bound) and F (held-out structural mechanism) are eval-only and NOT trained."""
    if mode == "mix":
        mode = rng.choice(["A", "B", "C", "C"])
    elif mode == "all":
        mode = rng.choice(["A", "B", "C", "C", "E"])
    return TRANSFORMS[mode](mal, donor, rng)
