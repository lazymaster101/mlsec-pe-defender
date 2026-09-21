#!/usr/bin/env python3
"""Convert the supplied NFS forest into version-independent, mmap-ready arrays.

The legacy object graph is read only after a static opcode/global audit and through
an allowlisted unpickler. sklearn/model classes are replaced by inert state holders:
no legacy estimator constructor, __setstate__, or prediction code runs. NumPy array
reconstruction is the only callable deserialization capability. Never use this
utility as a general-purpose loader for arbitrary uploaded pickle files.

Only the exporter needs the original gzip/pickle file; the HTTP runtime needs the
resulting JSON and .npy files. Conversion can exceed 1 GB RAM; inference does not
load the legacy object graph. A source SHA-256 pins the audited supplied artifact.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import pickle
import pickletools
import sys
from typing import Any

import numpy as np

EXPECTED_SOURCE_SHA256 = "bd38cc6367a9b2f54c669e76feb38967b1101fece9d00ab8d9ba9d3fc80c5477"
NUMERICAL_ATTRIBUTES = [
    "virtual_size", "has_debug", "imports", "exports", "has_relocations",
    "has_resources", "has_signature", "has_tls", "symbols", "timestamp",
    "numberof_sections", "major_image_version", "minor_image_version",
    "major_linker_version", "minor_linker_version", "major_operating_system_version",
    "minor_operating_system_version", "major_subsystem_version",
    "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit",
]
CATEGORICAL_ATTRIBUTES = ["machine", "magic"]
TEXTUAL_ATTRIBUTES = [
    "libraries", "functions", "exports_list", "dll_characteristics_list",
    "characteristics_list",
]
INERT_GLOBALS = {
    ("__main__", "NeedForSpeedModel"),
    ("sklearn.preprocessing._encoders", "OneHotEncoder"),
    ("sklearn.feature_extraction.text", "HashingVectorizer"),
    ("sklearn.preprocessing._data", "MaxAbsScaler"),
    ("sklearn.ensemble._forest", "RandomForestClassifier"),
    ("sklearn.tree._classes", "DecisionTreeClassifier"),
    ("sklearn.tree._tree", "Tree"),
}
NUMPY_GLOBALS = {
    ("numpy", "float64"), ("numpy", "ndarray"), ("numpy", "dtype"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
}


class InertState:
    """Store serialized attributes without invoking any sklearn implementation."""

    def __new__(cls, *args: Any, **kwargs: Any) -> "InertState":
        obj = super().__new__(cls)
        obj._constructor_args = args
        return obj

    def __setstate__(self, state: Any) -> None:
        if not isinstance(state, dict):
            raise pickle.UnpicklingError("Expected an attribute dictionary")
        self.__dict__.update(state)


class RestrictedLegacyUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> Any:
        key = module, name
        if key in INERT_GLOBALS:
            return InertState
        if key not in NUMPY_GLOBALS:
            raise pickle.UnpicklingError(f"Forbidden global: {module}.{name}")
        if module == "numpy":
            return getattr(np, name)
        # Supports NumPy 1.x and 2.x while keeping the imported capability explicit.
        core = np._core if hasattr(np, "_core") else np.core
        return getattr(core.multiarray, name)

    def persistent_load(self, pid: Any) -> Any:
        raise pickle.UnpicklingError("Persistent references are not supported")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit_source(path: Path, expected_sha256: str) -> dict[str, Any]:
    actual = sha256(path)
    if actual != expected_sha256:
        raise ValueError(f"Source SHA-256 mismatch: expected {expected_sha256}, got {actual}")
    globals_seen: set[tuple[str, str]] = set()
    opcode_counts: dict[str, int] = {}
    forbidden_opcodes = {"EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID", "STACK_GLOBAL", "INST", "OBJ"}
    with gzip.open(path, "rb") as stream:
        for opcode, value, position in pickletools.genops(stream):
            opcode_counts[opcode.name] = opcode_counts.get(opcode.name, 0) + 1
            if opcode.name in forbidden_opcodes:
                raise ValueError(f"Unsupported pickle opcode {opcode.name} at {position}")
            if opcode.name == "GLOBAL":
                key = tuple(value.split(" ", 1))
                if key not in INERT_GLOBALS | NUMPY_GLOBALS:
                    raise ValueError(f"Unexpected serialized global {key}")
                globals_seen.add(key)
        if stream.read(1):
            raise ValueError("Unexpected trailing bytes after pickle STOP")
    return {
        "sha256": actual,
        "bytes": path.stat().st_size,
        "compression": "gzip",
        "globals": [".".join(key) for key in sorted(globals_seen)],
        "opcode_counts": opcode_counts,
    }


def load_legacy(path: Path, expected_sha256: str = EXPECTED_SOURCE_SHA256) -> tuple[InertState, dict[str, Any]]:
    audit = audit_source(path, expected_sha256)
    with gzip.open(path, "rb") as stream:
        model = RestrictedLegacyUnpickler(stream).load()
    if not isinstance(model, InertState):
        raise ValueError("Unexpected root object")
    return model, audit


def json_hashing_config(vectorizer: InertState) -> dict[str, Any]:
    fields = [
        "input", "encoding", "decode_error", "strip_accents", "preprocessor",
        "tokenizer", "analyzer", "lowercase", "token_pattern", "stop_words",
        "n_features", "ngram_range", "binary", "norm", "alternate_sign",
    ]
    config = {field: getattr(vectorizer, field) for field in fields}
    if any(config[name] is not None for name in ("preprocessor", "tokenizer", "strip_accents", "stop_words")):
        raise ValueError("Unexpected custom text preprocessing")
    if config["analyzer"] != "word" or tuple(config["ngram_range"]) != (1, 1):
        raise ValueError("Unexpected analyzer")
    config["dtype"] = "float64"
    return config


def legacy_probabilities(model: InertState, features: np.ndarray) -> np.ndarray:
    """Reference traversal directly over legacy state, without sklearn."""
    rows = np.asarray(features, dtype=np.float32)
    predictions = np.zeros(len(rows), dtype=np.float64)
    for estimator in model.classifier.estimators_:
        nodes, values = estimator.tree_.nodes, estimator.tree_.values
        for sample_index, row in enumerate(rows):
            node_index = 0
            while int(nodes["left_child"][node_index]) != -1:
                feature = int(nodes["feature"][node_index])
                side = "left_child" if float(row[feature]) <= float(nodes["threshold"][node_index]) else "right_child"
                node_index = int(nodes[side][node_index])
            counts = values[node_index, 0]
            predictions[sample_index] += float(counts[1] / counts.sum())
    return predictions / len(model.classifier.estimators_)


def exported_probabilities(destination: Path, features: np.ndarray) -> np.ndarray:
    """Independent flat-array traversal used only for conversion verification."""
    arrays = {name: np.load(destination / f"{name}.npy", mmap_mode="r", allow_pickle=False)
              for name in ("children_left", "children_right", "features", "thresholds", "probabilities", "tree_roots")}
    rows = np.asarray(features, dtype=np.float32)
    predictions = np.zeros(len(rows), dtype=np.float64)
    for row_index, row in enumerate(rows):
        total = 0.0
        for root in arrays["tree_roots"]:
            node = int(root)
            while arrays["children_left"][node] != -1:
                feature = int(arrays["features"][node])
                branch = "children_left" if float(row[feature]) <= float(arrays["thresholds"][node]) else "children_right"
                node = int(arrays[branch][node])
            total += float(arrays["probabilities"][node])
        predictions[row_index] = total / len(arrays["tree_roots"])
    return predictions


def export_model(source: Path, destination: Path, expected_sha256: str = EXPECTED_SOURCE_SHA256,
                 verification_samples: int = 16) -> dict[str, Any]:
    model, audit = load_legacy(source, expected_sha256)
    classifier = model.classifier
    if np.asarray(classifier.classes_).tolist() != [0, 1] or classifier.n_outputs_ != 1:
        raise ValueError("Expected a binary classifier with labels [0, 1]")
    trees = classifier.estimators_
    if not trees or len(trees) != classifier.n_estimators:
        raise ValueError("Invalid number of estimators")
    categories = [[str(value) for value in values] for values in model.categorical_extractor.categories_]
    if model.categorical_extractor.handle_unknown != "ignore" or model.categorical_extractor.drop is not None:
        raise ValueError("Unexpected categorical encoding")
    text_configs = {name: json_hashing_config(model.textual_extractors[name]) for name in TEXTUAL_ATTRIBUTES}
    n_features = len(NUMERICAL_ATTRIBUTES) + sum(map(len, categories)) + sum(c["n_features"] for c in text_configs.values())
    if n_features != classifier.n_features_in_:
        raise ValueError("Preprocessing and forest feature counts disagree")
    scale = np.asarray(model.feature_scaler.scale_, dtype=np.float64)
    if scale.shape != (n_features,) or not np.isfinite(scale).all() or not (scale > 0).all():
        raise ValueError("Invalid scaling factors")
    counts = [int(estimator.tree_.node_count) for estimator in trees]
    total_nodes = sum(counts)
    if total_nodes >= np.iinfo(np.int32).max:
        raise ValueError("Forest too large for compact int32 node indices")
    destination.mkdir(parents=True, exist_ok=True)
    arrays = {}
    for name, dtype in (
        ("children_left", "<i4"), ("children_right", "<i4"), ("features", "<i4"),
        ("thresholds", "<f8"), ("probabilities", "<f8"),
    ):
        arrays[name] = np.lib.format.open_memmap(destination / f"{name}.npy", mode="w+", dtype=dtype, shape=(total_nodes,))
    roots = []
    offset = 0
    leaf_count = 0
    for tree_index, estimator in enumerate(trees):
        tree = estimator.tree_
        nodes, values = tree.nodes, tree.values
        count = counts[tree_index]
        if nodes.shape != (count,) or values.shape != (count, 1, 2):
            raise ValueError(f"Invalid tree shape at {tree_index}")
        left, right = nodes["left_child"], nodes["right_child"]
        leaves = left == -1
        if not np.array_equal(leaves, right == -1):
            raise ValueError("Inconsistent leaf markers")
        for children in (left[~leaves], right[~leaves]):
            if np.any(children <= np.flatnonzero(~leaves)) or np.any(children >= count):
                raise ValueError("Invalid, cyclic, or non-preorder child indices")
        feature = nodes["feature"]
        if np.any(feature[~leaves] < 0) or np.any(feature[~leaves] >= n_features):
            raise ValueError("Invalid split feature")
        if not np.isfinite(nodes["threshold"]).all() or not np.isfinite(values).all() or (values < 0).any():
            raise ValueError("Invalid tree numeric values")
        sums = values[:, 0, :].sum(axis=1)
        if np.any(sums <= 0):
            raise ValueError("Tree node has no class weight")
        chunk = slice(offset, offset + count)
        arrays["children_left"][chunk] = np.where(leaves, -1, left + offset)
        arrays["children_right"][chunk] = np.where(leaves, -1, right + offset)
        arrays["features"][chunk] = feature
        arrays["thresholds"][chunk] = nodes["threshold"]
        arrays["probabilities"][chunk] = values[:, 0, 1] / sums
        roots.append(offset)
        offset += count
        leaf_count += int(leaves.sum())
    for array in arrays.values():
        array.flush()
    arrays.clear()
    np.save(destination / "tree_roots.npy", np.asarray(roots, dtype="<i4"), allow_pickle=False)
    np.save(destination / "scales.npy", scale.astype("<f8", copy=False), allow_pickle=False)
    schema = {
        "format_version": 1,
        "model_name": "NFS_21_ALL_hash_50000_WITH_MLSEC20",
        "original_sklearn_version": classifier._sklearn_version,
        "classes": [0, 1],
        "malicious_class_index": 1,
        "n_features": n_features,
        "n_trees": len(trees),
        "n_nodes": total_nodes,
        "n_leaves": leaf_count,
        "tree_node_counts": counts,
        "tree_max_depths": [int(estimator.tree_.max_depth) for estimator in trees],
        "training_samples_seen": int(model.feature_scaler.n_samples_seen_),
        "numerical_attributes": NUMERICAL_ATTRIBUTES,
        "categorical_attributes": CATEGORICAL_ATTRIBUTES,
        "categorical_categories": categories,
        "categorical_handle_unknown": "ignore",
        "textual_attributes": TEXTUAL_ATTRIBUTES,
        "hashing": text_configs,
        "scaling": "MaxAbsScaler: multiply float64 features by reciprocal of scales.npy, then cast to float32",
        "input_dtype": "float32",
        "threshold_dtype": "float64",
        "child_indices": "Global indices in flat arrays; -1 denotes a leaf",
        "probabilities": "float64 probability of class 1 at each node; average reached leaves over all trees",
        "legacy_decision": {"rule": "benign_probability < benign_threshold", "benign_threshold": 0.75},
        "equivalent_malware_decision": {"rule": "malware_probability > malware_threshold", "malware_threshold": 0.25},
        "source_sha256": audit["sha256"],
    }
    (destination / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    rng = np.random.default_rng(20210919)
    rows = np.zeros((verification_samples, n_features), dtype=np.float32)
    if verification_samples > 1:
        for row in rows[1:]:
            selected = rng.choice(n_features, size=min(1024, n_features), replace=False)
            row[selected] = rng.uniform(-1, 1, len(selected)).astype(np.float32)
            row[:len(NUMERICAL_ATTRIBUTES)] = rng.uniform(0, 1, len(NUMERICAL_ATTRIBUTES))
    old = legacy_probabilities(model, rows)
    new = exported_probabilities(destination, rows)
    error = float(np.max(np.abs(old - new))) if len(rows) else 0.0
    if not np.array_equal(old, new):
        raise ValueError(f"Converted forest probabilities differ: max error {error}")
    files = {}
    for path in sorted(destination.glob("*.npy")):
        array = np.load(path, mmap_mode="r", allow_pickle=False)
        files[path.name] = {"sha256": sha256(path), "bytes": path.stat().st_size,
                            "dtype": str(array.dtype), "shape": list(array.shape)}
    schema_path = destination / "schema.json"
    files[schema_path.name] = {"sha256": sha256(schema_path), "bytes": schema_path.stat().st_size}
    manifest = {
        "format_version": 1,
        "source": {"filename": source.name, **audit},
        "files": files,
        "total_artifact_bytes": sum(info["bytes"] for info in files.values()),
        "conversion_verification": {
            "method": "Legacy inert-state versus exported-array traversal on deterministic float32 vectors",
            "samples": verification_samples,
            "all_tree_paths_preserved": True,
            "exact_probability_match": True,
            "maximum_absolute_error": error,
            "limitation": "Checks representation compatibility, not detection accuracy or feature extraction parity",
        },
        "performance_claims": {"fpr_validated": False, "tpr_validated": False},
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expected-sha256", default=EXPECTED_SOURCE_SHA256)
    parser.add_argument("--verification-samples", type=int, default=16)
    args = parser.parse_args()
    if args.verification_samples < 1:
        parser.error("--verification-samples must be positive")
    manifest = export_model(args.source, args.destination, args.expected_sha256, args.verification_samples)
    print(json.dumps({"destination": str(args.destination.resolve()),
                      "artifact_bytes": manifest["total_artifact_bytes"],
                      "verification": manifest["conversion_verification"]}, indent=2))


if __name__ == "__main__":
    main()
