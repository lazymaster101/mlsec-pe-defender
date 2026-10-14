"""sklearn-compatible HashingVectorizer transform, without scikit-learn.

Reproduces ``HashingVectorizer(n_features=50000, token_pattern=r"(?<=\\s)(.*?)(?=\\s)")``
defaults: lowercase, word analyzer, alternate_sign, L2 norm, float64 accumulation.
Only the transform path exists; hashing vectorizers are stateless, so nothing is fitted.
"""
from __future__ import annotations

import re
from typing import Iterable

import mmh3
import numpy as np

# The trained model's token pattern. Both lookarounds require surrounding
# whitespace, so unpadded fields silently drop their first and last token --
# that behaviour is part of the learned representation and is preserved.
TOKEN_PATTERN = r"(?<=\s)(.*?)(?=\s)"
_TOKENIZER = re.compile(TOKEN_PATTERN).findall

_INT32_MIN = -(2 ** 31)


def tokenize(document: str) -> list[str]:
    """Match sklearn's ``build_analyzer()`` for these settings."""
    return _TOKENIZER(document.lower())


def _fold(hashed: int, n_features: int) -> int:
    """Mirror sklearn's ``abs(h) % n_features`` including its int32 overflow guard."""
    if hashed == _INT32_MIN:
        # abs(-2**31) is undefined in C, so sklearn substitutes this expression.
        return (2147483647 - (n_features - 1)) % n_features
    return abs(hashed) % n_features


def transform(document: str, n_features: int, out: np.ndarray, offset: int) -> None:
    """Accumulate the L2-normalised hashed bag of words into ``out[offset:]``.

    ``out`` is a float64 buffer the caller reuses across fields and samples.
    """
    tokens = tokenize(document)
    if not tokens:
        return
    block = out[offset:offset + n_features]
    # A set, not a list: colliding tokens with opposite signs can drive a bucket
    # back to exactly 0.0, and a later token landing there would otherwise record
    # the index twice and double-count its square in the norm.
    touched: set[int] = set()
    for token in tokens:
        hashed = mmh3.hash(token.encode("utf-8"), 0, signed=True)
        index = _fold(hashed, n_features)
        touched.add(index)
        # alternate_sign spreads hash collisions around zero instead of inflating.
        block[index] += 1.0 if hashed >= 0 else -1.0
    # Buckets that cancelled to zero stay in the set and contribute zero, which is
    # what sklearn's sum_duplicates + csr_row_norms also produces.
    norm = 0.0
    for index in touched:
        value = block[index]
        norm += value * value
    if norm == 0.0:
        return
    norm = np.sqrt(norm)
    for index in touched:
        block[index] /= norm


def transform_many(documents: Iterable[tuple[str, int, int]], out: np.ndarray) -> None:
    for document, n_features, offset in documents:
        transform(document, n_features, out, offset)
