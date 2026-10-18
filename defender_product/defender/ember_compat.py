#!/usr/bin/env python3
"""Compatibility shim so the EMBER feature extractor runs on modern lief (0.17) and
numpy (2.x). Import this module BEFORE using ember.PEFeatureExtractor.feature_vector.

EMBER's extractors are ~95% version-robust (they stringify enums), so only four spots
need patching:
  1. PEFeatureExtractor.raw_features  — lief.bad_format/etc. exception names are gone
  2. ByteEntropyHistogram.raw_features — np.int removed in numpy 2
  3. SectionInfo.raw_features          — lief.not_found + SECTION_CHARACTERISTICS enum
  4. SectionInfo.process_raw_features  — sklearn>=1 rejects a bare single string sample

Value-level skew vs EMBER's original lief 0.9 is minimal: names/sizes/imports are file
facts; only section entropy is recomputed (same Shannon formula). Validated end-to-end.
"""
from __future__ import annotations
import hashlib
import numpy as np
import lief
from sklearn.feature_extraction import FeatureHasher
from defender import ember_features as _f


def _pe_raw_features(self, bytez):
    try:
        # bytes, not list(bytez): identical features (verified 220/220), but avoids a
        # per-byte Python list (hundreds of MB transient on large files under 1 GiB).
        lb = lief.PE.parse(bytes(bytez))
    except Exception:
        lb = None
    features = {"sha256": hashlib.sha256(bytez).hexdigest()}
    features.update({fe.name: fe.raw_features(bytez, lb) for fe in self.features})
    return features


def _byteentropy_raw(self, bytez, lief_binary):
    output = np.zeros((16, 16), dtype=np.int64)          # was np.int
    a = np.frombuffer(bytez, dtype=np.uint8)
    if a.shape[0] < self.window:
        Hbin, c = self._entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
        for block in blocks:
            Hbin, c = self._entropy_bin_counts(block)
            output[Hbin, :] += c
    return output.flatten().tolist()


def _props(s):
    return [str(c).split('.')[-1] for c in s.characteristics_lists]


def _section_raw(self, bytez, lb):
    if lb is None:
        return {"entry": "", "sections": []}
    try:
        section = lb.section_from_rva(lb.entrypoint - lb.imagebase)
        entry_section = section.name if section is not None else ""
    except Exception:
        entry_section = ""
    if not entry_section:
        for s in lb.sections:
            if 'MEM_EXECUTE' in _props(s):
                entry_section = s.name
                break
    return {"entry": entry_section,
            "sections": [{'name': s.name, 'size': s.size, 'entropy': s.entropy,
                          'vsize': s.virtual_size, 'props': _props(s)} for s in lb.sections]}


def _section_process(self, raw_obj):
    sections = raw_obj['sections']
    general = [
        len(sections),
        sum(1 for s in sections if s['size'] == 0),
        sum(1 for s in sections if s['name'] == ""),
        sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),
        sum(1 for s in sections if 'MEM_WRITE' in s['props']),
    ]
    def pair(key):
        return FeatureHasher(50, input_type="pair").transform(
            [[(s['name'], s[key]) for s in sections]]).toarray()[0]
    entry_name_hashed = FeatureHasher(50, input_type="string").transform(
        [[raw_obj['entry']]]).toarray()[0]               # fix: wrap the single string
    characteristics = [p for s in sections for p in s['props'] if s['name'] == raw_obj['entry']]
    characteristics_hashed = FeatureHasher(50, input_type="string").transform(
        [characteristics]).toarray()[0]
    return np.hstack([general, pair('size'), pair('entropy'), pair('vsize'),
                      entry_name_hashed, characteristics_hashed]).astype(np.float32)


def apply():
    _f.PEFeatureExtractor.raw_features = _pe_raw_features
    _f.ByteEntropyHistogram.raw_features = _byteentropy_raw
    _f.SectionInfo.raw_features = _section_raw
    _f.SectionInfo.process_raw_features = _section_process


apply()
