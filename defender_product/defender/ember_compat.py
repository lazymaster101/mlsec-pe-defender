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


_UNSET = object()


def _pe_raw_features(self, bytez, lief_binary=_UNSET):
    """lief_binary: a binary already parsed by the caller (None = parse failed), so the
    server parses each file once instead of three times. Default: parse here."""
    if lief_binary is not _UNSET:
        lb = lief_binary
    else:
        try:
            # bytes, not list(bytez): identical features (verified 220/220), but avoids a
            # per-byte Python list (hundreds of MB transient on large files under 1 GiB).
            lb = lief.PE.parse(bytes(bytez))
        except Exception:
            lb = None
    features = {"sha256": hashlib.sha256(bytez).hexdigest()}
    features.update({fe.name: fe.raw_features(bytez, lb) for fe in self.features})
    return features


_HIST_CHUNK = 4 << 20


def _bytehistogram_raw(self, bytez, lief_binary):
    """EMBER ByteHistogram.raw_features with identical output and a bounded transient.

    np.bincount casts its input to the platform integer, so the original
    bincount(frombuffer(bytez, uint8)) allocated 8 bytes per input byte (509 MiB for a
    67 MB file: the single largest share of the per-request memory; verification
    2026-10-22). Summing bincounts over 4 MiB chunks gives the same integer counts with a
    32 MiB transient."""
    view = np.frombuffer(bytez, dtype=np.uint8)
    counts = np.zeros(256, dtype=np.int64)
    for start in range(0, view.size, _HIST_CHUNK):
        counts += np.bincount(view[start:start + _HIST_CHUNK], minlength=256)
    return counts.tolist()


def _strings_raw(self, bytez, lief_binary):
    """EMBER StringExtractor.raw_features with identical output, faster and memory-lean.

    The regex (C) still finds the >=5-char printable strings; only the per-character
    Python loop over all of them is replaced by one numpy bincount, and the two
    IGNORECASE scans by bytes.count on a lowercased copy (same non-overlapping counts;
    IGNORECASE on bytes is ASCII-only, like bytes.lower()). Peak memory stays ~3x the
    file size (an earlier fully-vectorised variant allocated int64 arrays for EVERY
    printable run and was OOM-killed on 60 MB files under the 1 GiB container limit)."""
    allstrings = self._allstrings.findall(bytez)
    if allstrings:
        string_lengths = [len(s) for s in allstrings]
        avlength = sum(string_lengths) / len(string_lengths)
        joined = b''.join(allstrings)
        del allstrings
        c = np.bincount(np.frombuffer(joined, dtype=np.uint8) - np.uint8(0x20), minlength=96)
        del joined
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))
        n = len(string_lengths)
    else:
        avlength = 0
        c = np.zeros((96,), dtype=np.float32)
        H = 0
        csum = 0
        n = 0
    low = bytes(bytez).lower()
    out = {
        'numstrings': n, 'avlength': avlength, 'printabledist': c.tolist(),
        'printables': int(csum), 'entropy': float(H),
        'paths': low.count(b'c:\\'), 'urls': low.count(b'http://') + low.count(b'https://'),
        'registry': bytes(bytez).count(b'HKEY_'), 'MZ': bytes(bytez).count(b'MZ'),
    }
    del low
    return out


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
    _f.ByteHistogram.raw_features = _bytehistogram_raw
    _f.ByteEntropyHistogram.raw_features = _byteentropy_raw
    _f.StringExtractor.raw_features = _strings_raw
    _f.SectionInfo.raw_features = _section_raw
    _f.SectionInfo.process_raw_features = _section_process


apply()
