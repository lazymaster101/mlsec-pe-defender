"""Embedded hidden-PowerShell command line: a deterministic tell (v3.1 layer 2b).

A PE that carries, in its own bytes, a PowerShell invocation that both bypasses the
execution policy AND hides its window is a dropper/loader pattern
(`powershell -ExecutionPolicy Bypass -WindowStyle Hidden ...`); legitimate software has
no reason to hide a policy-bypassing shell from the user. Measured on 2026-10-20 over
every goodware corpus in this repository (13,503 files: Chocolatey, NuGet, GitHub
releases, locally installed software, the course samples): 0 hits. Training malware:
4/1,455 (Rhadamanthys, AsyncRAT x2, Loki). This is a signature, not a model: it is
narrow, and trivially evaded by obfuscating the string, so it only ever ADDS detections
on top of the ML fusion and never clears a file.

The scan is linear and cheap: a case-insensitive literal search for "powershell" (ASCII
and UTF-16LE), then the two option checks inside a +/-512-byte window around each hit.
Nothing is decoded, parsed or executed.
"""
from __future__ import annotations
import re

_PWSH_ASCII = re.compile(rb"powershell", re.IGNORECASE)
_PWSH_U16 = re.compile("powershell".encode("utf-16le").replace(b"p", b"[pP]", 1), re.IGNORECASE)
_SEP = r"[\"',\s]{1,6}"
_BYPASS = re.compile(r"-e(?:xecutionpolicy|xec|p|x)?" + _SEP + r"bypass", re.IGNORECASE)
_HIDDEN = re.compile(r"-w(?:indowstyle)?" + _SEP + r"(?:hidden|1\b)", re.IGNORECASE)
_WINDOW = 512
_MAX_HITS = 200


def _windows(bytez: bytes):
    n = 0
    for pat, enc in ((_PWSH_ASCII, "latin-1"), (_PWSH_U16, "utf-16le")):
        for m in pat.finditer(bytez):
            lo, hi = max(0, m.start() - _WINDOW), min(len(bytez), m.end() + _WINDOW)
            yield bytez[lo:hi].decode(enc, "ignore")
            n += 1
            if n >= _MAX_HITS:
                return


def embedded_powershell_bypass(bytez: bytes) -> str | None:
    """-> a short description of the first matching window, or None."""
    for text in _windows(bytez):
        if _BYPASS.search(text) and _HIDDEN.search(text):
            i = text.lower().find("powershell")
            return "powershell_bypass_hidden:" + re.sub(r"\s+", " ", text[max(0, i - 20):i + 100]).strip()
    return None
