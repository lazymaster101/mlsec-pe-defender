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

The scan is linear and cheap: bytes.find for the common spellings of "powershell"
(ASCII and UTF-16LE, no copy of the body), then the two option checks inside a
+/-512-byte window around each hit.
Nothing is decoded, parsed or executed.
"""
from __future__ import annotations
import re

_SEP = r"[\"',\s]{1,6}"
_BYPASS = re.compile(r"-e(?:xecutionpolicy|xec|p|x)?" + _SEP + r"bypass", re.IGNORECASE)
_HIDDEN = re.compile(r"-w(?:indowstyle)?" + _SEP + r"(?:hidden|1\b)", re.IGNORECASE)
# Case variants searched WITHOUT a lowercase copy of the body (a 64 MB copy was a
# measurable share of the per-request memory transient). The leading p/P is left out of
# the needle so both cases match; mixed-case spellings beyond these are obfuscation and
# outside this signature's scope.
_NEEDLES = tuple((n, "latin-1") for n in (b"owershell", b"owerShell", b"OWERSHELL")) + \
           tuple((n.encode("utf-16le"), "utf-16le") for n in ("owershell", "owerShell", "OWERSHELL"))
_WINDOW = 512
_MAX_HITS = 200


def _windows(bytez: bytes):
    """Yield the decoded +/-512-byte window around every 'powershell' occurrence.

    bytes.lower() + bytes.find are memchr-speed (a 65 MB file costs ~60 ms); a
    case-insensitive regex over the whole buffer cost 2.5 s, which is a real share of
    the 4 s request budget on the largest benign installers.
    """
    n = 0
    for needle, enc in _NEEDLES:
        pos = bytez.find(needle)
        while pos != -1:
            lo, hi = max(0, pos - _WINDOW), min(len(bytez), pos + len(needle) + _WINDOW)
            yield bytez[lo:hi].decode(enc, "ignore")
            n += 1
            if n >= _MAX_HITS:
                return
            pos = bytez.find(needle, pos + len(needle))


def embedded_powershell_bypass(bytez: bytes) -> str | None:
    """-> a short description of the first matching window, or None."""
    for text in _windows(bytez):
        if _BYPASS.search(text) and _HIDDEN.search(text):
            i = text.lower().find("powershell")
            return "powershell_bypass_hidden:" + re.sub(r"\s+", " ", text[max(0, i - 20):i + 100]).strip()
    return None
