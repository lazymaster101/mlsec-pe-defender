#!/usr/bin/env python3
"""Enrich sample hashes with VirusTotal metadata, within free-tier limits.

The public API allows lookups but NOT file downloads (``/files/{id}/download``
returns 403), so this reads labels rather than collecting samples. What it gives
the dataset is exactly what the threat model asks for in section 6:

* ``last_analysis_stats``  -> AV-consensus labels with an explicit discard band
* ``first_submission_date`` -> the temporal-split axis
* ``popular_threat_classification`` -> family/type slices

Quota is enforced client-side (default 4 requests/minute, 500/day) and progress is
checkpointed, so an interrupted run resumes without spending quota twice.

    export VT_API_KEY=...            # never pass the key on the command line
    python vt_enrich.py hashes.txt --out enriched.jsonl --limit 400
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3/files/"


def _ssl_context() -> ssl.SSLContext:
    """The macOS framework Python ships no CA bundle; fall back to certifi."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL = _ssl_context()
# Public-tier ceilings; the client stays under them rather than relying on 429s.
DEFAULT_PER_MINUTE = 4
DEFAULT_DAILY = 500


class QuotaExhausted(RuntimeError):
    pass


class VirusTotal:
    def __init__(self, key: str, per_minute: int = DEFAULT_PER_MINUTE) -> None:
        self._key = key
        self._interval = 60.0 / max(per_minute, 1)
        self._last = 0.0

    def lookup(self, sha256: str) -> dict | None:
        wait = self._interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        request = urllib.request.Request(API + sha256, headers={"x-apikey": self._key})
        try:
            with urllib.request.urlopen(request, timeout=60, context=_SSL) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None                      # not in VT's corpus
            if error.code == 429:
                raise QuotaExhausted("VirusTotal rate limit or quota reached")
            if error.code == 401:
                raise SystemExit("VirusTotal rejected the key (401)")
            raise
        finally:
            self._last = time.monotonic()
        return payload.get("data", {}).get("attributes", {})


def summarise(sha256: str, attributes: dict | None) -> dict:
    if attributes is None:
        return {"sha256": sha256, "found": False}
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    classification = attributes.get("popular_threat_classification", {}) or {}
    names = classification.get("popular_threat_name", []) or []
    categories = classification.get("popular_threat_category", []) or []
    return {
        "sha256": sha256,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "detection_ratio": (malicious / total) if total else None,
        "first_submission_date": attributes.get("first_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "type_tag": attributes.get("type_tag"),
        "size": attributes.get("size"),
        "suggested_threat_label": classification.get("suggested_threat_label"),
        "threat_names": [n.get("value") for n in names[:3]],
        "threat_categories": [c.get("value") for c in categories[:3]],
        "tags": (attributes.get("tags") or [])[:10],
        "signed": bool((attributes.get("signature_info") or {}).get("verified")),
    }


def load_done(path: pathlib.Path) -> set[str]:
    if not path.exists():
        return set()
    done = set()
    with path.open() as stream:
        for line in stream:
            try:
                done.add(json.loads(line)["sha256"])
            except (ValueError, KeyError):
                continue
    return done


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("hashes", type=pathlib.Path, help="file of sha256 hashes, one per line")
    parser.add_argument("--out", type=pathlib.Path, required=True, help="JSONL output (appended)")
    parser.add_argument("--limit", type=int, default=DEFAULT_DAILY, help="max lookups this run")
    parser.add_argument("--per-minute", type=int, default=DEFAULT_PER_MINUTE)
    args = parser.parse_args()

    key = os.environ.get("VT_API_KEY")
    if not key:
        raise SystemExit("Set VT_API_KEY in the environment (not on the command line)")

    wanted = [h.strip().lower() for h in args.hashes.read_text().split() if len(h.strip()) == 64]
    done = load_done(args.out)
    todo = [h for h in wanted if h not in done][:args.limit]
    print(f"{len(wanted)} hashes, {len(done)} already enriched, {len(todo)} this run",
          file=sys.stderr)
    if not todo:
        return

    client = VirusTotal(key, args.per_minute)
    found = 0
    with args.out.open("a") as stream:
        for index, sha256 in enumerate(todo, 1):
            try:
                record = summarise(sha256, client.lookup(sha256))
            except QuotaExhausted as error:
                print(f"stopping: {error}", file=sys.stderr)
                break
            found += record["found"]
            stream.write(json.dumps(record) + "\n")
            stream.flush()
            if index % 10 == 0 or index == len(todo):
                print(f"  {index}/{len(todo)} looked up, {found} found in VT", file=sys.stderr)
    print(f"done: {found} records written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
