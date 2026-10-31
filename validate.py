#!/usr/bin/env python3
"""Validate feed.json against schema.json plus feed-specific invariants.

Run locally or in CI:

    python3 validate.py

Exits non-zero (and prints what is wrong) if the feed is invalid, so it is
safe to use as a required PR check. Checks: JSON Schema, JA4 format on every
entry, required provenance, browser==allow / non-browser consistency, and that
no JA4 is both allow (browser) and non-browser (a measured client colliding
with the browser allowlist would be a real alarm).
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "feed.json")
SCHEMA = os.path.join(HERE, "schema.json")

JA4_RE = re.compile(r"^[tq]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")


def fail(msg: str) -> None:
    print(f"  FAIL: {msg}")


def main() -> int:
    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed: pip install jsonschema", file=sys.stderr)
        return 2

    data = json.load(open(DATA, encoding="utf-8"))
    schema = json.load(open(SCHEMA, encoding="utf-8"))
    errors = 0

    try:
        jsonschema.validate(data, schema)
        print("schema: OK")
    except jsonschema.ValidationError as e:
        fail(f"schema: {e.message} (at {'/'.join(map(str, e.path))})")
        errors += 1

    entries = data.get("entries", [])
    if not entries:
        fail("no entries in feed")
        errors += 1

    allow_ja4, nonbrowser_ja4 = set(), set()
    for i, e in enumerate(entries):
        where = f"entry[{i}] {e.get('label', '?')}"
        ja4 = e.get("ja4", "")
        if not JA4_RE.match(ja4):
            fail(f"{where}: ja4 '{ja4}' is not a JA4 fingerprint")
            errors += 1
        prov = e.get("provenance", {})
        if prov.get("method") not in ("measured", "cited"):
            fail(f"{where}: provenance.method must be measured|cited")
            errors += 1
        if not prov.get("date"):
            fail(f"{where}: missing provenance.date")
            errors += 1
        if prov.get("method") == "measured" and not prov.get("tool"):
            fail(f"{where}: measured entry missing provenance.tool")
            errors += 1
        cat, verdict = e.get("category"), e.get("verdict")
        if cat == "browser" and verdict != "allow":
            fail(f"{where}: browser entry must have verdict 'allow', got '{verdict}'")
            errors += 1
        if verdict == "allow":
            allow_ja4.add(ja4)
        if verdict == "non-browser":
            nonbrowser_ja4.add(ja4)

    conflict = allow_ja4 & nonbrowser_ja4
    if conflict:
        fail(f"JA4 marked both allow and non-browser: {', '.join(sorted(conflict))}")
        errors += 1

    if errors:
        print(f"\nINVALID: {errors} problem(s) found.")
        return 1

    m = sum(1 for e in entries if e["provenance"]["method"] == "measured")
    c = len(entries) - m
    print(f"valid: {len(entries)} entries ({m} measured, {c} cited)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
