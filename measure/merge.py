#!/usr/bin/env python3
"""Assemble feed.json from measured non-browser entries + cited browser allowlist.

Measured entries come from measure/measured.json (written by measure.mjs).
Browser allowlist entries are CITED from North-web-dev/fingerprint-db — pulled
from FPDB_PATH if set, else downloaded from the repo's raw URL. Browser JA4s are
referenced, not re-measured. Nothing is fabricated: entries with no valid JA4
are dropped.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import date, timezone, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MEASURED = os.path.join(HERE, "measured.json")
OUT = os.path.join(ROOT, "feed.json")

FPDB_RAW = "https://raw.githubusercontent.com/North-web-dev/fingerprint-db/main/fingerprints.json"
JA4_RE = re.compile(r"^[tq]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")

REFERENCES = {
    "note": "Malware / C2 JA4 coverage is BY REFERENCE ONLY. This feed does not "
            "redistribute third-party malware datasets; consult the sources below directly.",
    "sources": [
        {"name": "abuse.ch SSLBL", "url": "https://sslbl.abuse.ch/", "scope": "malware TLS certificates / JA3; SSL blocklist"},
        {"name": "FoxIO JA4DB", "url": "https://ja4db.com/", "scope": "community JA4+ fingerprint database (apps, malware, tooling)"},
        {"name": "FoxIO JA4 spec", "url": "https://github.com/FoxIO-LLC/ja4", "scope": "JA4+ fingerprint definitions"},
    ],
}


def load_fpdb() -> dict:
    path = os.environ.get("FPDB_PATH")
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(FPDB_RAW, headers={"User-Agent": "ja4-threat-feed-merge"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def browser_entries(fpdb: dict) -> list:
    out = []
    cite = "North-web-dev/fingerprint-db"
    cite_url = "https://github.com/North-web-dev/fingerprint-db"
    for name, b in (fpdb.get("browsers") or {}).items():
        ja4 = (b.get("tls") or {}).get("ja4", "")
        if not JA4_RE.match(ja4):
            continue
        e = {
            "ja4": ja4,
            "category": "browser",
            "label": f"{name} (curated)",
            "verdict": "allow",
            "source": cite,
            "provenance": {"method": "cited", "date": b.get("measured") or fpdb.get("metadata", {}).get("updated"), "ref": cite_url},
        }
        ak = (b.get("http2") or {}).get("akamai_fingerprint")
        if ak:
            e["akamai_h2"] = ak
        out.append(e)
    for name, eng in ((fpdb.get("live") or {}).get("engines") or {}).items():
        if name == "curl":
            continue
        ja4 = (eng.get("tls") or {}).get("ja4", "")
        if not JA4_RE.match(ja4):
            continue
        prov = eng.get("provenance") or {}
        e = {
            "ja4": ja4,
            "category": "browser",
            "label": f"{eng.get('engine', name)} (live)",
            "verdict": "allow",
            "source": cite,
            "provenance": {"method": "cited", "date": prov.get("measured") or fpdb.get("live", {}).get("updated"), "ref": cite_url},
        }
        if eng.get("ja4h"):
            e["ja4h"] = eng["ja4h"]
        ak = (eng.get("http2") or {}).get("akamai_fingerprint")
        if ak:
            e["akamai_h2"] = ak
        out.append(e)
    return out


def main() -> int:
    with open(MEASURED, encoding="utf-8") as f:
        measured = json.load(f)
    entries = list(measured.get("entries", []))
    if not entries:
        print("merge: no measured entries", file=sys.stderr)
        return 1

    try:
        fpdb = load_fpdb()
        browsers = browser_entries(fpdb)
    except Exception as e:
        print(f"merge: could not load fingerprint-db ({e}); writing measured-only feed", file=sys.stderr)
        browsers = []

    bad = [e for e in entries if not JA4_RE.match(e.get("ja4", ""))]
    if bad:
        print(f"merge: dropping {len(bad)} measured entries with invalid JA4", file=sys.stderr)
    entries = [e for e in entries if JA4_RE.match(e.get("ja4", ""))] + browsers

    seen, deduped = set(), []
    for e in sorted(entries, key=lambda x: (x["verdict"], x["category"], x["label"])):
        key = (e["ja4"], e.get("ja4h", ""), e.get("akamai_h2", ""), e["label"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)

    today = datetime.now(timezone.utc).date().isoformat()
    feed = {
        "$schema": "./schema.json",
        "metadata": {
            "description": "JA4 client-identity threat feed: measured browser vs. automation-tool TLS fingerprints.",
            "reflector": measured.get("reflector"),
            "updated": today,
            "measured_count": sum(1 for e in deduped if e["provenance"]["method"] == "measured"),
            "cited_count": sum(1 for e in deduped if e["provenance"]["method"] == "cited"),
            "cadence": "weekly",
            "license": "CC0-1.0 (data)",
            "pairs_with": ["North-web-dev/ja4-guard", "North-web-dev/fingerprint-db"],
        },
        "references": REFERENCES,
        "entries": deduped,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {OUT}: {feed['metadata']['measured_count']} measured + {feed['metadata']['cited_count']} cited = {len(deduped)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
