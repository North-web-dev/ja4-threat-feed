"""Load the JA4 threat feed and derive allow / deny JA4 sets."""
from __future__ import annotations

import json
import os

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feed.json")


def load(path: str = _PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def entries(path: str = _PATH) -> list:
    return load(path).get("entries", [])


def allow_ja4(path: str = _PATH) -> list:
    return sorted({e["ja4"] for e in entries(path) if e["verdict"] == "allow"})


def deny_ja4(path: str = _PATH) -> list:
    return sorted({e["ja4"] for e in entries(path) if e["verdict"] in ("non-browser", "suspicious")})


def lookup(ja4: str, path: str = _PATH) -> list:
    return [e for e in entries(path) if e["ja4"] == ja4]


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(json.dumps(lookup(sys.argv[1]), indent=2))
    else:
        print(f"allow ({len(allow_ja4())}):")
        for j in allow_ja4():
            print(" ", j)
        print(f"deny ({len(deny_ja4())}):")
        for j in deny_ja4():
            print(" ", j)
