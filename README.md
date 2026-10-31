# ja4-threat-feed

A curated, **sourced** threat-intel feed that maps **JA4 TLS client fingerprints**
to what produced them — a real browser, an automation tool, or a known-bad
client — so a WAF or [`ja4-guard`](https://github.com/North-web-dev/ja4-guard)
deployment can **allow real browsers and flag non-browser clients**.

Think *abuse.ch SSLBL, but JA4-specific and browser-aware*.

![entries](https://img.shields.io/badge/entries-measured%20%2B%20cited-blue)
![refresh](https://img.shields.io/badge/auto--refresh-weekly-blueviolet)
![data](https://img.shields.io/badge/data-CC0--1.0-green)
![code](https://img.shields.io/badge/code-MIT-green)

This is the **intel** piece of a trio:

- [`ja4-guard`](https://github.com/North-web-dev/ja4-guard) — consumes this feed as a deny/allow source.
- [`fingerprint-db`](https://github.com/North-web-dev/fingerprint-db) — the measured browser allowlist this feed cites.

## Why it exists

Security and ops teams buy threat feeds, but nobody ships a JA4-specific
*client-identity* feed that is both **measured** and **auto-refreshed**. JA4
collapses a TLS ClientHello into a short, stable string that is far more
tool-specific than a User-Agent (which any client can set to anything). A
`python-requests` script and Chrome produce visibly different JA4s. This feed
records those JA4s with provenance so you can act on them.

## Honest methodology: measured vs. cited

Every entry carries a `provenance.method`. There are exactly two, and nothing
else is invented:

- **`measured`** — we actually ran the client against a live TLS reflector and
  recorded the JA4 / Akamai-h2 the reflector read back off the wire, plus the
  tool name, version and date. See [`measure/`](measure/). These are the
  **non-browser** entries (curl, wget, Python `requests`/`httpx`/`urllib`/
  `aiohttp`, Go `net/http`, Node `fetch`/undici, Java `HttpClient`). Verdict:
  `non-browser`. The reflector is configurable via `REFLECTOR_URL` and defaults
  to the public [`tls.peet.ws`](https://tls.peet.ws); set it to your own
  reflector to measure against that instead. Two honest notes about the public
  reflector: it does not expose a JA4H, so measured entries carry no `ja4h`
  (the cited browser entries do); and it prints the no-ALPN JA4 without the
  trailing `00`, so the harness pads it back to the FoxIO spec form that
  ja4-guard also computes (the cipher/extension hashes are identical — same
  handshake, canonical string).
- **`cited`** — the **browser allowlist**, referenced (not re-measured) from
  [`fingerprint-db`](https://github.com/North-web-dev/fingerprint-db): its
  curated `browsers` plus its freshly-measured `live` engines. Category
  `browser`, verdict `allow`.

### Known-bad / malware is BY REFERENCE ONLY

We do **not** have our own malware C2 captures, so this feed ships **no**
malware JA4 entries — fabricating them would destroy the one thing a security
feed sells: credibility. For malware / C2 JA4s, go to the authoritative
sources directly (we do not redistribute their data):

| Source | Scope |
|---|---|
| [abuse.ch SSLBL](https://sslbl.abuse.ch/) | malware TLS certificates / JA3, SSL blocklist |
| [FoxIO JA4DB](https://ja4db.com/) | community JA4+ database (apps, malware, tooling) |
| [FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4) | JA4+ fingerprint definitions |

These links are also machine-readable under `references` in `feed.json`.

## The feed

[`feed.json`](feed.json) (validated against [`schema.json`](schema.json)):

```jsonc
{
  "metadata": { "updated": "...", "reflector": "...", "measured_count": 10, "cited_count": 8, ... },
  "references": { "note": "...", "sources": [ ... ] },
  "entries": [
    {
      "ja4": "t13d3113h2_e8f1e7e78f70_ce5650b735ce",
      "akamai_h2": "3:100;4:33554432;2:0|33488897|0|m,p,s,a",
      "category": "tool",                 // browser | library | tool | scanner | unknown
      "label": "curl (HTTP/2 ALPN) 7.81.0",
      "verdict": "non-browser",           // allow | non-browser | suspicious
      "source": "https://tls.peet.ws/api/all",
      "provenance": { "method": "measured", "tool": "curl", "version": "7.81.0", "date": "2026-10-31" }
    }
  ]
}
```

- `ja4h` and `akamai_h2` are included when the client exposed them (some clients
  only speak HTTP/1.1, so they have no Akamai HTTP/2 fingerprint).
- Different tools can share a JA4 when they share a TLS stack (e.g. several
  Python clients built on the same OpenSSL). We list each tool separately with
  its own label — that is the truth, not a bug.

## Threat model (read this)

JA4 is computed from the TLS ClientHello. A client that **wants** to look like a
browser can forge any JA4 — for example with our own
[`impersonate-http`](https://github.com/North-web-dev/impersonate-http). So:

- This feed reliably identifies **lazy** / default clients: a bot using stock
  `requests` or `curl` keeps its library's JA4 and this feed flags it.
- It does **not** stop a determined adversary who deliberately mimics a browser
  JA4. Treat `verdict: allow` as "*consistent with a browser*", never "*proven
  human*".
- JA4 depends on the client's TLS library, **version** and platform, so these
  values drift. That is exactly why the feed re-measures weekly — but your
  production policy should still be seeded from your own observed traffic, not
  this seed alone.

Same honesty as `ja4-guard`'s threat model: this catches the cheap bots, raises
the cost of the rest, and proves nothing on its own.

## Using with ja4-guard

`ja4-guard` today takes JA4 values via its library constructors
(`guard.NewAllowList(...)`, `guard.NewDenyList(...)`, `Policy.Allow/Deny`) or
the CLI's repeatable `-allow` / `-deny` flags. It does **not** yet read
`feed.json` natively — so you wire this feed in with a tiny adapter that turns
the feed into those JA4 slices. Nothing here claims a `ja4-guard` feature that
does not exist.

**Go (deny non-browser clients, allow everything else):**

```go
import (
    "github.com/North-web-dev/ja4-guard/guard"
    threatfeed "github.com/North-web-dev/ja4-threat-feed"
)

feed, _ := threatfeed.Load()
policy := guard.NewDenyList(feed.DenyJA4()...) // block measured bots/libraries
g := guard.New(policy)
```

**Go (allow-list: only known browsers pass):**

```go
feed, _ := threatfeed.Load()
policy := guard.NewAllowList(feed.AllowJA4()...)
policy.FailOpen = false
```

**CLI** — generate `-deny` flags from the feed:

```sh
DENY=$(python3 -c "import loader; print(','.join(loader.deny_ja4()))")
ja4-guard -mode deny-list -deny "$DENY" -upstream http://127.0.0.1:8080 \
  -cert server.crt -key server.key
```

## Loaders

**Go** (`loader.go`, embeds `feed.json`):

```go
feed, _ := threatfeed.Load()
feed.AllowJA4()            // []string of browser JA4s
feed.DenyJA4()             // []string of non-browser / suspicious JA4s
feed.Lookup("t13d3113h2_e8f1e7e78f70_ce5650b735ce") // []Entry
```

**Python** (`loader.py`, stdlib only):

```python
import loader
loader.allow_ja4()   # sorted browser JA4s
loader.deny_ja4()    # sorted non-browser / suspicious JA4s
loader.lookup("t13d3113h2_e8f1e7e78f70_ce5650b735ce")
```

## Validation & CI

`validate.py` checks `feed.json` against `schema.json` plus invariants: every
`ja4` matches the JA4 format, provenance is present (measured entries must name
a tool), browser entries must be `allow`, and no JA4 is simultaneously `allow`
and `non-browser`. CI (`.github/workflows/ci.yml`) runs it on every push and
pull request, alongside the Go and Python loaders.

```sh
pip install jsonschema && python3 validate.py
```

## Update cadence

`.github/workflows/refresh.yml` runs weekly (Mondays, plus manual dispatch): it
re-measures the non-browser clients against the live reflector, re-pulls the
cited browser allowlist from `fingerprint-db`, merges, validates, and commits
`feed.json` **only if it changed**. If the reflector is unreachable the
measurement step exits non-zero and the job fails — it never commits stale or
fabricated data. Refresh commits are authored `North-web-dev`.

## Re-measuring locally

```sh
cd measure && npm install      # no runtime deps; installs nothing by default
node measure.mjs               # writes measure/measured.json (skips uninstalled clients)
cd .. && python3 measure/merge.py   # merges + rebuilds feed.json (pulls fingerprint-db)
python3 validate.py
```

Set `FPDB_PATH=/path/to/fingerprints.json` to merge against a local
`fingerprint-db` checkout instead of downloading it.

## License

- **Data** (`feed.json`, `schema.json`): [CC0-1.0](LICENSE-DATA) — public domain.
- **Code** (loaders, validator, harness): [MIT](LICENSE).

## Support

If this feed saves you time, a ⭐ or a tip keeps the weekly measurements running.

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |
