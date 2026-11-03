# ip-reputation-checker

A small command-line tool that looks up an IP address against public
reputation sources and summarises the result as a single score and verdict.

It was built to answer one practical question — *should I trust traffic
from this IP?* — without handing a whole dashboard, account, or paid feed
to do it. The free lookup alone tells you where an IP is and who runs it;
the optional AbuseIPDB check is what turns that into an actual abuse
signal. The tool is explicit about which of those two you got, so a clean
geolocation result is never dressed up as a clean reputation.

## What it does

- Validates IPv4 and IPv6 input (rejects garbage like `999.999.999.999`
  with a clear error instead of sending it to an API).
- Queries a free, no-key source (ip-api.com) for country, city, ISP, and
  organisation.
- Optionally queries AbuseIPDB for an abuse confidence score and report
  count, when `ABUSEIPDB_API_KEY` is set in the environment.
- Summarises everything into a score out of 100 and a verdict:
  0–24 Low, 25–74 Medium, 75–100 High.
- Caches results locally (default TTL 24 hours) so repeat lookups do not
  hit the network again.
- Handles HTTP 429 rate limits and network errors with plain-language
  messages, including the server's `Retry-After` value when one is given.
- Runs fully offline with `--no-network`, using bundled sample data, so
  the tool and its tests never depend on a live connection.

## Run it

No third-party dependencies — Python 3.10+ standard library only, so
there is nothing to install.

```bash
# Help
python3 -m ip_reputation_checker --help

# Live lookup (free source; AbuseIPDB added if a key is set)
python3 -m ip_reputation_checker 8.8.8.8

# Offline demo — no network requests at all
python3 -m ip_reputation_checker 203.0.113.45 --no-network

# Machine-readable output, no cache
python3 -m ip_reputation_checker 1.1.1.1 --no-network --json --no-cache
```

## API keys (environment variables only)

Keys are read from the environment, never from the command line, never
hardcoded, and never printed:

```bash
export ABUSEIPDB_API_KEY="your-key-here"
python3 -m ip_reputation_checker 203.0.113.45
```

Without that variable the tool still works — it just reports the free
lookup and labels the score source honestly. If the optional AbuseIPDB
call fails, the free result is still returned rather than failing the
whole lookup.

## Rate limits and caching

- Results are cached in `~/.cache/ip-reputation-checker/cache.json`
  (override with `--cache-path`, lifetime with `--cache-ttl`, skip with
  `--no-cache`). Expired entries are ignored, not served.
- An HTTP 429 exits with a message telling you to wait, and passes on
  the server's `Retry-After` hint when present. A network failure exits
  with a connection message and a pointer to `--no-network` for the demo.
- A cached lookup is labelled as such in the output.

## Sample output (offline demo mode)

```text
$ python3 -m ip_reputation_checker 203.0.113.45 --no-network
IP:      203.0.113.45
Score:   87/100  (High risk)
Source:  AbuseIPDB abuseConfidenceScore
Location: Demo, Demo
ISP:     Example ISP
Reports: 42
Note:    Offline demo result from bundled sample data (not a live lookup).
```

The bundled samples live in `ip_reputation_checker/sample_data.json`:
`8.8.8.8` and `1.1.1.1` (clean) and `203.0.113.45` (high-risk demo).
Any other valid IP in offline mode gets a clearly labelled generic demo
result, not a fabricated reputation.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite uses stubbed HTTP responses and the offline demo path only —
no live network access. It covers IP validation, score summarisation,
cache round-trip and expiry, cache hits without network, HTTP 429
handling, network-error handling, and the CLI in offline and bad-input
cases.

## What was learned

- A reputation score without a named source is meaningless, so the
  output always says where the score came from — and a geolocation-only
  result says so instead of pretending to be an abuse verdict.
- Making the keyed source optional, not required, keeps the tool useful
  on first run and keeps the failure modes honest: a dead optional
  source degrades the answer instead of killing it.
- Building the offline mode first made the tests fast and deterministic,
  and it doubles as a demo for anyone without a key or a connection.

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
