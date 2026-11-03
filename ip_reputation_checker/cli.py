"""CLI for ip-reputation-checker.

API keys are read from environment variables only:
    ABUSEIPDB_API_KEY  (optional; enables the AbuseIPDB abuse check)
Never pass a key on the command line, and this tool never prints one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .checker import (
    DEFAULT_TTL_SECONDS,
    NetworkError,
    RateLimitError,
    ReputationError,
    default_cache_path,
    is_private_or_reserved,
    lookup,
    lookup_offline,
    validate_ip,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ip-reputation-checker",
        description="Look up an IP address against public reputation sources and summarise the result.",
    )
    p.add_argument("ip", nargs="?", help="IPv4 or IPv6 address to check")
    p.add_argument("--no-network", action="store_true",
                   help="Offline demo mode: use bundled sample data, make no network requests")
    p.add_argument("--no-cache", action="store_true", help="Skip the local result cache")
    p.add_argument("--cache-ttl", type=int, default=DEFAULT_TTL_SECONDS,
                   help=f"Cache lifetime in seconds (default: {DEFAULT_TTL_SECONDS})")
    p.add_argument("--cache-path", type=Path, default=None,
                   help="Override the cache file location")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    return p


def format_human(result: dict) -> str:
    lines = [
        f"IP:      {result['ip']}",
        f"Score:   {result['score']}/100  ({result['verdict']} risk)",
        f"Source:  {result['score_source']}",
    ]
    if result.get("country"):
        lines.append(f"Location: {result.get('city') or '?'}, {result['country']}")
    if result.get("isp"):
        lines.append(f"ISP:     {result['isp']}")
    if result.get("total_reports") is not None:
        lines.append(f"Reports: {result['total_reports']}")
    if result.get("cached"):
        lines.append("Cache:   served from local cache")
    if result.get("note"):
        lines.append(f"Note:    {result['note']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.ip:
        print("Error: an IP address is required (or run with --help).", file=sys.stderr)
        return 2
    try:
        parsed = validate_ip(args.ip)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.no_network:
        result = lookup_offline(str(parsed))
    else:
        if is_private_or_reserved(parsed):
            print("Note: this is a private/reserved address; public reputation sources have no data for it.",
                  file=sys.stderr)
        try:
            result = lookup(
                str(parsed),
                use_cache=not args.no_cache,
                ttl=args.cache_ttl,
                cache_path=args.cache_path or default_cache_path(),
                abuse_api_key=os.environ.get("ABUSEIPDB_API_KEY") or None,
            )
        except RateLimitError as exc:
            print(f"Error: rate limited. {exc}", file=sys.stderr)
            return 3
        except NetworkError as exc:
            print(f"Error: {exc} (check your connection, or use --no-network for the offline demo).",
                  file=sys.stderr)
            return 3
        except ReputationError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 3

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_human(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
