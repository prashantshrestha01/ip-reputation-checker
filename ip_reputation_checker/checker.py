"""IP reputation lookup: validation, caching, fetching, summarisation.

Standard library only. No API keys are hardcoded anywhere in this
project; the optional AbuseIPDB key is read from the environment
by the CLI layer, never stored here.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

IP_API_URL = "https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"

DEFAULT_TTL_SECONDS = 24 * 3600


class ReputationError(Exception):
    """Base error for lookup failures."""


class RateLimitError(ReputationError):
    """Raised on HTTP 429, with the server's Retry-After value if given."""

    def __init__(self, message: str, retry_after: str | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class NetworkError(ReputationError):
    """Raised on connection / DNS / timeout failures."""


def validate_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate an IPv4/IPv6 string, raising ValueError on bad input.

    Rejects empty strings, surrounding whitespace is stripped first,
    and private/reserved addresses are still valid syntactically --
    callers decide whether to query them.
    """
    if not value or not value.strip():
        raise ValueError("IP address must not be empty")
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def is_private_or_reserved(ip) -> bool:
    return bool(ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local)


def default_cache_path() -> Path:
    return Path.home() / ".cache" / "ip-reputation-checker" / "cache.json"


def load_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def cache_get(path: Path, ip: str, ttl: int = DEFAULT_TTL_SECONDS,
              now: float | None = None) -> dict | None:
    """Return a cached entry if it exists and is within TTL, else None."""
    now = time.time() if now is None else now
    entry = load_cache(path).get(ip)
    if not isinstance(entry, dict):
        return None
    if now - entry.get("_cached_at", 0) > ttl:
        return None
    return {k: v for k, v in entry.items() if not k.startswith("_")}


def cache_put(path: Path, ip: str, result: dict,
              now: float | None = None) -> None:
    now = time.time() if now is None else now
    data = load_cache(path)
    stored = dict(result)
    stored["_cached_at"] = now
    data[ip] = stored
    save_cache(path, data)


def _fetch_json(url: str, headers: dict | None = None,
                opener=None) -> dict:
    """Fetch JSON, translating HTTP/network failures into clear errors."""
    request = urllib.request.Request(url, headers=headers or {})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            retry = exc.headers.get("Retry-After") if exc.headers else None
            raise RateLimitError(
                "Rate limited (HTTP 429). Wait before retrying"
                + (f" (server suggests {retry}s)" if retry else "")
                + "; try again later or use --no-network for the offline demo.",
                retry_after=retry,
            ) from exc
        raise ReputationError(f"HTTP {exc.code} from reputation source: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise NetworkError(f"Network error contacting reputation source: {exc.reason}") from exc
    except (json.JSONDecodeError, TimeoutError) as exc:
        raise ReputationError(f"Could not parse response from reputation source: {exc}") from exc


def fetch_ip_api(ip: str, opener=None) -> dict:
    data = _fetch_json(IP_API_URL.format(ip=ip), opener=opener)
    if data.get("status") == "fail":
        raise ReputationError(f"IP info lookup failed: {data.get('message', 'unknown error')}")
    return data


def fetch_abuseipdb(ip: str, api_key: str, opener=None) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    data = _fetch_json(ABUSEIPDB_URL.format(ip=ip), headers=headers, opener=opener)
    return data.get("data", data)


def summarise(ip: str, ip_api: dict | None = None,
              abuse: dict | None = None) -> dict:
    """Turn raw source data into a single score + verdict.

    Score is 0-100 (higher = riskier):
    - If AbuseIPDB data is present, its abuseConfidenceScore is the score.
    - Otherwise the score is 0 for a clean public lookup, because a
      geolocation/ISP lookup alone is not evidence of abuse. This is
      stated explicitly in the output so a 0 is never mistaken for
      a full abuse check.
    Verdict bands: 0-24 Low, 25-74 Medium, 75-100 High.
    """
    score = 0
    source = "ip-api (geolocation/ISP only, no abuse signal)"
    abuse_score = None
    total_reports = None
    if abuse:
        abuse_score = abuse.get("abuseConfidenceScore")
        total_reports = abuse.get("totalReports")
        if isinstance(abuse_score, (int, float)):
            score = int(max(0, min(100, abuse_score)))
            source = "AbuseIPDB abuseConfidenceScore"
    if score < 25:
        verdict = "Low"
    elif score < 75:
        verdict = "Medium"
    else:
        verdict = "High"
    return {
        "ip": ip,
        "score": score,
        "verdict": verdict,
        "abuse_confidence_score": abuse_score,
        "total_reports": total_reports,
        "country": (ip_api or {}).get("country"),
        "city": (ip_api or {}).get("city"),
        "isp": (ip_api or {}).get("isp"),
        "org": (ip_api or {}).get("org"),
        "score_source": source,
    }


def load_sample_data() -> dict:
    sample_path = Path(__file__).with_name("sample_data.json")
    return json.loads(sample_path.read_text(encoding="utf-8"))


def lookup_offline(ip: str) -> dict:
    """Offline demo lookup from bundled sample data; never touches network."""
    samples = load_sample_data()
    entry = samples.get(ip)
    if entry is None:
        # Generic demo entry so any valid IP works offline.
        entry = {
            "ip_api": {"country": "Demo", "city": "Demo", "isp": "Demo ISP", "org": "Demo Org"},
            "abuse": {"abuseConfidenceScore": 0, "totalReports": 0},
        }
        note = "No bundled sample for this IP; showing a generic demo result."
    else:
        note = "Offline demo result from bundled sample data (not a live lookup)."
    summary = summarise(ip, entry.get("ip_api"), entry.get("abuse"))
    summary["mode"] = "offline-demo"
    summary["note"] = note
    return summary


def lookup(ip: str, *, use_cache: bool = True, ttl: int = DEFAULT_TTL_SECONDS,
           cache_path: Path | None = None, opener=None,
           abuse_api_key: str | None = None) -> dict:
    """Full lookup: cache -> free source -> optional keyed source -> summary."""
    parsed = validate_ip(ip)
    ip_str = str(parsed)
    path = cache_path or default_cache_path()
    if use_cache:
        cached = cache_get(path, ip_str, ttl=ttl)
        if cached is not None:
            cached = dict(cached)
            cached["cached"] = True
            return cached
    ip_api = fetch_ip_api(ip_str, opener=opener)
    abuse = None
    if abuse_api_key:
        try:
            abuse = fetch_abuseipdb(ip_str, abuse_api_key, opener=opener)
        except ReputationError:
            # A failing optional source must not kill the free lookup.
            abuse = None
    summary = summarise(ip_str, ip_api, abuse)
    summary["mode"] = "live"
    summary["cached"] = False
    if use_cache:
        cache_put(path, ip_str, summary)
    return summary
