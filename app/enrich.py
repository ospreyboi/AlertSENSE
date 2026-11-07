"""Threat-intel enrichment: look up IPs (AbuseIPDB) and file hashes (VirusTotal)."""
import ipaddress
import re
import time

import httpx

from app.config import ABUSEIPDB_KEY, VT_KEY

CACHE_TTL = 6 * 3600          # remember results for 6 hours (saves free API quota)
_CACHE: dict[str, tuple[float, dict]] = {}
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")  # MD5 / SHA1 / SHA256


def _cached(key: str, fetch) -> dict:
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    result = fetch()
    if "error" not in result:          # never cache failures
        _CACHE[key] = (time.time(), result)
    return result


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_ip(ip: str) -> dict:
    if not is_public_ip(ip):
        return {"source": "abuseipdb", "skipped": "private or invalid IP"}
    if not ABUSEIPDB_KEY:
        return {"source": "abuseipdb", "skipped": "no API key"}

    def fetch() -> dict:
        try:
            r = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                timeout=5,
            )
            r.raise_for_status()
            d = r.json()["data"]
            return {
                "source": "abuseipdb",
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "is_tor": d.get("isTor", False),
            }
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            return {"source": "abuseipdb", "error": str(exc)[:200]}

    return _cached(f"ip:{ip}", fetch)


def lookup_hash(file_hash: str) -> dict:
    if not HASH_RE.match(file_hash):           # never put untrusted text into a URL
        return {"source": "virustotal", "skipped": "not a valid MD5/SHA1/SHA256"}
    if not VT_KEY:
        return {"source": "virustotal", "skipped": "no API key"}

    def fetch() -> dict:
        try:
            r = httpx.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                          headers={"x-apikey": VT_KEY}, timeout=10)
            if r.status_code == 404:
                return {"source": "virustotal", "known": False, "malicious": 0}
            r.raise_for_status()
            attrs = r.json()["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            return {
                "source": "virustotal",
                "known": True,
                "malicious": stats.get("malicious", 0),
                "engines": sum(stats.values()),
                "name": attrs.get("meaningful_name"),
            }
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            return {"source": "virustotal", "error": str(exc)[:200]}

    return _cached(f"hash:{file_hash.lower()}", fetch)
