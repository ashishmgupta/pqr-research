"""
Cloudflare PQC Zone Checker
============================
Checks each Cloudflare zone for:
  - Minimum TLS version (must be 1.3 for ML-KEM)
  - Post-quantum encryption setting (supported / preferred / off)
  - Flags zones that are NOT TLS 1.3 as HIGH RISK

Source: developers.cloudflare.com/ssl/post-quantum-cryptography/
        developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-to-origin/

API used:
  GET  /client/v4/zones                    → list all zones
  GET  /client/v4/zones/{id}/settings/min_tls_version
  GET  /client/v4/zones/{id}/cache/origin_post_quantum_encryption

Authentication:
  Set environment variable CLOUDFLARE_API_TOKEN before running.
  The token needs Zone:Read and Zone Settings:Read permissions.

Usage:
    export CLOUDFLARE_API_TOKEN="your_token_here"
    python check_cloudflare_pq.py

    # Optional: check only specific zones by name pattern
    python check_cloudflare_pq.py example.com
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass

# Cloudflare API base URL
CF_API_BASE = "https://api.cloudflare.com/client/v4"

# Risk thresholds
RISK_TLS_12 = "HIGH — TLS 1.2 cannot negotiate ML-KEM"
RISK_PQ_OFF = "MEDIUM — ML-KEM not advertised to origin"
RISK_PQ_SUPPORTED = "LOW — ML-KEM supported but requires HelloRetryRequest"
RISK_PQ_PREFERRED = "NONE — ML-KEM preferred, no extra round-trip"


@dataclass
class ZoneResult:
    """Results for a single Cloudflare zone."""
    zone_id: str
    zone_name: str
    min_tls: str          # e.g. "1.2" or "1.3"
    pq_setting: str       # "supported", "preferred", or "off"
    risk: str
    error: str = ""


def get_token() -> str:
    """
    Read the Cloudflare API token from environment.

    Never hardcode the token — it grants access to your zones.

    Returns:
        The API token string.

    Raises:
        SystemExit: If the token is not set.
    """
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        print("ERROR: CLOUDFLARE_API_TOKEN environment variable is not set.")
        print()
        print("To set it (PowerShell):")
        print('  $env:CLOUDFLARE_API_TOKEN = "your_token_here"')
        print()
        print("To set it (bash/zsh):")
        print('  export CLOUDFLARE_API_TOKEN="your_token_here"')
        print()
        print("Your token needs these permissions:")
        print("  Zone > Zone: Read")
        print("  Zone > Zone Settings: Read")
        sys.exit(1)
    return token


def cf_get(path: str, token: str) -> dict:
    """
    Make an authenticated GET request to the Cloudflare API.

    Args:
        path: API path, e.g. "/zones" or "/zones/{id}/settings/min_tls_version"
        token: Cloudflare API token.

    Returns:
        Parsed JSON response dict.

    Raises:
        urllib.error.HTTPError: On non-2xx responses.
        ValueError: If the response is not valid JSON.
    """
    url = CF_API_BASE + path
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def list_zones(token: str, name_filter: str = "") -> list[dict]:
    """
    List all zones accessible with the given token.

    Args:
        token: Cloudflare API token.
        name_filter: Optional zone name substring filter.

    Returns:
        List of zone dicts with 'id' and 'name' keys.
    """
    all_zones = []
    page = 1

    while True:
        # Cloudflare paginates at 50 zones per page
        data = cf_get(f"/zones?page={page}&per_page=50", token)
        zones = data.get("result", [])
        if not zones:
            break
        all_zones.extend(zones)
        result_info = data.get("result_info", {})
        if page >= result_info.get("total_pages", 1):
            break
        page += 1
        time.sleep(0.1)  # stay well under Cloudflare rate limits (1200 req/5min)

    if name_filter:
        all_zones = [z for z in all_zones if name_filter.lower() in z["name"].lower()]

    return all_zones


def get_min_tls(zone_id: str, token: str) -> str:
    """
    Get the minimum TLS version setting for a zone.

    Args:
        zone_id: Cloudflare zone ID.
        token: API token.

    Returns:
        TLS version string like "1.2" or "1.3".
    """
    data = cf_get(f"/zones/{zone_id}/settings/min_tls_version", token)
    return data.get("result", {}).get("value", "unknown")


def get_pq_setting(zone_id: str, token: str) -> str:
    """
    Get the origin post-quantum encryption preference for a zone.

    Cloudflare documentation:
        developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-to-origin/

    Values:
        "supported"  — Cloudflare adds PQ keyshare on HelloRetryRequest
                       (default, adds one extra round-trip)
        "preferred"  — Cloudflare sends PQ keyshare in first ClientHello
                       (eliminates the extra round-trip)
        "off"        — PQ not used for Cloudflare → origin connections

    Note: Browser → Cloudflare is ALWAYS PQ (ML-KEM is on by default for
    TLS 1.3 zones). This setting only controls Cloudflare → your origin (F5).

    Args:
        zone_id: Cloudflare zone ID.
        token: API token.

    Returns:
        PQ setting string: "supported", "preferred", or "off".
    """
    try:
        data = cf_get(f"/zones/{zone_id}/cache/origin_post_quantum_encryption", token)
        return data.get("result", {}).get("value", "unknown")
    except urllib.error.HTTPError as e:
        # Some zones may not have this setting exposed
        if e.code == 404:
            return "not_available"
        raise


def assess_risk(min_tls: str, pq_setting: str) -> str:
    """
    Determine the PQC risk level for a zone based on its TLS and PQ settings.

    Risk logic:
      1. TLS 1.2 minimum → HIGH RISK (ML-KEM is impossible without TLS 1.3)
      2. TLS 1.3, PQ off → MEDIUM RISK (no PQ to origin)
      3. TLS 1.3, PQ supported → LOW RISK (PQ works but with extra round-trip)
      4. TLS 1.3, PQ preferred → NO RISK (fully optimized)

    Args:
        min_tls: Minimum TLS version string.
        pq_setting: Post-quantum encryption setting string.

    Returns:
        Risk assessment string.
    """
    if min_tls not in ("1.3",):
        return RISK_TLS_12
    if pq_setting == "off":
        return RISK_PQ_OFF
    if pq_setting == "supported":
        return RISK_PQ_SUPPORTED
    if pq_setting == "preferred":
        return RISK_PQ_PREFERRED
    return f"UNKNOWN (min_tls={min_tls}, pq={pq_setting})"


def check_zone(zone: dict, token: str) -> ZoneResult:
    """
    Run all checks for a single zone.

    Args:
        zone: Zone dict with 'id' and 'name'.
        token: API token.

    Returns:
        ZoneResult with all findings.
    """
    zone_id = zone["id"]
    zone_name = zone["name"]

    try:
        min_tls = get_min_tls(zone_id, token)
        time.sleep(0.05)  # rate limit courtesy
        pq_setting = get_pq_setting(zone_id, token)
        time.sleep(0.05)
        risk = assess_risk(min_tls, pq_setting)
        return ZoneResult(zone_id, zone_name, min_tls, pq_setting, risk)

    except urllib.error.HTTPError as e:
        return ZoneResult(zone_id, zone_name, "error", "error", "ERROR",
                          error=f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        return ZoneResult(zone_id, zone_name, "error", "error", "ERROR",
                          error=str(e))


def print_table(results: list[ZoneResult]):
    """
    Print a formatted table of zone PQC status results.

    Args:
        results: List of ZoneResult objects.
    """
    if not results:
        print("No zones found.")
        return

    # Calculate column widths dynamically
    col_name = max(len(r.zone_name) for r in results)
    col_name = max(col_name, 20)

    header = (
        f"  {'Zone Name':<{col_name}}  {'Min TLS':>8}  {'PQ Setting':>12}  Risk"
    )
    print()
    print(header)
    print("  " + "─" * (len(header) - 2))

    high_risk = []
    for r in results:
        risk_short = r.risk.split("—")[0].strip()  # just the severity label

        # Color coding in terminal (ANSI escape codes)
        if "HIGH" in r.risk:
            color = "\033[91m"   # red
            high_risk.append(r)
        elif "MEDIUM" in r.risk:
            color = "\033[93m"   # yellow
        elif "LOW" in r.risk:
            color = "\033[96m"   # cyan
        elif "NONE" in r.risk:
            color = "\033[92m"   # green
        else:
            color = "\033[0m"    # reset

        reset = "\033[0m"

        line = f"  {r.zone_name:<{col_name}}  {r.min_tls:>8}  {r.pq_setting:>12}  {color}{risk_short}{reset}"
        print(line)

        if r.error:
            print(f"    ERROR: {r.error}")

    print()

    # Summary
    total = len(results)
    high = sum(1 for r in results if "HIGH" in r.risk)
    medium = sum(1 for r in results if "MEDIUM" in r.risk)
    low = sum(1 for r in results if "LOW" in r.risk)
    ok = sum(1 for r in results if "NONE" in r.risk)

    print(f"  Summary: {total} zones — {ok} optimized, {low} supported, {medium} medium risk, {high} HIGH RISK")
    print()

    if high_risk:
        print("\033[91m  HIGH RISK ZONES (TLS 1.2 — ML-KEM impossible):\033[0m")
        for r in high_risk:
            print(f"    → {r.zone_name}")
        print()
        print("  To fix: Change minimum TLS version to 1.3 in Cloudflare SSL/TLS → Edge Certificates")
        print()

    print("  To upgrade PQ setting from 'supported' to 'preferred' (eliminates extra round-trip):")
    print("  PUT /zones/{zone_id}/cache/origin_post_quantum_encryption")
    print('  Body: {"value": "preferred"}')
    print()
    print("  Verification tool: pq.cloudflareresearch.com")
    print("  Enter your hostname to confirm X25519MLKEM768 is negotiated.")


def main():
    """
    Main entry point: authenticate, list zones, check each, print results.
    """
    token = get_token()
    name_filter = sys.argv[1] if len(sys.argv) > 1 else ""

    print("=" * 68)
    print("CLOUDFLARE PQC ZONE CHECKER")
    print("Checks TLS version and post-quantum encryption for all zones")
    print("Source: developers.cloudflare.com/ssl/post-quantum-cryptography/")
    print("=" * 68)
    print()

    if name_filter:
        print(f"Filtering zones matching: '{name_filter}'")

    print("Fetching zones from Cloudflare API...")
    try:
        zones = list_zones(token, name_filter)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("ERROR: API token lacks permission. Needs Zone:Read.")
        else:
            print(f"ERROR: HTTP {e.code} — {e.reason}")
        sys.exit(1)

    if not zones:
        print("No zones found (check token permissions or name filter).")
        sys.exit(0)

    print(f"Found {len(zones)} zone(s). Checking PQC settings...")
    print()

    results = []
    for zone in zones:
        print(f"  Checking: {zone['name']}...", end="", flush=True)
        result = check_zone(zone, token)
        results.append(result)
        print(f" {result.pq_setting} / TLS {result.min_tls}")

    print_table(results)


if __name__ == "__main__":
    main()
