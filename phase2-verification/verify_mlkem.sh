#!/usr/bin/env bash
# =============================================================================
# verify_mlkem.sh — ML-KEM / X25519MLKEM768 TLS Verification
# =============================================================================
# Uses openssl s_client to verify whether a host negotiates the hybrid
# post-quantum key exchange: X25519MLKEM768 (ML-KEM + X25519).
#
# What this checks:
#   - TLS version negotiated (must be 1.3 for ML-KEM)
#   - Whether the server accepted the X25519MLKEM768 key share
#   - Server certificate key type
#   - Full TLS handshake details
#
# Limitations:
#   - Requires OpenSSL 3.2+ (with ML-KEM / hybrid group support)
#   - On Windows, use via WSL (Windows Subsystem for Linux) or Git Bash
#     with a modern OpenSSL build
#   - Standard macOS OpenSSL (LibreSSL) does NOT support ML-KEM —
#     install via: brew install openssl@3
#
# Source: RFC 8446 (TLS 1.3), draft-tls-westerbaan-xyber768d00 (X25519MLKEM768)
# Cloudflare docs: developers.cloudflare.com/ssl/post-quantum-cryptography/
# F5 docs: community.f5.com/kb/technicalarticles/future-proofing-your-network-enabling-quantum-ciphers-on-f5-big-ip-tmos-17-5-1/342586
#
# Usage:
#   chmod +x verify_mlkem.sh
#   ./verify_mlkem.sh cloudflare.com
#   ./verify_mlkem.sh your-f5-host.internal 8443
#   ./verify_mlkem.sh --all                          # test all hosts in HOSTS list
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

# Hosts to test when running with --all flag
# Edit this list to match your infrastructure
HOSTS=(
    "cloudflare.com:443"
    "one.one.one.one:443"
    # "your-f5-external.company.com:443"
    # "your-f5-internal.company.com:443"
)

# OpenSSL binary — override with OPENSSL_BIN env var if needed
# macOS users with brew: export OPENSSL_BIN="/opt/homebrew/opt/openssl@3/bin/openssl"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

# TLS groups to advertise — X25519MLKEM768 is the hybrid PQ group
# X25519 is included for fallback (classical only)
PQ_GROUPS="X25519MLKEM768:x25519:P-256"

# Timeout in seconds for each connection
TIMEOUT=10

# =============================================================================
# Helper functions
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

check_openssl_version() {
    # Verify openssl is present and supports ML-KEM groups
    if ! command -v "${OPENSSL_BIN}" &>/dev/null; then
        echo -e "${RED}ERROR: openssl not found at '${OPENSSL_BIN}'${NC}"
        echo ""
        echo "Install options:"
        echo "  Ubuntu/Debian: sudo apt install openssl (3.0+)"
        echo "  macOS (brew):  brew install openssl@3"
        echo "                 export OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl"
        echo "  Windows:       Use WSL or download OpenSSL 3.2+ from slproweb.com"
        exit 1
    fi

    local version
    version=$("${OPENSSL_BIN}" version 2>/dev/null || echo "unknown")
    echo -e "  OpenSSL version: ${CYAN}${version}${NC}"

    # Check if the version supports X25519MLKEM768 as a TLS group
    # NOTE: use 'openssl list -tls-groups', NOT 'openssl list -groups'
    # 'openssl list -groups' returns nothing in OpenSSL 3.5 — it is a different command
    if ! "${OPENSSL_BIN}" list -tls-groups 2>/dev/null | grep -q "X25519MLKEM768"; then
        echo -e "${YELLOW}  WARNING: This OpenSSL build does not include X25519MLKEM768.${NC}"
        echo "  Requires OpenSSL 3.5.0+ (released April 2025)."
        echo ""
        echo "  To diagnose, run:  openssl list -tls-groups"
        echo "  Common causes:"
        echo "    - Running from PowerShell/CMD with a different OpenSSL in PATH"
        echo "      Fix: use Git Bash (MinGW64) — which openssl"
        echo "    - OpenSSL < 3.5 — upgrade or download from slproweb.com"
        echo ""
    fi
}

check_host() {
    local host="$1"
    local port="$2"

    echo ""
    echo -e "${BOLD}  Checking: ${host}:${port}${NC}"
    echo "  ────────────────────────────────────────────────────────────"

    # Run openssl s_client and capture output
    # -groups: advertise these key share groups (X25519MLKEM768 first = preferred)
    # -tls1_3: force TLS 1.3 (ML-KEM requires TLS 1.3)
    # -connect: target host:port
    # -brief: summary output (suppress certificate dump)
    # We use /dev/null as stdin to close the connection immediately after handshake
    local output
    local exit_code=0
    output=$(timeout "${TIMEOUT}" "${OPENSSL_BIN}" s_client \
        -connect "${host}:${port}" \
        -tls1_3 \
        -groups "${PQ_GROUPS}" \
        -brief \
        -servername "${host}" \
        </dev/null 2>&1) || exit_code=$?

    if [[ ${exit_code} -ne 0 && -z "${output}" ]]; then
        echo -e "  ${RED}ERROR: Connection failed or timed out${NC}"
        return
    fi

    # Extract TLS version
    local tls_version
    tls_version=$(echo "${output}" | grep -oE 'TLSv[0-9]\.[0-9]+' | head -1 || echo "unknown")

    # Extract cipher suite — OpenSSL 3.5 -brief uses "Ciphersuite: NAME"
    local cipher
    cipher=$(echo "${output}" | sed -n 's/^Ciphersuite: //p' | head -1)
    [[ -z "${cipher}" ]] && cipher=$(echo "${output}" | grep -oE 'Cipher\s*:\s*\S+' | awk '{print $NF}')
    [[ -z "${cipher}" ]] && cipher="unknown"

    # Check for X25519MLKEM768 negotiation.
    # OpenSSL 3.5+ outputs "Negotiated TLS1.3 group: X25519MLKEM768" in -brief mode.
    # Older output: "Server Temp Key: X25519MLKEM768" in verbose mode.
    local pq_negotiated="NO"
    local key_share_line
    key_share_line=$(echo "${output}" | grep -i "Negotiated TLS.*group\|Server Temp Key\|Peer Temp Key" || echo "")
    if echo "${key_share_line}" | grep -qi "MLKEM\|X25519MLKEM"; then
        pq_negotiated="YES"
    fi

    # Extract server certificate info — OpenSSL 3.5 -brief uses "Peer certificate: ..."
    local cert_subject
    cert_subject=$(echo "${output}" | sed -n 's/^Peer certificate: //p' | head -1)
    [[ -z "${cert_subject}" ]] && cert_subject=$(echo "${output}" | grep "subject=" | sed 's/.*subject=//' | head -1)
    [[ -z "${cert_subject}" ]] && cert_subject="unknown"

    # Display results
    if [[ "${tls_version}" == "TLSv1.3" ]]; then
        echo -e "  TLS Version:     ${GREEN}${tls_version}${NC}"
    else
        echo -e "  TLS Version:     ${RED}${tls_version} (ML-KEM requires TLS 1.3)${NC}"
    fi

    echo "  Cipher Suite:    ${cipher}"

    if [[ "${pq_negotiated}" == "YES" ]]; then
        echo -e "  ML-KEM (PQ):     ${GREEN}YES — X25519MLKEM768 negotiated${NC}"
    else
        echo -e "  ML-KEM (PQ):     ${YELLOW}NOT DETECTED${NC}"
        echo "                   (Server may not support it, or OpenSSL build lacks ML-KEM)"
    fi

    echo "  Server Cert:     ${cert_subject}"

    # Show the negotiated group line (OpenSSL 3.5 -brief output)
    local negotiated_group
    negotiated_group=$(echo "${output}" | grep -i "Negotiated TLS.*group" || echo "")
    if [[ -n "${negotiated_group}" ]]; then
        echo "  TLS Group:       ${negotiated_group}"
    elif [[ -n "${key_share_line}" ]]; then
        echo "  Key Share Info:  ${key_share_line}"
    fi

    # Handshake details
    echo ""
    echo "  --- Handshake summary ---"
    echo "${output}" | grep -E "Protocol version|Ciphersuite|Negotiated TLS|Peer Temp Key|Peer certificate|Verification" \
        | sed 's/^/  /' || echo "  (no details extracted)"
}

print_f5_instructions() {
    echo ""
    echo "  ════════════════════════════════════════════════════════════"
    echo "  F5 BIG-IP ML-KEM Configuration Reference"
    echo "  Source: community.f5.com (DevCentral) — TMOS 17.5.1+"
    echo "  ════════════════════════════════════════════════════════════"
    echo ""
    echo "  1. Enable via GUI:"
    echo "     Local Traffic → Profiles → SSL → Client"
    echo "     → Configuration: Custom"
    echo "     → Ciphers: DEFAULT + :SecP256r1ML-KEM-768"
    echo "     → TLS 1.3 must be enabled"
    echo ""
    echo "  2. Enable via TMSH (command line):"
    echo '     tmsh modify ltm profile client-ssl <profile-name> \'
    echo '       ciphers "DEFAULT:+ECDHE-RSA-AES256-GCM-SHA384:SecP256r1ML-KEM-768"'
    echo ""
    echo '     tmsh modify ltm profile client-ssl <profile-name> \'
    echo '       options { no-tlsv1 no-tlsv1-1 }'
    echo ""
    echo "  3. Verify negotiation from F5 shell:"
    echo '     openssl s_client -connect <your-vip-ip>:443 \'
    echo '       -tls1_3 -groups "X25519MLKEM768:x25519" -brief'
    echo ""
    echo "  Hybrid cipher suites available in TMOS 17.5.1:"
    echo "    SecP256r1ML-KEM-768   (NIST P-256 + ML-KEM-768)"
    echo "    SecP384r1ML-KEM-1024  (NIST P-384 + ML-KEM-1024)"
    echo ""
    echo "  Note: F5 Client SSL Profile controls Cloudflare → F5 connections."
    echo "        F5 Server SSL Profile controls F5 → backend connections."
}

print_header() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  ML-KEM / X25519MLKEM768 TLS VERIFICATION SCRIPT"
    echo "  Checks whether post-quantum key exchange is negotiated"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Shell context: run in Git Bash (MinGW64), NOT PowerShell/CMD."
    echo "  PowerShell/CMD may resolve a different (older) openssl binary."
    echo "  Diagnose: which openssl && openssl list -tls-groups"
    echo "  Note: 'openssl list -groups' returns NOTHING in OpenSSL 3.5 — use -tls-groups"
    echo ""
    echo "  How ML-KEM appears in TLS 1.3:"
    echo "  1. Client Hello: advertises X25519MLKEM768 in supported_groups"
    echo "  2. Server Hello: if supported, picks X25519MLKEM768 in key_share"
    echo "  3. Result: hybrid classical+PQ key exchange (both must fail to break)"
    echo ""
    echo "  This script advertises X25519MLKEM768 first (preferred mode)."
    echo "  Cloudflare PQ default ('supported') would need HelloRetryRequest;"
    echo "  set to 'preferred' via API to avoid the extra round-trip."
    echo ""
}

# =============================================================================
# Main
# =============================================================================

print_header

echo "  Checking OpenSSL..."
check_openssl_version

# Parse arguments
if [[ $# -eq 0 ]]; then
    echo ""
    echo "  Usage: ./verify_mlkem.sh <hostname> [port]"
    echo "         ./verify_mlkem.sh --all"
    echo ""
    echo "  Running default check: cloudflare.com:443"
    check_host "cloudflare.com" "443"

elif [[ "$1" == "--all" ]]; then
    echo ""
    echo "  Checking all configured hosts..."
    for host_entry in "${HOSTS[@]}"; do
        host="${host_entry%%:*}"
        port="${host_entry##*:}"
        check_host "${host}" "${port}"
    done

else
    host="$1"
    port="${2:-443}"
    check_host "${host}" "${port}"
fi

print_f5_instructions

echo ""
echo "  Online verification (browser → Cloudflare):"
echo "  pq.cloudflareresearch.com — enter hostname, confirm X25519MLKEM768"
echo ""
