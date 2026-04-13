"""
TLS Version and Cipher Suite Checker
======================================
Connects to one or more hosts and reports:
  - Negotiated TLS version
  - Negotiated cipher suite
  - Whether ML-KEM / X25519MLKEM768 was offered (from server's perspective)
  - Certificate info (issuer, expiry, key type)

Useful for comparing:
  - External connection (browser → Cloudflare → you) — expect TLS 1.3 + ML-KEM
  - Internal connection (you → F5 BIG-IP) — depends on F5 TMOS version and config

LIMITATION:
  Python's ssl module cannot detect ML-KEM negotiation directly — it doesn't
  expose the TLS key_share extension. For full ML-KEM verification, use:
    1. pq.cloudflareresearch.com (online tool for browser → Cloudflare)
    2. verify_mlkem.sh (openssl s_client with TLS 1.3 key logging)

This script is useful for: TLS version, cipher suite, and certificate auditing.

Usage:
    python check_tls_version.py example.com
    python check_tls_version.py example.com 8443
    python check_tls_version.py example.com your-f5.internal 192.168.1.10

Source: Python ssl module docs — docs.python.org/3/library/ssl.html
"""

import ssl
import socket
import sys
import datetime


def check_host(hostname: str, port: int = 443) -> dict:
    """
    Connect to a host via TLS and collect negotiation details.

    Creates a real TLS connection, completes the handshake, and extracts
    the negotiated parameters. Does NOT send any HTTP request.

    Args:
        hostname: The hostname or IP address to connect to.
        port: The port to connect on (default 443).

    Returns:
        Dict with keys: hostname, port, tls_version, cipher_name,
        cipher_bits, cert_subject, cert_issuer, cert_expiry,
        cert_key_type, error (if any).
    """
    result = {
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "cipher_name": None,
        "cipher_bits": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_key_type": None,
        "error": None,
    }

    try:
        # Create SSL context that prefers TLS 1.3
        # SSLContext with TLS_CLIENT verifies the server certificate
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # accept 1.2 too, for comparison
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

        # Load the system's CA bundle for certificate verification
        ctx.load_default_certs()

        # Connect and complete the TLS handshake
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                # TLS version negotiated (e.g. "TLSv1.3")
                result["tls_version"] = tls_sock.version()

                # Cipher suite negotiated (name, protocol, key_bits)
                cipher = tls_sock.cipher()
                if cipher:
                    result["cipher_name"] = cipher[0]
                    result["cipher_bits"] = cipher[2]

                # Certificate details
                cert = tls_sock.getpeercert()
                if cert:
                    # Subject: {'commonName': 'example.com', ...}
                    subject = dict(x[0] for x in cert.get("subject", []))
                    result["cert_subject"] = subject.get("commonName", "unknown")

                    # Issuer: {'organizationName': 'DigiCert', ...}
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["cert_issuer"] = issuer.get("organizationName", "unknown")

                    # Expiry: 'Apr 15 12:00:00 2026 GMT'
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        try:
                            expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                            result["cert_expiry"] = expiry_dt.strftime("%Y-%m-%d")
                        except ValueError:
                            result["cert_expiry"] = expiry_str

    except ssl.CertificateError as e:
        result["error"] = f"Certificate error: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = f"Network error: {e}"

    return result


def assess_pqc_readiness(result: dict) -> str:
    """
    Assess the PQC readiness of a host based on its TLS configuration.

    Note: Python's ssl module cannot detect whether ML-KEM was actually
    negotiated (that requires inspecting the key_share TLS extension).
    This function assesses CAPABILITY (is TLS 1.3 in use?) not ACTUALITY.

    Args:
        result: Dict returned by check_host().

    Returns:
        Assessment string.
    """
    if result["error"]:
        return "UNKNOWN (connection error)"

    tls = result.get("tls_version", "")
    cipher = result.get("cipher_name", "")

    if tls == "TLSv1.3":
        # TLS 1.3 is necessary but not sufficient for ML-KEM
        # ML-KEM also requires both client and server to advertise X25519MLKEM768
        if "MLKEM" in cipher.upper() or "ML_KEM" in cipher.upper():
            return "ML-KEM CONFIRMED — X25519MLKEM768 negotiated"
        else:
            return "TLS 1.3 capable — ML-KEM possible if both sides configured"
    elif tls == "TLSv1.2":
        return "HIGH RISK — TLS 1.2 cannot negotiate ML-KEM"
    else:
        return f"UNKNOWN ({tls})"


def days_until_expiry(expiry_str: str) -> int | None:
    """
    Calculate days until certificate expiry.

    Args:
        expiry_str: Date string in YYYY-MM-DD format.

    Returns:
        Number of days until expiry, or None if parsing fails.
    """
    if not expiry_str:
        return None
    try:
        expiry = datetime.datetime.strptime(expiry_str, "%Y-%m-%d")
        delta = expiry - datetime.datetime.utcnow()
        return delta.days
    except ValueError:
        return None


def print_result(result: dict):
    """
    Print a formatted report for a single host's TLS check results.

    Args:
        result: Dict returned by check_host().
    """
    host_label = f"{result['hostname']}:{result['port']}"
    print(f"\n  ┌─ {host_label} {'─' * max(0, 54 - len(host_label))}┐")

    if result["error"]:
        print(f"  │  ERROR: {result['error']}")
        print(f"  └{'─' * 58}┘")
        return

    tls_ver = result.get("tls_version", "unknown")
    cipher = result.get("cipher_name", "unknown")
    bits = result.get("cipher_bits", "?")
    subject = result.get("cert_subject", "unknown")
    issuer = result.get("cert_issuer", "unknown")
    expiry = result.get("cert_expiry", "unknown")
    days = days_until_expiry(expiry) if expiry else None

    # TLS version with risk color
    if tls_ver == "TLSv1.3":
        tls_color = "\033[92m"   # green
    elif tls_ver == "TLSv1.2":
        tls_color = "\033[91m"   # red
    else:
        tls_color = "\033[93m"   # yellow
    reset = "\033[0m"

    print(f"  │  TLS Version:   {tls_color}{tls_ver}{reset}")
    print(f"  │  Cipher Suite:  {cipher} ({bits}-bit)")
    print(f"  │  Cert Subject:  {subject}")
    print(f"  │  Cert Issuer:   {issuer}")

    if days is not None:
        expiry_color = "\033[91m" if days < 30 else "\033[92m"
        print(f"  │  Cert Expiry:   {expiry} ({expiry_color}{days} days{reset})")
    else:
        print(f"  │  Cert Expiry:   {expiry}")

    assessment = assess_pqc_readiness(result)
    if "HIGH RISK" in assessment:
        assess_color = "\033[91m"
    elif "CONFIRMED" in assessment:
        assess_color = "\033[92m"
    elif "capable" in assessment:
        assess_color = "\033[96m"
    else:
        assess_color = "\033[93m"

    print(f"  │  PQC Status:    {assess_color}{assessment}{reset}")
    print(f"  └{'─' * 58}┘")


def main():
    """
    Check TLS configuration for one or more hosts.

    CLI args: hostnames (optionally with :port suffix).
    Default test hosts if none provided: example.com, cloudflare.com.
    """
    # Parse CLI arguments — accept "hostname" or "hostname:port"
    if len(sys.argv) > 1:
        raw_args = sys.argv[1:]
    else:
        raw_args = ["cloudflare.com", "example.com"]
        print("No hosts specified. Testing defaults: cloudflare.com, example.com")
        print("Usage: python check_tls_version.py <hostname[:port]> ...")

    targets = []
    for arg in raw_args:
        if ":" in arg and not arg.startswith("["):
            # hostname:port format
            host, port_str = arg.rsplit(":", 1)
            try:
                targets.append((host, int(port_str)))
            except ValueError:
                print(f"WARNING: Invalid port in '{arg}', defaulting to 443")
                targets.append((arg, 443))
        else:
            targets.append((arg, 443))

    print()
    print("=" * 62)
    print("TLS VERSION AND CIPHER SUITE CHECKER")
    print("Assessing post-quantum readiness of TLS endpoints")
    print("=" * 62)

    for hostname, port in targets:
        print(f"\n  Connecting to {hostname}:{port}...", end="", flush=True)
        result = check_host(hostname, port)
        print(" done.")
        print_result(result)

    print()
    print("  IMPORTANT: Python's ssl module cannot detect ML-KEM key exchange.")
    print("  For definitive ML-KEM verification, use:")
    print("    1. pq.cloudflareresearch.com — browser → Cloudflare verification")
    print("    2. verify_mlkem.sh — openssl s_client TLS 1.3 key_share inspection")
    print()
    print("  F5 BIG-IP ML-KEM requires:")
    print("    - TMOS 17.5.1 or later")
    print("    - TLS 1.3 enabled in Client SSL Profile")
    print("    - Cipher suite: SecP256r1ML-KEM-768 or SecP384r1ML-KEM-1024")


if __name__ == "__main__":
    main()
