import socket
import struct
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

TIMEOUT = 2.0
WORKERS = 200

RANGES = [
    "104.219.76.0/23",
    "104.219.78.0/23",
]

UDP_PORTS = {
    500:  "IKEv2/IPsec",
    4500: "IKEv2 NAT-T",
    1194: "OpenVPN",
    161:  "SNMP",
    514:  "Syslog (UDP)",
    1812: "RADIUS",
    88:   "Kerberos (UDP)",
    5060: "SIP (UDP)",
    53:   "DNS",
    123:  "NTP",
}


def make_ike_probe():
    """Minimal IKEv2 IKE_SA_INIT — enough for a server to respond with an error or SA."""
    spi_i = os.urandom(8)
    spi_r = b'\x00' * 8
    # Minimal SA payload: propose AES-256-CBC + SHA-256 + DH-2048
    # Transform type 1 (ENCR), id 12 (AES-CBC), keylen 256
    t_encr = struct.pack('!BBHBBHBBH', 3, 0, 12, 0, 1, 12, 0, 14, 256)
    # Transform type 3 (INTEG), id 2 (HMAC-SHA-256-128)
    t_integ = struct.pack('!BBHBBH', 3, 0, 8, 0, 3, 2)
    # Transform type 4 (DH), id 14 (MODP-2048) — last transform
    t_dh = struct.pack('!BBHBBH', 0, 0, 8, 0, 4, 14)
    transforms = t_encr + t_integ + t_dh
    prop_len = 8 + len(transforms)
    proposal = struct.pack('!BBHBBBB', 0, 0, prop_len, 1, 1, 0, 3) + transforms
    sa_payload_len = 4 + len(proposal)
    # Next payload after SA = 40 (Nonce)
    sa_payload = struct.pack('!BBH', 40, 0, sa_payload_len) + proposal
    # Nonce payload (type 40), 32 random bytes, next=0
    nonce_data = os.urandom(32)
    nonce_payload = struct.pack('!BBH', 0, 0, 4 + len(nonce_data)) + nonce_data
    body = sa_payload + nonce_payload
    total_len = 28 + len(body)
    header = spi_i + spi_r + struct.pack('!BBBBI', 33, 0x20, 34, 0x08, 0) + struct.pack('!I', total_len)
    return header + body


def make_snmp_probe():
    """SNMPv2c GET sysDescr.0"""
    return bytes.fromhex(
        '302602010104067075626c6963a01902047f80'
        '000002010002010030090305312e332e362e312e322e312e312e3000'
    )


def make_sip_probe():
    """SIP OPTIONS ping"""
    return (
        b"OPTIONS sip:probe@target SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP probe;branch=z9hG4bK1234\r\n"
        b"From: <sip:probe@probe>;tag=1234\r\n"
        b"To: <sip:probe@target>\r\n"
        b"Call-ID: probe@probe\r\n"
        b"CSeq: 1 OPTIONS\r\n"
        b"Content-Length: 0\r\n\r\n"
    )


PROBES = {
    500:  make_ike_probe,
    4500: make_ike_probe,
    161:  make_snmp_probe,
    5060: make_sip_probe,
}


def probe_udp(ip, port):
    """Returns 'open', 'closed', or None (filtered/no response)."""
    payload = PROBES[port]() if port in PROBES else b'\x00' * 4
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(payload, (str(ip), port))
        try:
            data, _ = s.recvfrom(1024)
            return 'open', data[:32]
        except socket.timeout:
            return None, None  # filtered or no response
        except ConnectionResetError:
            return 'closed', None  # ICMP port unreachable
    except Exception as e:
        return None, None
    finally:
        s.close()


def main():
    targets = []
    for cidr in RANGES:
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in net.hosts():
            for port in UDP_PORTS:
                targets.append((ip, port))

    total = len(targets)
    print(f"UDP scan: {total} probes across {sum(ipaddress.ip_network(r, strict=False).num_addresses - 2 for r in RANGES)} IPs")
    print(f"Ports: {', '.join(str(p) for p in UDP_PORTS)}")
    print(f"Started: {datetime.now().strftime('%H:%M:%S')}\n")

    results = []
    done = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(probe_udp, ip, port): (ip, port) for ip, port in targets}
        for fut in as_completed(futures):
            ip, port = futures[fut]
            done += 1
            if done % 2000 == 0:
                print(f"  {done}/{total} ({done/total*100:.0f}%) — {len(results)} responding so far", flush=True)
            status, banner = fut.result()
            if status == 'open':
                results.append((str(ip), port, banner))

    print(f"\nFinished: {datetime.now().strftime('%H:%M:%S')}")
    print(f"\n{'='*60}")
    print(f"UDP RESPONDING PORTS — {len(results)} found")
    print(f"{'='*60}")

    if not results:
        print("  No UDP ports responded.")
    else:
        by_host = {}
        for ip, port, banner in sorted(results, key=lambda x: (ipaddress.ip_address(x[0]), x[1])):
            by_host.setdefault(ip, []).append((port, banner))
        for ip in sorted(by_host, key=ipaddress.ip_address):
            for port, banner in sorted(by_host[ip]):
                banner_str = f"  [{banner.hex()}]" if banner else ""
                print(f"  {ip:18s}  {port:5d}  {UDP_PORTS[port]}{banner_str}")

    print(f"\n{'='*60}")
    print("SUMMARY BY PROTOCOL")
    print(f"{'='*60}")
    port_counts = {}
    for _, port, _ in results:
        port_counts[port] = port_counts.get(port, 0) + 1
    if port_counts:
        for port in sorted(port_counts, key=lambda p: -port_counts[p]):
            print(f"  {UDP_PORTS[port]:25s} port {port:5d}  —  {port_counts[port]} host(s)")
    else:
        print("  None.")


main()
