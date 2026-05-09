import asyncio
import ipaddress
import sys
from datetime import datetime

PORTS = {
    # SSH / file transfer
    22:    "SSH/SFTP",
    2222:  "SSH (alt)",
    8022:  "SSH (alt)",
    21:    "FTP",
    990:   "FTPS (implicit)",
    # Email
    25:    "SMTP",
    587:   "SMTP (submission)",
    465:   "SMTPS",
    143:   "IMAP",
    993:   "IMAPS",
    110:   "POP3",
    995:   "POP3S",
    # Directory / auth
    389:   "LDAP",
    636:   "LDAPS",
    88:    "Kerberos",
    464:   "Kerberos kpasswd",
    # Databases
    1433:  "MSSQL",
    3306:  "MySQL/MariaDB",
    5432:  "PostgreSQL",
    1521:  "Oracle",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    5984:  "CouchDB",
    # Messaging / streaming
    5672:  "AMQP (RabbitMQ)",
    5671:  "AMQPS",
    9092:  "Kafka",
    9093:  "Kafka TLS",
    61616: "ActiveMQ",
    1883:  "MQTT",
    8883:  "MQTT TLS",
    # VoIP
    5060:  "SIP",
    5061:  "SIP TLS",
    # Remote access / management
    3389:  "RDP",
    5985:  "WinRM (HTTP)",
    5986:  "WinRM (HTTPS)",
    445:   "SMB",
    # Syslog / monitoring
    514:   "Syslog",
    6514:  "Syslog TLS",
    # gRPC / service mesh common ports
    50051: "gRPC (default)",
    8500:  "Consul",
    8200:  "Vault",
    2181:  "ZooKeeper",
    2379:  "etcd",
    # VPN
    1194:  "OpenVPN",
    1701:  "L2TP",
}

RANGES = [
    "104.219.76.0/23",
    "104.219.78.0/23",
]

CONCURRENCY = 300
TIMEOUT = 2.0


async def check_port(sem, ip, port, results):
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), timeout=TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            results.append((str(ip), port))
        except Exception:
            pass


async def main():
    targets = []
    for cidr in RANGES:
        net = ipaddress.ip_network(cidr, strict=False)
        for ip in net.hosts():
            for port in PORTS:
                targets.append((ip, port))

    total = len(targets)
    print(f"Scanning {total} probes across {sum(ipaddress.ip_network(r, strict=False).num_addresses - 2 for r in RANGES)} IPs")
    print(f"Ports: {', '.join(str(p) for p in PORTS)}")
    print(f"Started: {datetime.now().strftime('%H:%M:%S')}\n")

    sem = asyncio.Semaphore(CONCURRENCY)
    results = []
    done = 0

    tasks = [check_port(sem, ip, port, results) for ip, port in targets]

    for coro in asyncio.as_completed(tasks):
        await coro
        done += 1
        if done % 1000 == 0:
            pct = done / total * 100
            print(f"  {done}/{total} ({pct:.0f}%) — {len(results)} open so far", flush=True)

    print(f"\nFinished: {datetime.now().strftime('%H:%M:%S')}")
    print(f"\n{'='*60}")
    print(f"OPEN PORTS — {len(results)} found")
    print(f"{'='*60}")

    by_host = {}
    for ip, port in sorted(results, key=lambda x: (ipaddress.ip_address(x[0]), x[1])):
        by_host.setdefault(ip, []).append(port)

    for ip in sorted(by_host, key=ipaddress.ip_address):
        ports = by_host[ip]
        port_str = "  |  ".join(f"{p} ({PORTS[p]})" for p in sorted(ports))
        print(f"  {ip:18s}  {port_str}")

    print(f"\n{'='*60}")
    print("SUMMARY BY PROTOCOL")
    print(f"{'='*60}")
    port_counts = {}
    for _, port in results:
        port_counts[port] = port_counts.get(port, 0) + 1
    for port in sorted(port_counts, key=lambda p: -port_counts[p]):
        print(f"  {PORTS[port]:25s} port {port:5d}  —  {port_counts[port]} host(s)")


asyncio.run(main())
