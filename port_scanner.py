#!/usr/bin/env python3
"""
Port Scanner — Multi-threaded network port scanner with service detection.

Usage:
    python port_scanner.py <target> [--ports PORT_RANGE] [--threads N] [--output FILE]

Examples:
    python port_scanner.py 192.168.1.1
    python port_scanner.py 192.168.1.1 --ports 1-1024
    python port_scanner.py 192.168.1.1 --threads 100 --output results.txt

Disclaimer: For educational and authorized use only.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Common ports and their associated services
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Risk levels for commonly exposed services
RISK_LEVELS: Dict[str, str] = {
    "Telnet": "🔴 High",
    "FTP": "🟠 Medium",
    "RDP": "🟠 Medium",
    "SMB": "🟠 Medium",
    "VNC": "🟠 Medium",
    "MongoDB": "🟠 Medium",
    "Redis": "🟠 Medium",
    "Oracle DB": "🟠 Medium",
    "MSSQL": "🟠 Medium",
    "MySQL": "🟡 Low",
    "PostgreSQL": "🟡 Low",
    "SSH": "🟢 Low",
    "HTTP": "🟡 Low",
    "HTTPS": "🟢 Low",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[Tuple[int, str]]:
    """Scan a single port and return (port, service) if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            # Try to get banner for service version
            try:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner and service == "Unknown":
                    service = "HTTP"
            except Exception:
                pass
            return (port, service)
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()
    return None


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        socket.gethostbyname(host)
        return host
    except socket.gaierror:
        print(f"Error: Could not resolve host '{host}'")
        sys.exit(1)


def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string like '1-1024' or '22,80,443'."""
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_host(host: str, ports: List[int], threads: int = 50,
              timeout: float = 1.0) -> List[Tuple[int, str]]:
    """Scan multiple ports on a host using thread pool."""
    open_ports = []
    total = len(ports)
    scanned = 0

    print(f"\nScanning {host} ({total} ports, {threads} threads)...")
    print("-" * 60)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            scanned += 1
            if result:
                open_ports.append(result)
                port_num, service = result
                risk = RISK_LEVELS.get(service, "🟡 Unknown")
                print(f"  [{scanned}/{total}] OPEN  {port_num:<6} {service:<15} {risk}")
            if scanned % 100 == 0:
                print(f"  Progress: {scanned}/{total} ports scanned...")

    open_ports.sort(key=lambda x: x[0])
    return open_ports


def generate_report(host: str, open_ports: List[Tuple[int, str]],
                    scan_time: float) -> str:
    """Generate a text report of scan results."""
    lines = []
    lines.append("=" * 60)
    lines.append("PORT SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Target:     {host}")
    lines.append(f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Scan time:  {scan_time:.2f} seconds")
    lines.append(f"Open ports: {len(open_ports)}")
    lines.append("-" * 60)

    if open_ports:
        lines.append(f"\n{'Port':<8}{'Service':<15}{'Risk Level'}")
        lines.append(f"{'-'*8} {'-'*15} {'-'*12}")
        for port, service in open_ports:
            risk = RISK_LEVELS.get(service, "🟡 Unknown")
            lines.append(f"{port:<8}{service:<15}{risk}")
    else:
        lines.append("\nNo open ports found.")

    lines.append("-" * 60)
    lines.append("\nRecommendations:")
    for port, service in open_ports:
        risk = RISK_LEVELS.get(service, "")
        if "🔴" in risk or "🟠" in risk:
            lines.append(f"  - Port {port} ({service}): Consider blocking or restricting access")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded port scanner with service detection"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--ports", default="21,22,23,25,53,80,110,111,135,139,143,443,445,"
                          "993,995,1433,1521,3306,3389,5432,5900,6379,8080,"
                          "8443,27017",
        help="Port range (e.g., '1-1024' or '22,80,443')"
    )
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--output", help="Output file for report")

    args = parser.parse_args()

    # Resolve target
    target = resolve_host(args.target)
    ports = parse_port_range(args.ports)

    print(f"[*] Target: {target}")
    print(f"[*] Ports: {len(ports)}")
    print(f"[*] Threads: {args.threads}")

    # Run scan
    start_time = time.time()
    open_ports = scan_host(target, ports, args.threads, args.timeout)
    scan_time = time.time() - start_time

    # Generate report
    report = generate_report(target, open_ports, scan_time)
    print(f"\n{report}")

    # Save to file if requested
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n[*] Report saved to: {args.output}")

    # Summary
    print(f"\n[*] Scan complete: {len(open_ports)} open ports found in {scan_time:.2f}s")


if __name__ == "__main__":
    main()
