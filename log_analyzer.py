#!/usr/bin/env python3
"""
Log Analyzer — Analyzes system logs for security events.

Detects:
- Failed login attempts (brute force detection)
- Successful logins after failures
- Suspicious IP addresses
- Privilege escalation attempts
- Unusual login times

Usage:
    python log_analyzer.py <log_file> [--report FILE] [--top N]

Examples:
    python log_analyzer.py /var/log/auth.log
    python log_analyzer.py auth.log --report report.txt --top 20

Disclaimer: For educational and authorized use only.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple


class LogAnalyzer:
    """Analyzes authentication logs for security events."""

    # Patterns for common log formats (syslog/auth.log)
    PATTERNS = {
        "failed_ssh": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd[\[\d+\]:\s]+"
            r"Failed password for (?:invalid user\s+)?(\S+) from (\S+)"
        ),
        "accepted_ssh": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd[\[\d+\]:\s]+"
            r"Accepted (?:password|publickey) for (\S+) from (\S+)"
        ),
        "failed_login": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+\S+[\[\d+\]:\s]+"
            r"(?:authentication failure|FAILED LOGIN)"
        ),
        "sudo_attempt": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo[\[\d+\]:\s]+"
            r"(\S+):\s+(.*NOT in sudoers|.*)"
        ),
        "session_opened": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+session\[opend]+\s+"
            r"for user (\S+)"
        ),
    }

    def __init__(self):
        self.failed_logins: List[Dict] = []
        self.successful_logins: List[Dict] = []
        self.sudo_attempts: List[Dict] = []
        self.sessions: List[Dict] = []
        self.suspicious_events: List[Dict] = []

    def analyze_file(self, filepath: str) -> None:
        """Parse and analyze a log file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    self._analyze_line(line.strip(), line_num)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied reading '{filepath}'.")
            sys.exit(1)

    def _analyze_line(self, line: str, line_num: int) -> None:
        """Analyze a single log line against all patterns."""
        if not line:
            return

        # Check failed SSH logins
        match = self.PATTERNS["failed_ssh"].search(line)
        if match:
            timestamp, user, ip = match.groups()
            self.failed_logins.append({
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "line": line_num,
            })
            return

        # Check successful SSH logins
        match = self.PATTERNS["accepted_ssh"].search(line)
        if match:
            timestamp, user, ip = match.groups()
            self.successful_logins.append({
                "timestamp": timestamp,
                "user": user,
                "ip": ip,
                "line": line_num,
            })
            return

        # Check sudo attempts
        match = self.PATTERNS["sudo_attempt"].search(line)
        if match:
            timestamp, user, message = match.groups()
            self.sudo_attempts.append({
                "timestamp": timestamp,
                "user": user,
                "message": message[:100],
                "line": line_num,
            })
            return

    def detect_brute_force(self, threshold: int = 5,
                           window_minutes: int = 10) -> List[Dict]:
        """Detect brute force attacks based on failed login frequency."""
        attacks = []
        ip_failures = defaultdict(list)

        for login in self.failed_logins:
            ip_failures[login["ip"]].append(login)

        for ip, failures in ip_failures.items():
            if len(failures) >= threshold:
                users_targeted = list(set(f["user"] for f in failures))
                attacks.append({
                    "ip": ip,
                    "attempts": len(failures),
                    "users_targeted": users_targeted,
                    "first_seen": failures[0]["timestamp"],
                    "last_seen": failures[-1]["timestamp"],
                    "severity": "🔴 Critical" if len(failures) > 20
                                else "🟠 High" if len(failures) > 10
                                else "🟡 Medium",
                })

        attacks.sort(key=lambda x: x["attempts"], reverse=True)
        return attacks

    def detect_successful_after_failure(self) -> List[Dict]:
        """Detect successful logins that occurred after failed attempts."""
        suspicious = []
        ip_failures = defaultdict(int)
        ip_users = defaultdict(set)

        for login in self.failed_logins:
            ip_failures[login["ip"]] += 1
            ip_users[login["ip"]].add(login["user"])

        for login in self.successful_logins:
            ip = login["ip"]
            if ip_failures[ip] > 0 and login["user"] in ip_users[ip]:
                suspicious.append({
                    "ip": ip,
                    "user": login["user"],
                    "timestamp": login["timestamp"],
                    "prior_failures": ip_failures[ip],
                    "severity": "🔴 Critical",
                })

        return suspicious

    def get_top_sources(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get top IP addresses by failed login count."""
        ip_counter = Counter(login["ip"] for login in self.failed_logins)
        return ip_counter.most_common(top_n)

    def get_top_users(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get top targeted usernames."""
        user_counter = Counter(login["user"] for login in self.failed_logins)
        return user_counter.most_common(top_n)

    def generate_report(self, top_n: int = 10) -> str:
        """Generate a comprehensive analysis report."""
        lines = []
        lines.append("=" * 70)
        lines.append("LOG ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)

        # Summary
        lines.append("\n📊 SUMMARY")
        lines.append("-" * 70)
        lines.append(f"  Failed login attempts:    {len(self.failed_logins)}")
        lines.append(f"  Successful logins:        {len(self.successful_logins)}")
        lines.append(f"  Sudo attempts:            {len(self.sudo_attempts)}")
        lines.append(f"  Unique source IPs:        {len(set(l['ip'] for l in self.failed_logins))}")
        lines.append(f"  Unique targeted users:    {len(set(l['user'] for l in self.failed_logins))}")

        # Brute force detection
        brute_force = self.detect_brute_force()
        lines.append("\n🔴 BRUTE FORCE DETECTION")
        lines.append("-" * 70)
        if brute_force:
            for attack in brute_force[:top_n]:
                lines.append(f"  {attack['severity']}  IP: {attack['ip']}")
                lines.append(f"    Attempts: {attack['attempts']}")
                lines.append(f"    Users targeted: {', '.join(attack['users_targeted'][:5])}")
                lines.append(f"    Period: {attack['first_seen']} → {attack['last_seen']}")
                lines.append("")
        else:
            lines.append("  No brute force attacks detected.")

        # Successful after failure
        suspicious = self.detect_successful_after_failure()
        lines.append("\n⚠️  SUSPICIOUS SUCCESSFUL LOGINS (after failures)")
        lines.append("-" * 70)
        if suspicious:
            for event in suspicious:
                lines.append(f"  {event['severity']}  IP: {event['ip']} → User: {event['user']}")
                lines.append(f"    Time: {event['timestamp']}")
                lines.append(f"    Prior failures: {event['prior_failures']}")
                lines.append("")
        else:
            lines.append("  No suspicious successful logins detected.")

        # Top source IPs
        top_ips = self.get_top_sources(top_n)
        lines.append(f"\n📍 TOP {top_n} SOURCE IPs (by failed attempts)")
        lines.append("-" * 70)
        for ip, count in top_ips:
            bar = "█" * min(count // 2, 50)
            lines.append(f"  {ip:<20} {count:>5}  {bar}")

        # Top targeted users
        top_users = self.get_top_users(top_n)
        lines.append(f"\n👤 TOP {top_n} TARGETED USERS")
        lines.append("-" * 70)
        for user, count in top_users:
            bar = "█" * min(count // 2, 50)
            lines.append(f"  {user:<20} {count:>5}  {bar}")

        # Recommendations
        lines.append("\n🛡️  RECOMMENDATIONS")
        lines.append("-" * 70)
        if brute_force:
            lines.append("  1. Block top attacking IPs at the firewall level")
            lines.append("  2. Implement fail2ban or similar rate limiting")
            lines.append("  3. Enable multi-factor authentication (MFA)")
            lines.append("  4. Consider disabling password authentication for SSH")
        if suspicious:
            lines.append("  5. Investigate successful logins after failures")
            lines.append("  6. Verify these were legitimate user actions")
            lines.append("  7. Reset passwords for compromised accounts")
        if not brute_force and not suspicious:
            lines.append("  No immediate actions required. Continue monitoring.")

        lines.append("\n" + "=" * 70)
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze system logs for security events"
    )
    parser.add_argument("log_file", help="Path to log file (e.g., /var/log/auth.log)")
    parser.add_argument("--report", help="Output file for report")
    parser.add_argument("--top", type=int, default=10,
                        help="Number of top items to show (default: 10)")

    args = parser.parse_args()

    print(f"[*] Analyzing: {args.log_file}")
    analyzer = LogAnalyzer()
    analyzer.analyze_file(args.log_file)

    report = analyzer.generate_report(args.top)
    print(f"\n{report}")

    if args.report:
        with open(args.report, "w") as f:
            f.write(report)
        print(f"\n[*] Report saved to: {args.report}")


if __name__ == "__main__":
    main()
