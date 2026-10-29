#!/usr/bin/env python3
"""
Phishing Email Detector — Analyzes emails for phishing indicators.

Detects:
- Suspicious sender addresses (domain spoofing, typosquatting)
- Urgency and manipulation language
- Suspicious URLs (mismatched display text, shorteners)
- Attachment risk assessment
- Social engineering patterns

Usage:
    python phishing_detector.py <email_file.eml> [--detailed]
    python phishing_detector.py --text "Paste email text here"

Examples:
    python phishing_detector.py suspicious.eml
    python phishing_detector.py suspicious.eml --detailed
    echo "Click here now: http://evil.com" | python phishing_detector.py --stdin

Disclaimer: For educational and authorized use only.
"""

import argparse
import re
import sys
from email import parser as email_parser
from email.header import decode_header
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class PhishingDetector:
    """Analyzes email content for phishing indicators."""

    # Urgency and manipulation keywords
    URGENCY_KEYWORDS = [
        "urgent", "immediate action", "act now", "last chance",
        "expire", "expired", "suspended", "suspension", "blocked",
        "block", "verify now", "confirm now", "update now",
        "action required", "account compromised", "unusual activity",
        "security alert", "final notice", "deadline", "today",
        "within 24 hours", "within 48 hours", "limited time",
    ]

    # Threat and fear keywords
    THREAT_KEYWORDS = [
        "your account will be closed", "permanent loss",
        "legal action", "law enforcement", "police",
        "arrest", "fine", "penalty", "consequence",
        "terminate", "termination", "disable", "disabled",
    ]

    # Common typosquatted domains
    TYPOSQUAT_DOMAINS = {
        "gmal.com": "gmail.com",
        "gmai.com": "gmail.com",
        "gmial.com": "gmail.com",
        "yahooo.com": "yahoo.com",
        "yaho.com": "yahoo.com",
        "hotmal.com": "hotmail.com",
        "hotmai.com": "hotmail.com",
        "outlok.com": "outlook.com",
        "outloo.com": "outlook.com",
        "facebok.com": "facebook.com",
        "faceook.com": "facebook.com",
        "paypa.com": "paypal.com",
        "paypai.com": "paypal.com",
        "appie.com": "apple.com",
        "amzon.com": "amazon.com",
        "amazen.com": "amazon.com",
        "microsft.com": "microsoft.com",
        "microsof.com": "microsoft.com",
    }

    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".work", ".click", ".link", ".info", ".biz",
    ]

    # URL shorteners
    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
        "short.link", "goo.gl", "is.gd",
    ]

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jar", ".dll", ".msi", ".hta", ".lnk",
        ".rtf", ".docm", ".xlsm", ".htm", ".html",
    ]

    def __init__(self):
        self.score = 0
        self.max_score = 100
        self.findings: List[Dict] = []
        self.email_data: Dict = {}

    def analyze_eml_file(self, filepath: str) -> Dict:
        """Parse and analyze an .eml file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                msg = email_parser.Parser().parse(f)
            return self._analyze_message(msg)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)

    def analyze_text(self, text: str) -> Dict:
        """Analyze raw email text."""
        self.email_data = {
            "subject": "",
            "from": "",
            "to": "",
            "body": text,
            "html_body": "",
            "urls": [],
            "attachments": [],
        }
        self._run_checks()
        return self._build_result()

    def _analyze_message(self, msg) -> Dict:
        """Extract data from email message and run checks."""
        self.email_data = {
            "subject": self._decode_header(msg.get("Subject", "")),
            "from": self._decode_header(msg.get("From", "")),
            "to": self._decode_header(msg.get("To", "")),
            "body": "",
            "html_body": "",
            "urls": [],
            "attachments": [],
        }

        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True)
                        if body:
                            self.email_data["body"] = body.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True)
                        if body:
                            self.email_data["html_body"] = body.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                elif "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        self.email_data["attachments"].append(
                            self._decode_header(filename)
                        )
        else:
            try:
                body = msg.get_payload(decode=True)
                if body:
                    self.email_data["body"] = body.decode("utf-8", errors="ignore")
            except Exception:
                pass

        # Extract URLs from body
        full_text = self.email_data["body"] + self.email_data["html_body"]
        urls = re.findall(r'https?://\S+', full_text, re.IGNORECASE)
        self.email_data["urls"] = list(set(urls))

        self._run_checks()
        return self._build_result()

    def _run_checks(self) -> None:
        """Run all phishing detection checks."""
        self._check_sender()
        self._check_subject()
        self._check_body_content()
        self._check_urls()
        self._check_attachments()

    def _check_sender(self) -> None:
        """Check sender address for spoofing indicators."""
        sender = self.email_data.get("from", "")
        if not sender:
            return

        # Check for typosquatted domains
        domain = re.search(r"@(\S+)", sender)
        if domain:
            domain = domain.group(1).lower().rstrip(">")
            for fake, real in self.TYPOSQUAT_DOMAINS.items():
                if fake in domain:
                    self.score += 25
                    self.findings.append({
                        "category": "Sender Spoofing",
                        "severity": "🔴 Critical",
                        "score": 25,
                        "detail": f"Typosquatted domain detected: '{domain}' → likely '{real}'",
                    })

        # Check for mismatched display name and domain
        display_match = re.match(r'"([^"]+)"<([^>]+)>', sender)
        if display_match:
            display_name = display_match.group(1).lower()
            email_addr = display_match.group(2).lower()

            # Check if display name claims to be a brand but domain doesn't match
            brands = ["apple", "microsoft", "google", "amazon", "paypal",
                      "facebook", "netflix", "bank", "hr", "human resources"]
            for brand in brands:
                if brand in display_name and brand not in email_addr:
                    self.score += 15
                    self.findings.append({
                        "category": "Sender Spoofing",
                        "severity": "🟠 High",
                        "score": 15,
                        "detail": f"Display name '{display_name}' doesn't match domain '{email_addr}'",
                    })

        # Check for free email domain in business context
        free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        for fd in free_domains:
            if fd in sender.lower():
                subject = self.email_data.get("subject", "").lower()
                if any(word in subject for word in ["invoice", "payment", "salary", "hr"]):
                    self.score += 10
                    self.findings.append({
                        "category": "Sender Risk",
                        "severity": "🟡 Medium",
                        "score": 10,
                        "detail": f"Business email sent from free email provider",
                    })

    def _check_subject(self) -> None:
        """Check subject line for phishing indicators."""
        subject = self.email_data.get("subject", "").lower()
        if not subject:
            return

        urgency_count = sum(1 for kw in self.URGENCY_KEYWORDS if kw in subject)
        if urgency_count >= 2:
            self.score += 15
            self.findings.append({
                "category": "Urgency",
                "severity": "🟠 High",
                "score": 15,
                "detail": f"Multiple urgency keywords in subject ({urgency_count} found)",
            })
        elif urgency_count == 1:
            self.score += 5
            self.findings.append({
                "category": "Urgency",
                "severity": "🟡 Medium",
                "score": 5,
                "detail": "Urgency keyword found in subject line",
            })

        threat_count = sum(1 for kw in self.THREAT_KEYWORDS if kw in subject)
        if threat_count > 0:
            self.score += 20
            self.findings.append({
                "category": "Threat/Fear",
                "severity": "🔴 Critical",
                "score": 20,
                "detail": f"Threat keywords in subject ({threat_count} found)",
            })

    def _check_body_content(self) -> None:
        """Check email body for social engineering patterns."""
        body = (self.email_data.get("body", "") +
                self.email_data.get("html_body", "")).lower()
        if not body:
            return

        # Strip HTML tags for text analysis
        body_text = re.sub(r"<[^>]+>", " ", body)

        urgency_count = sum(1 for kw in self.URGENCY_KEYWORDS if kw in body_text)
        if urgency_count >= 3:
            self.score += 15
            self.findings.append({
                "category": "Social Engineering",
                "severity": "🟠 High",
                "score": 15,
                "detail": f"High urgency language in body ({urgency_count} keywords)",
            })
        elif urgency_count >= 1:
            self.score += 5
            self.findings.append({
                "category": "Social Engineering",
                "severity": "🟡 Medium",
                "score": 5,
                "detail": f"Urgency language in body ({urgency_count} keywords)",
            })

        # Check for credential requests
        credential_patterns = [
            "enter your password", "login to verify", "confirm your account",
            "update your password", "verify your identity", "click here to verify",
            "enter your credentials", "sign in now",
        ]
        for pattern in credential_patterns:
            if pattern in body_text:
                self.score += 15
                self.findings.append({
                    "category": "Credential Harvesting",
                    "severity": "🔴 Critical",
                    "score": 15,
                    "detail": f"Credential request detected: '{pattern}'",
                })

        # Check for mismatched URLs in HTML
        html_body = self.email_data.get("html_body", "")
        if html_body:
            link_pattern = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',
                                      html_body, re.IGNORECASE)
            for href, text in link_pattern:
                href_domain = urlparse(href).netloc.lower()
                text_lower = text.lower().strip()
                if text_lower and href_domain and text_lower not in href_domain:
                    self.score += 10
                    self.findings.append({
                        "category": "URL Mismatch",
                        "severity": "🟠 High",
                        "score": 10,
                        "detail": f"Link text '{text}' doesn't match URL domain '{href_domain}'",
                    })

    def _check_urls(self) -> None:
        """Check URLs for suspicious patterns."""
        urls = self.email_data.get("urls", [])
        if not urls:
            return

        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check for URL shorteners
            for shortener in self.URL_SHORTENERS:
                if shortener in domain:
                    self.score += 10
                    self.findings.append({
                        "category": "Suspicious URL",
                        "severity": "🟠 High",
                        "score": 10,
                        "detail": f"URL shortener detected: {url}",
                    })
                    break

            # Check for suspicious TLDs
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    self.score += 5
                    self.findings.append({
                        "category": "Suspicious URL",
                        "severity": "🟡 Medium",
                        "score": 5,
                        "detail": f"Suspicious TLD in URL: {url}",
                    })
                    break

            # Check for IP addresses instead of domains
            ip_pattern = re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)
            if ip_pattern:
                self.score += 15
                self.findings.append({
                    "category": "Suspicious URL",
                    "severity": "🟠 High",
                    "score": 15,
                    "detail": f"IP address used instead of domain: {url}",
                })

            # Check for typosquatted domains in URLs
            for fake, real in self.TYPOSQUAT_DOMAINS.items():
                if fake in domain:
                    self.score += 20
                    self.findings.append({
                        "category": "Typosquatting",
                        "severity": "🔴 Critical",
                        "score": 20,
                        "detail": f"Typosquatted domain in URL: '{domain}' → '{real}'",
                    })

    def _check_attachments(self) -> None:
        """Check attachments for suspicious file types."""
        attachments = self.email_data.get("attachments", [])
        if not attachments:
            return

        for filename in attachments:
            filename_lower = filename.lower()
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if filename_lower.endswith(ext):
                    self.score += 15
                    self.findings.append({
                        "category": "Suspicious Attachment",
                        "severity": "🟠 High",
                        "score": 15,
                        "detail": f"Potentially dangerous attachment: {filename}",
                    })
                    break

    def _build_result(self) -> Dict:
        """Build the analysis result."""
        self.score = min(self.score, self.max_score)

        if self.score >= 70:
            risk_level = "🔴 CRITICAL — Likely Phishing"
        elif self.score >= 40:
            risk_level = "🟠 HIGH — Suspicious"
        elif self.score >= 20:
            risk_level = "🟡 MEDIUM — Review Recommended"
        else:
            risk_level = "🟢 LOW — Appears Safe"

        return {
            "score": self.score,
            "risk_level": risk_level,
            "findings": self.findings,
            "email_data": self.email_data,
        }

    def _decode_header(self, header: str) -> str:
        """Decode email header."""
        if not header:
            return ""
        decoded_parts = decode_header(header)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="ignore"))
            else:
                result.append(part)
        return "".join(result)

    def print_report(self, result: Dict, detailed: bool = False) -> None:
        """Print analysis report."""
        lines = []
        lines.append("=" * 60)
        lines.append("PHISHING EMAIL ANALYSIS REPORT")
        lines.append("=" * 60)

        # Email info
        lines.append("\n📧 EMAIL DETAILS")
        lines.append("-" * 60)
        lines.append(f"  From: {result['email_data'].get('from', 'N/A')}")
        lines.append(f"  To: {result['email_data'].get('to', 'N/A')}")
        lines.append(f"  Subject: {result['email_data'].get('subject', 'N/A')}")
        lines.append(f"  URLs found: {len(result['email_data'].get('urls', []))}")
        lines.append(f"  Attachments: {len(result['email_data'].get('attachments', []))}")

        # Risk score
        lines.append(f"\n🎯 RISK SCORE: {result['score']}/100")
        lines.append(f"   Assessment: {result['risk_level']}")

        # Score bar
        filled = int(result['score'] / 5)
        bar = "█" * filled + "░" * (20 - filled)
        lines.append(f"   [{bar}] {result['score']}%")

        # Findings
        lines.append(f"\n🔍 FINDINGS ({len(result['findings'])} issues)")
        lines.append("-" * 60)
        if result['findings']:
            for i, finding in enumerate(result['findings'], 1):
                lines.append(f"  {i}. {finding['severity']}  {finding['category']}")
                lines.append(f"     {finding['detail']}")
                if detailed:
                    lines.append(f"     Score impact: +{finding['score']}")
                lines.append("")
        else:
            lines.append("  No phishing indicators detected.")

        # Recommendations
        lines.append("🛡️  RECOMMENDATIONS")
        lines.append("-" * 60)
        if result['score'] >= 70:
            lines.append("  ⚠️  DO NOT click any links or open attachments")
            lines.append("  ⚠️  Report this email to your IT security team")
            lines.append("  ⚠️  Delete the email after reporting")
        elif result['score'] >= 40:
            lines.append("  ⚠️  Exercise extreme caution")
            lines.append("  ⚠️  Verify the sender through a separate channel")
            lines.append("  ⚠️  Do not enter credentials or sensitive data")
        elif result['score'] >= 20:
            lines.append("  ℹ️  Review the email carefully")
            lines.append("  ℹ️  Verify sender identity if unsure")
        else:
            lines.append("  ✅  Email appears safe, but stay vigilant")

        lines.append("\n" + "=" * 60)
        print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Analyze emails for phishing indicators"
    )
    parser.add_argument("email_file", nargs="?", help="Path to .eml file")
    parser.add_argument("--text", help="Email text to analyze")
    parser.add_argument("--detailed", action="store_true",
                        help="Show detailed scoring")

    args = parser.parse_args()

    detector = PhishingDetector()

    if args.email_file:
        result = detector.analyze_eml_file(args.email_file)
    elif args.text:
        result = detector.analyze_text(args.text)
    else:
        # Read from stdin
        text = sys.stdin.read()
        if text.strip():
            result = detector.analyze_text(text)
        else:
            parser.print_help()
            sys.exit(1)

    detector.print_report(result, args.detailed)


if __name__ == "__main__":
    main()
