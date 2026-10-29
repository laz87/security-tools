# Security Tools

> **Author:** laz87 | **Location:** Nairobi, Kenya | **Focus:** Security Automation & Tooling

## Overview

Python-based security automation tools for common security tasks. These scripts demonstrate practical security engineering skills and can be used in a home lab or adapted for organizational use.

## Tools

| Tool | Description | File |
|------|-------------|------|
| **Port Scanner** | Multi-threaded network port scanner with service detection | `port_scanner.py` |
| **Log Analyzer** | Analyzes system logs for failed login attempts and suspicious patterns | `log_analyzer.py` |
| **Phishing Detector** | Analyzes emails for phishing indicators (URLs, sender, urgency) | `phishing_detector.py` |

## Setup

```bash
# Clone the repository
git clone https://github.com/laz87/security-tools.git
cd security-tools

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Port Scanner

```bash
# Scan a single host
python port_scanner.py 192.168.1.1

# Scan with custom port range
python port_scanner.py 192.168.1.1 --ports 1-1024

# Scan with output file
python port_scanner.py 192.168.1.1 --output scan_results.txt
```

### Log Analyzer

```bash
# Analyze auth log
python log_analyzer.py /var/log/auth.log

# Analyze with report output
python log_analyzer.py /var/log/auth.log --report report.html
```

### Phishing Detector

```bash
# Analyze an email file
python phishing_detector.py email.eml

# Analyze with detailed report
python phishing_detector.py email.eml --detailed
```

## Disclaimer

These tools are for **educational and authorized use only**. Always obtain proper authorization before scanning networks or analyzing systems you do not own.

## Learning Outcomes

- Network reconnaissance and service discovery
- Log analysis and threat detection
- Email security and phishing analysis
- Python scripting for security automation
- Multi-threading and performance optimization
