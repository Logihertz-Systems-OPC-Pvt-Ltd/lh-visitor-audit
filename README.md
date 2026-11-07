# lh-visitor-audit

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-visitor-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-visitor-audit/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise web traffic telemetry & bot probe analyzer developed by **Logihertz Systems (OPC) Private Limited**.

Analyzes HTTP access logs (Combined/JSON/CloudFront/Cloudflare) to detect directory brute-forcing, vulnerability scanner fingerprints (Nuclei/Nikto/SQLMap), credential stuffing bursts, and anomalous L7 scraping velocity.

---

## Key Features

- **Multi-Format Log Ingestion**: High-performance streaming parser for Nginx, Apache, Cloudflare, and custom telemetry log files.
- **Automated Scanner Footprint Detection**: Identifies probing by offensive scanners (Sqlmap, Nikto, Nmap, Nuclei, Gobuster).
- **Sensitive Path & Dotfile Probing**: Detects enumeration targeting `/.git/`, `/.env`, `wp-config.php`, `/actuator`, and backup archives.
- **Credential Stuffing & Brute-Force Bursts**: Correlates client IPs, request velocity, and 401/403 status spikes within sliding windows.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-VIS-001` | `CRITICAL` | Sensitive File & Repository Probing — visitor requests targeting /.git/, /.env, or config files |
| `LH-VIS-002` | `CRITICAL` | High-Velocity Credential Stuffing Burst — rapid failed auth responses (401/403) from single origin |
| `LH-VIS-003` | `HIGH` | Automated Vulnerability Scanner Footprint — offensive scanner User-Agents (sqlmap, nikto, nuclei) |
| `LH-VIS-004` | `HIGH` | Subdomain & Virtual Host Enumeration Sweep — single IP sweeping multiple unmapped Host headers |
| `LH-VIS-005` | `HIGH` | Device / User-Agent Fingerprint Rotation — rapid rotating User-Agents from identical client IP |
| `LH-VIS-006` | `MEDIUM` | Unresolved / Anonymized GeoIP Traffic Spike — high-velocity requests from Tor exit nodes or proxies |
| `LH-VIS-007` | `HIGH` | Suspicious Referrer Injection or Downgrade — malicious payloads embedded in Referer header |
| `LH-VIS-008` | `MEDIUM` | Headless Automation or Scraper Bot — requests from automated scraper frameworks |
| `LH-VIS-009` | `MEDIUM` | Robots.txt Reconnaissance Followed by Path Probing — scraping disallow paths immediately after robots.txt |
| `LH-VIS-010` | `LOW` | Missing User-Agent or Malformed Visitor Telemetry — requests with blank or non-standard User-Agent |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-visitor-audit.git
cd lh-visitor-audit

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-visitor` (also accessible via `lh-visitor`, `lh-visitor-audit`).

```bash
# Scan a web server access log for reconnaissance attacks
lh-visitor scan /var/log/nginx/access.log

# Analyze visitor traffic logs in JSONL format
lh-visitor scan traffic.jsonl --format json

# Export findings to OASIS SARIF v2.1.0
lh-visitor scan access.log --format sarif --output visitor-results.sarif

# Filter by minimum severity threshold
lh-visitor scan access.log --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
