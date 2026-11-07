# Security Rules Reference: lh-visitor-audit

An enterprise visitor traffic & perimeter reconnaissance analyzer developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-visitor-audit`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-VIS-001` | `CRITICAL` | Reconnaissance | Sensitive File & Repository Probing Detected |
| `LH-VIS-002` | `CRITICAL` | Brute Force | High-Velocity Credential Stuffing Burst |
| `LH-VIS-003` | `HIGH` | Reconnaissance | Automated Vulnerability Scanner Footprint Detected |
| `LH-VIS-004` | `HIGH` | Reconnaissance | Subdomain & Virtual Host Enumeration Sweep |
| `LH-VIS-005` | `HIGH` | Evasion | Rapid User-Agent / Fingerprint Rotation from Single IP |
| `LH-VIS-006` | `MEDIUM` | Anomaly | Unresolved or Anonymized GeoIP Traffic Spike |
| `LH-VIS-007` | `HIGH` | Web Attack | Suspicious Referrer Injection or Downgrade Attack |
| `LH-VIS-008` | `MEDIUM` | Bot Scraping | Headless Automation or Scraper Bot Detected |
| `LH-VIS-009` | `MEDIUM` | Reconnaissance | Robots.txt Reconnaissance Followed by Path Probing |
| `LH-VIS-010` | `LOW` | Telemetry | Missing User-Agent or Malformed Visitor Telemetry |

---

## Granular Rule Specifications

### `LH-VIS-001`: Sensitive File & Repository Probing Detected

- **Severity**: `CRITICAL`
- **Category**: `Reconnaissance`
- **Description**: Visitor requests targeting sensitive dotfiles (/.git, /.env, wp-config.php, /actuator).
- **Remediation**: Block scanning IP addresses at perimeter firewall and return immediate 403 Forbidden.

---

### `LH-VIS-002`: High-Velocity Credential Stuffing Burst

- **Severity**: `CRITICAL`
- **Category**: `Brute Force`
- **Description**: Rapid failed authentication responses (401/403) from single origin within sliding window.
- **Remediation**: Enforce automated temporary IP bans and deploy CAPTCHA challenge on authentication routes.

---

### `LH-VIS-003`: Automated Vulnerability Scanner Footprint Detected

- **Severity**: `HIGH`
- **Category**: `Reconnaissance`
- **Description**: Offensive vulnerability scanner User-Agents (sqlmap, nikto, nuclei, gobuster) in logs.
- **Remediation**: Drop automated scanner User-Agents at edge reverse proxy and blacklist offending subnets.

---

### `LH-VIS-004`: Subdomain & Virtual Host Enumeration Sweep

- **Severity**: `HIGH`
- **Category**: `Reconnaissance`
- **Description**: Single client IP sweeping multiple distinct virtual host headers within short interval.
- **Remediation**: Configure web server to reject unrecognized Host headers with 421 Misdirected Request.

---

### `LH-VIS-005`: Rapid User-Agent / Fingerprint Rotation from Single IP

- **Severity**: `HIGH`
- **Category**: `Evasion`
- **Description**: Client IP rapidly cycling through dozens of disparate User-Agent strings to evade rate limits.
- **Remediation**: Key rate limits on client TLS fingerprints (JA3/JA4) or IP subnets rather than User-Agent alone.

---

### `LH-VIS-006`: Unresolved or Anonymized GeoIP Traffic Spike

- **Severity**: `MEDIUM`
- **Category**: `Anomaly`
- **Description**: High-velocity traffic originating from known Tor exit nodes or commercial proxy networks.
- **Remediation**: Apply rate-limiting step-ups and bot verification on anonymized proxy traffic.

---

### `LH-VIS-007`: Suspicious Referrer Injection or Downgrade Attack

- **Severity**: `HIGH`
- **Category**: `Web Attack`
- **Description**: Malicious script payloads or SQL injection syntax embedded inside HTTP Referer header.
- **Remediation**: Sanitize and validate all incoming HTTP headers before logging or downstream processing.

---

### `LH-VIS-008`: Headless Automation or Scraper Bot Detected

- **Severity**: `MEDIUM`
- **Category**: `Bot Scraping`
- **Description**: Requests from automated browser frameworks (HeadlessChrome, Puppeteer, Scrapy).
- **Remediation**: Deploy challenge-response bot management (Cloudflare Turnstile) on scraping-prone routes.

---

### `LH-VIS-009`: Robots.txt Reconnaissance Followed by Path Probing

- **Severity**: `MEDIUM`
- **Category**: `Reconnaissance`
- **Description**: Client scrapes robots.txt and immediately probes disallowed administrative paths.
- **Remediation**: Deploy honeypot paths in robots.txt to identify and automatically ban offensive crawlers.

---

### `LH-VIS-010`: Missing User-Agent or Malformed Visitor Telemetry

- **Severity**: `LOW`
- **Category**: `Telemetry`
- **Description**: Visitor requests with blank, non-standard, or truncated User-Agent headers.
- **Remediation**: Reject HTTP requests lacking valid User-Agent header with 400 Bad Request at edge.

---
