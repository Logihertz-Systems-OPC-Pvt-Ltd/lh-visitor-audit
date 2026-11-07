# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        src.lh_visitor_audit.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-visitor-audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for visitor telemetry audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


@dataclass
class VisitorRecord:
    """Ingested visitor traffic log entry or telemetry event."""

    timestamp: str = ""
    ip_address: str = ""
    location: str = "Unknown"
    device: str = "Unknown"
    page: str = ""
    referrer: str = ""
    user_agent: str = ""
    status_code: int = 200
    method: str = "GET"
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Security finding or anomaly identified in visitor traffic."""

    rule_id: str
    severity: FindingSeverity
    category: str
    ip_address: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated audit report for inspected visitor traffic."""

    target: str
    files_scanned: int = 0
    records_analyzed: int = 0
    unique_ips: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for visitor audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-VIS-001": AuditRuleDefinition(
        rule_id="LH-VIS-001",
        title="Sensitive File & Repository Probing",
        severity=FindingSeverity.CRITICAL,
        category="Repository & Configuration Exposure",
        description=(
            "Visitor telemetry targets sensitive files including .git/config, .env, wp-config.php, "
            ".aws/credentials, or backup archives (.bak, .sql, .zip)."
        ),
        remediation=(
            "Block probing IPs at WAF, restrict public access to hidden directories, and purge "
            "exposed repository or configuration files from web root."
        ),
    ),
    "LH-VIS-002": AuditRuleDefinition(
        rule_id="LH-VIS-002",
        title="High-Velocity Credential Stuffing & Brute-Force Burst",
        severity=FindingSeverity.CRITICAL,
        category="Authentication Abuse & Brute-Force",
        description=(
            "Rapid sequential visitor requests targeting login, authentication, admin, or "
            "token API endpoints from a single IP source."
        ),
        remediation=(
            "Enforce strict per-IP rate limiting, adaptive CAPTCHA challenges, and automated "
            "temporary IP blocks on repeated auth failures."
        ),
    ),
    "LH-VIS-003": AuditRuleDefinition(
        rule_id="LH-VIS-003",
        title="Automated Vulnerability Scanner Footprint",
        severity=FindingSeverity.HIGH,
        category="Offensive Reconnaissance & Scanning",
        description=(
            "Traffic matches signatures of automated vulnerability scanning tools (sqlmap, nikto, "
            "nuclei, nmap, gobuster, dirbuster, zgrab, masscan) or traversal sweeps."
        ),
        remediation=(
            "Deploy edge WAF rules to block known offensive scanner User-Agents and generic "
            "path fuzzing probes."
        ),
    ),
    "LH-VIS-004": AuditRuleDefinition(
        rule_id="LH-VIS-004",
        title="Subdomain & Virtual Host Enumeration Sweep",
        severity=FindingSeverity.HIGH,
        category="Perimeter Reconnaissance & Virtual Host Probing",
        description=(
            "Single IP systematically probing multiple distinct subdomains or virtual host "
            "prefixes in rapid succession."
        ),
        remediation=(
            "Disable wildcard DNS routing where unneeded, sinkhole unrecognized host headers, and "
            "rate limit domain sweeps."
        ),
    ),
    "LH-VIS-005": AuditRuleDefinition(
        rule_id="LH-VIS-005",
        title="Device / User-Agent Fingerprint Rotation (Spoofing)",
        severity=FindingSeverity.HIGH,
        category="Session Spoofing & Fingerprint Evasion",
        description=(
            "Single IP address rapidly rotating across contradictory device types (Desktop vs "
            "Mobile) or mutually exclusive operating systems."
        ),
        remediation=(
            "Implement browser fingerprint consistency checks and session binding to prevent "
            "adversarial User-Agent rotation."
        ),
    ),
    "LH-VIS-006": AuditRuleDefinition(
        rule_id="LH-VIS-006",
        title="Unresolved / Anonymized GeoIP Traffic Spike",
        severity=FindingSeverity.MEDIUM,
        category="Anonymized Infrastructure & Geolocation Anomaly",
        description=(
            "High-volume visitor bursts originating from unresolved or anonymized proxy, VPN, "
            "or Tor exit nodes."
        ),
        remediation=(
            "Inspect anonymized proxy traffic with challenge pages and review GeoIP database "
            "resolution health."
        ),
    ),
    "LH-VIS-007": AuditRuleDefinition(
        rule_id="LH-VIS-007",
        title="Suspicious Referrer Injection or Cleartext Downgrade",
        severity=FindingSeverity.HIGH,
        category="Traffic Tampering & Injection",
        description=(
            "Visitor telemetry includes injected script tags or SQL syntax in Referrer headers, "
            "or cleartext http:// downgrades on sensitive routes."
        ),
        remediation=(
            "Enforce strict Referrer-Policy (strict-origin-when-cross-origin), sanitize incoming "
            "telemetry headers, and drop malformed requests."
        ),
    ),
    "LH-VIS-008": AuditRuleDefinition(
        rule_id="LH-VIS-008",
        title="Headless Automation, Scraper Bot, or Obsolete Botnet User-Agent",
        severity=FindingSeverity.MEDIUM,
        category="Botnet & Automated Scraping",
        description=(
            "Visitor requests utilize headless automation frameworks (HeadlessChrome, Playwright, "
            "Selenium, curl, python-requests) or obsolete browser versions."
        ),
        remediation=(
            "Require client-side JavaScript execution validation or challenge checks for headless "
            "clients, and throttle scraper bots."
        ),
    ),
    "LH-VIS-009": AuditRuleDefinition(
        rule_id="LH-VIS-009",
        title="Robots.txt Reconnaissance Followed by Sensitive Path Probing",
        severity=FindingSeverity.MEDIUM,
        category="Automated Crawler Reconnaissance",
        description=(
            "Visitor IP inspected robots.txt or sitemap.xml and subsequently probed restricted "
            "or disallowed application directories."
        ),
        remediation=(
            "Avoid listing high-risk sensitive paths in robots.txt disallow directives; protect "
            "sensitive endpoints with strict authentication instead."
        ),
    ),
    "LH-VIS-010": AuditRuleDefinition(
        rule_id="LH-VIS-010",
        title="Missing User-Agent or Malformed Visitor Telemetry",
        severity=FindingSeverity.LOW,
        category="Telemetry Hygiene & Evasion",
        description=(
            "Visitor telemetry records contain empty or missing User-Agent strings, missing "
            "referrers, or unparseable IP/timestamp data."
        ),
        remediation=(
            "Enforce mandatory User-Agent headers at the edge reverse proxy and drop requests with "
            "blank or hyphen-only client agents."
        ),
    ),
}
