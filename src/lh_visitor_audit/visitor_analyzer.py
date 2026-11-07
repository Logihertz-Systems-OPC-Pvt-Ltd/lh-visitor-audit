# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        src.lh_visitor_audit.visitor_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Visitor traffic analysis engine and anomaly detection rules."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from lh_visitor_audit.models import (
    RULES_REGISTRY,
    AuditFinding,
    AuditReport,
    FindingSeverity,
    VisitorRecord,
)
from lh_visitor_audit.traffic_parser import find_traffic_files, parse_traffic_file

# Offensive scanners and vulnerability inspection tools
SCANNER_UA_SIGNATURES = [
    "sqlmap",
    "nikto",
    "nuclei",
    "nmap",
    "gobuster",
    "dirbuster",
    "zgrab",
    "masscan",
    "wpscan",
    "acunetix",
    "nessus",
    "qualys",
    "openvas",
    "ffuf",
    "wfuzz",
]

# Sensitive paths and configurations
SENSITIVE_PROBE_PATTERNS = [
    "/.git/",
    "/.git",
    "/.env",
    ".env.",
    "wp-config.php",
    "/.aws/credentials",
    "/.aws/",
    "/.svn",
    "/.hg",
    "/.ds_store",
    "/.vscode",
    "web.config",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
]

SENSITIVE_BACKUP_EXTENSIONS = (
    ".bak",
    ".sql",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".7z",
    ".rar",
    ".old",
    ".orig",
)

# Authentication and login endpoints
AUTH_ENDPOINTS = [
    "/login",
    "/auth",
    "/signin",
    "/sign-in",
    "/authenticate",
    "/wp-login.php",
    "/admin",
    "/administrator",
    "/api/login",
    "/api/v1/auth",
    "/api/v1/login",
    "/oauth/token",
    "/session",
]

# Headless frameworks and programmatic scrapers
HEADLESS_SCRAPER_SIGNATURES = [
    "headlesschrome",
    "phantomjs",
    "playwright",
    "selenium",
    "curl/",
    "python-requests",
    "aiohttp",
    "scrapy",
    "httpx",
    "go-http-client",
    "java/",
    "libwww-perl",
    "wget/",
]

# Obsolete browser patterns
CHROME_VERSION_PATTERN = re.compile(r"Chrome/(\d+)\.")
IOS_VERSION_PATTERN = re.compile(r"(?:iPhone OS|iOS|CPU OS)\s*(\d+)[._]")
MSIE_PATTERN = re.compile(r"MSIE\s*([0-9.]+)")

# Injection patterns for referrer / user-agent
INJECTION_SIGNATURES = [
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "union select",
    "' or '1'='1",
    "../..",
    "${jndi:",
    "/etc/passwd",
    "cmd.exe",
    "phpinfo()",
]

# Sensitive routes for HTTP downgrade detection
SENSITIVE_ROUTES = (
    "/checkout",
    "/account",
    "/login",
    "/admin",
    "/payment",
    "/auth",
    "/settings",
    "/dashboard",
    "/cart",
)


def _is_valid_ip(ip_str: str) -> bool:
    """Validate IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def _extract_subdomain(url_or_page: str) -> str | None:
    """Extract subdomain prefix if present in URL or host prefix."""
    target = url_or_page.strip()
    if not target:
        return None

    if "://" not in target and not target.startswith("//"):
        if "/" in target:
            target = "http://" + target
        else:
            target = "http://" + target + "/"

    try:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        parts = host.split(".")
        if len(parts) >= 3:
            return parts[0]
    except Exception:  # nosec B110
        pass
    return None


class VisitorAnalyzer:
    """Rule engine for auditing visitor logs and telemetry."""

    def __init__(self, records: list[VisitorRecord]) -> None:
        self.records = records
        self.ip_groups: dict[str, list[VisitorRecord]] = {}
        for rec in records:
            ip = rec.ip_address.strip() or "UNKNOWN_IP"
            self.ip_groups.setdefault(ip, []).append(rec)

    def analyze(self) -> list[AuditFinding]:
        """Execute full rule inspection suite against grouped visitor telemetry."""
        findings: list[AuditFinding] = []

        findings.extend(self._check_lh_vis_001())
        findings.extend(self._check_lh_vis_002())
        findings.extend(self._check_lh_vis_003())
        findings.extend(self._check_lh_vis_004())
        findings.extend(self._check_lh_vis_005())
        findings.extend(self._check_lh_vis_006())
        findings.extend(self._check_lh_vis_007())
        findings.extend(self._check_lh_vis_008())
        findings.extend(self._check_lh_vis_009())
        findings.extend(self._check_lh_vis_010())

        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-001: Sensitive File & Repository Probing Detected (CRITICAL) ---
    # Evaluates security posture against sensitive file & repository probing
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_001(self) -> list[AuditFinding]:
        """LH-VIS-001 (CRITICAL): Sensitive File & Repository Probing."""
        rule = RULES_REGISTRY["LH-VIS-001"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            probed_paths: list[str] = []
            for r in recs:
                p_lower = r.page.lower()
                is_probe = False
                for pattern in SENSITIVE_PROBE_PATTERNS:
                    if pattern in p_lower:
                        is_probe = True
                        break
                if not is_probe:
                    clean_path = p_lower.split("?")[0]
                    if any(clean_path.endswith(ext) for ext in SENSITIVE_BACKUP_EXTENSIONS):
                        is_probe = True

                if is_probe and r.page not in probed_paths:
                    probed_paths.append(r.page)

            if probed_paths:
                evidence = (
                    f"Probed {len(probed_paths)} sensitive target(s): {', '.join(probed_paths[:5])}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} submitted requests targeting sensitive repositories, "
                            f"configuration files, or backup archives."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-002: High-Velocity Credential Stuffing Burst (CRITICAL) ---
    # Evaluates security posture against high-velocity credential stuffing burst.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_002(self) -> list[AuditFinding]:
        """LH-VIS-002 (CRITICAL): High-Velocity Credential Stuffing & Brute-Force Burst."""
        rule = RULES_REGISTRY["LH-VIS-002"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            auth_requests: list[str] = []
            for r in recs:
                p_lower = r.page.lower()
                if any(endpoint in p_lower for endpoint in AUTH_ENDPOINTS):
                    auth_requests.append(r.page)

            if len(auth_requests) >= 5:
                sample = ", ".join(auth_requests[:3])
                evidence = f"{len(auth_requests)} authentication requests detected (e.g., {sample})"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} launched high-velocity sequential requests against "
                            f"authentication and credential endpoints."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-003: Automated Vulnerability Scanner Footprint Detected (HIGH) ---
    # Evaluates security posture against automated vulnerability scanner footprint
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_003(self) -> list[AuditFinding]:
        """LH-VIS-003 (HIGH): Automated Vulnerability Scanner Footprint."""
        rule = RULES_REGISTRY["LH-VIS-003"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            scanner_matches: set[str] = set()
            traversal_probes: set[str] = set()

            for r in recs:
                ua_lower = r.user_agent.lower()
                for scanner in SCANNER_UA_SIGNATURES:
                    if scanner in ua_lower:
                        scanner_matches.add(scanner)

                p_lower = r.page.lower()
                for sig in [
                    "../../",
                    "<script",
                    "union select",
                    "cmd.exe",
                    "/etc/passwd",
                    "${jndi:",
                ]:
                    if sig in p_lower:
                        traversal_probes.add(sig)

            if scanner_matches or traversal_probes:
                ev_parts: list[str] = []
                if scanner_matches:
                    ev_parts.append(f"Scanner User-Agent(s): {', '.join(sorted(scanner_matches))}")
                if traversal_probes:
                    ev_parts.append(f"Attack signature(s): {', '.join(sorted(traversal_probes))}")
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"Visitor traffic from IP {ip} contains offensive security scanner "
                            f"signatures or fuzzing probe payloads."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_parts),
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-004: Subdomain & Virtual Host Enumeration Sweep (HIGH) ---
    # Evaluates security posture against subdomain & virtual host enumeration sweep.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_004(self) -> list[AuditFinding]:
        """LH-VIS-004 (HIGH): Subdomain & Virtual Host Enumeration Sweep."""
        rule = RULES_REGISTRY["LH-VIS-004"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            subdomains: set[str] = set()
            for r in recs:
                sub_p = _extract_subdomain(r.page)
                if sub_p and sub_p not in {"www", "com", "org", "net"}:
                    subdomains.add(sub_p)
                sub_r = _extract_subdomain(r.referrer)
                if sub_r and sub_r not in {"www", "com", "org", "net"}:
                    subdomains.add(sub_r)

            if len(subdomains) >= 3:
                sample = ", ".join(sorted(subdomains)[:5])
                evidence = f"Probed {len(subdomains)} distinct subdomains/vhosts: {sample}"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} performed an enumeration sweep across {len(subdomains)} "
                            f"distinct virtual host or subdomain targets."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-005 (HIGH):
    #     Rapid User-Agent / Fingerprint Rotation from Single IP
    # ---
    # Evaluates security posture against rapid user-agent / fingerprint rotation
    # from single ip.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_005(self) -> list[AuditFinding]:
        """LH-VIS-005 (HIGH): Device / User-Agent Fingerprint Rotation (Spoofing)."""
        rule = RULES_REGISTRY["LH-VIS-005"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            devices = {r.device.capitalize() for r in recs if r.device and r.device != "Unknown"}
            contradictory_devices = ("Desktop" in devices and "Mobile" in devices) or (
                "Desktop" in devices and "Tablet" in devices
            )

            os_pool: set[str] = set()
            for r in recs:
                ua = r.user_agent
                if "Windows" in ua:
                    os_pool.add("Windows")
                if "iPhone" in ua or "iOS" in ua:
                    os_pool.add("iOS")
                if "Android" in ua:
                    os_pool.add("Android")
                if "Macintosh" in ua or "Mac OS X" in ua:
                    os_pool.add("macOS")
                if "Linux" in ua and "Android" not in ua:
                    os_pool.add("Linux")

            contradictory_os = len(os_pool) >= 2

            if contradictory_devices or (contradictory_os and len(recs) >= 2):
                ev_items: list[str] = []
                if contradictory_devices:
                    ev_items.append(f"Conflicting devices: {', '.join(sorted(devices))}")
                if len(os_pool) >= 2:
                    ev_items.append(f"Conflicting OS platforms: {', '.join(sorted(os_pool))}")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} rapidly alternated across conflicting client device "
                            f"categories or contradictory operating system fingerprints."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-006: Unresolved or Anonymized GeoIP Traffic Spike (MEDIUM) ---
    # Evaluates security posture against unresolved or anonymized geoip traffic
    # spike.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_006(self) -> list[AuditFinding]:
        """LH-VIS-006 (MEDIUM): Unresolved / Anonymized GeoIP Traffic Spike."""
        rule = RULES_REGISTRY["LH-VIS-006"]
        findings: list[AuditFinding] = []

        unresolved_keywords = {
            "unknown",
            "n/a",
            "anonymous proxy",
            "tor exit node",
            "vpn",
            "private",
            "",
            "-",
        }

        for ip, recs in self.ip_groups.items():
            if len(recs) >= 5:
                unresolved_count = 0
                sample_loc = "Unknown"
                for r in recs:
                    clean_loc = r.location.strip().lower()
                    if clean_loc in unresolved_keywords:
                        unresolved_count += 1
                        sample_loc = r.location or "Unknown"

                if unresolved_count >= 5 and (unresolved_count / len(recs)) >= 0.7:
                    evidence = (
                        f"{unresolved_count}/{len(recs)} requests from unresolved location "
                        f"'{sample_loc}'"
                    )
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            ip_address=ip,
                            title=f"{rule.title} - {ip}",
                            description=(
                                f"High-volume visitor traffic spike ({unresolved_count} requests) "
                                f"from IP {ip} originating from unresolved or anonymized proxy."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-007: Suspicious Referrer Injection or Downgrade Attack (HIGH) ---
    # Evaluates security posture against suspicious referrer injection or downgrade
    # attack.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_007(self) -> list[AuditFinding]:
        """LH-VIS-007 (HIGH): Suspicious Referrer Injection or Cleartext Downgrade."""
        rule = RULES_REGISTRY["LH-VIS-007"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            injections: list[str] = []
            downgrades: list[str] = []

            for r in recs:
                ref_lower = r.referrer.lower()
                ua_lower = r.user_agent.lower()

                # Check injection payloads
                for sig in INJECTION_SIGNATURES:
                    if sig in ref_lower or sig in ua_lower:
                        injections.append(f"Payload '{sig}' in referrer/UA")
                        break

                # Check cleartext downgrade on sensitive routes
                if ref_lower.startswith("http://"):
                    p_lower = r.page.lower()
                    if any(route in p_lower for route in SENSITIVE_ROUTES):
                        downgrades.append(
                            f"Cleartext downgrade referrer '{r.referrer}' on route '{r.page}'"
                        )

            if injections or downgrades:
                ev_items = injections[:2] + downgrades[:2]
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} sent requests with injected script/SQL payloads in Referrer "
                            f"headers or cleartext HTTP downgrades on sensitive routes."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-008: Headless Automation or Scraper Bot Detected (MEDIUM) ---
    # Evaluates security posture against headless automation or scraper bot
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_008(self) -> list[AuditFinding]:
        """LH-VIS-008 (MEDIUM): Headless Automation, Scraper Bot, or Obsolete Botnet User-Agent."""
        rule = RULES_REGISTRY["LH-VIS-008"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            bot_reasons: set[str] = set()

            for r in recs:
                ua = r.user_agent
                ua_lower = ua.lower()

                for sig in HEADLESS_SCRAPER_SIGNATURES:
                    if sig in ua_lower:
                        bot_reasons.add(f"Headless/scraper client: {sig}")

                m_chrome = CHROME_VERSION_PATTERN.search(ua)
                if m_chrome:
                    major = int(m_chrome.group(1))
                    if major < 100:
                        bot_reasons.add(f"Obsolete browser version Chrome/{major}")

                m_ios = IOS_VERSION_PATTERN.search(ua)
                if m_ios:
                    ios_ver = int(m_ios.group(1))
                    if ios_ver < 15:
                        bot_reasons.add(f"Obsolete iOS version {ios_ver}")

                m_msie = MSIE_PATTERN.search(ua)
                if m_msie:
                    bot_reasons.add(f"Obsolete MSIE client {m_msie.group(0)}")

            if bot_reasons:
                sample_reasons = ", ".join(sorted(bot_reasons)[:3])
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} utilized programmatic scraping frameworks, headless "
                            f"browsers, or obsolete botnet client fingerprints."
                        ),
                        remediation=rule.remediation,
                        evidence=sample_reasons,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-009 (MEDIUM):
    #     Robots.txt Reconnaissance Followed by Path Probing
    # ---
    # Evaluates security posture against robots.txt reconnaissance followed by path
    # probing.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_009(self) -> list[AuditFinding]:
        """LH-VIS-009 (MEDIUM): Robots.txt Reconnaissance Followed by Sensitive Path Probing."""
        rule = RULES_REGISTRY["LH-VIS-009"]
        findings: list[AuditFinding] = []

        restricted_targets = (
            "/admin",
            "/private",
            "/backup",
            "/internal",
            "/api/internal",
            "/config",
            "/.hidden",
            "/secret",
            "/hidden",
        )

        for ip, recs in self.ip_groups.items():
            crawled_robots = False
            sensitive_probes: list[str] = []

            for r in recs:
                p_lower = r.page.lower()
                if "/robots.txt" in p_lower or "/sitemap.xml" in p_lower:
                    crawled_robots = True
                if any(target in p_lower for target in restricted_targets):
                    sensitive_probes.append(r.page)

            if crawled_robots and sensitive_probes:
                sample = ", ".join(sensitive_probes[:3])
                evidence = (
                    f"Inspected crawler directives, then probed restricted target(s): {sample}"
                )
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"IP {ip} performed reconnaissance on robots.txt/sitemap.xml and "
                            f"subsequently probed restricted internal application paths."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-010: Missing User-Agent or Malformed Visitor Telemetry (LOW) ---
    # Evaluates security posture against missing user-agent or malformed visitor
    # telemetry.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_vis_010(self) -> list[AuditFinding]:
        """LH-VIS-010 (LOW): Missing User-Agent or Malformed Visitor Telemetry."""
        rule = RULES_REGISTRY["LH-VIS-010"]
        findings: list[AuditFinding] = []

        for ip, recs in self.ip_groups.items():
            anomalies: list[str] = []

            # Check if IP address itself is malformed
            if ip != "UNKNOWN_IP" and not _is_valid_ip(ip):
                anomalies.append(f"Malformed IP address syntax: '{ip}'")

            for r in recs:
                ua = r.user_agent.strip()
                if not ua or ua in {"-", "null", "none"}:
                    anomalies.append(f"Missing User-Agent header on line {r.line_number}")
                if not r.timestamp.strip():
                    anomalies.append(f"Missing event timestamp on line {r.line_number}")

            if anomalies:
                sample = ", ".join(anomalies[:3])
                evidence = f"{len(anomalies)} telemetry anomaly(ies): {sample}"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        ip_address=ip,
                        title=f"{rule.title} - {ip}",
                        description=(
                            f"Telemetry for IP {ip} contains blank/missing User-Agent strings, "
                            f"unparseable timestamps, or malformed network addresses."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )
        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated perimeter risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_visitor_traffic(target: Path) -> AuditReport:
    """Ingest visitor telemetry and evaluate against complete rule catalog."""
    files = find_traffic_files(target)

    all_records: list[VisitorRecord] = []
    for f in files:
        file_records = parse_traffic_file(f)
        all_records.extend(file_records)

    analyzer = VisitorAnalyzer(all_records)
    findings = analyzer.analyze()

    unique_ips = len({r.ip_address.strip() for r in all_records if r.ip_address.strip()})
    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        records_analyzed=len(all_records),
        unique_ips=unique_ips,
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
