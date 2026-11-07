# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        tests.test_visitor_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for visitor behavior analyzer and security rule detection."""

from __future__ import annotations

from pathlib import Path

from lh_visitor_audit.models import (
    FindingSeverity,
    VisitorRecord,
)
from lh_visitor_audit.visitor_analyzer import (
    VisitorAnalyzer,
    audit_visitor_traffic,
    calculate_risk_score,
)


def test_severity_thresholds() -> None:
    """Verify FindingSeverity hierarchy and comparison methods."""
    assert FindingSeverity.CRITICAL.level == 4
    assert FindingSeverity.HIGH.level == 3
    assert FindingSeverity.MEDIUM.level == 2
    assert FindingSeverity.LOW.level == 1

    assert FindingSeverity.CRITICAL.meets_threshold(FindingSeverity.HIGH)
    assert FindingSeverity.HIGH.meets_threshold(FindingSeverity.HIGH)
    assert not FindingSeverity.MEDIUM.meets_threshold(FindingSeverity.HIGH)

    assert FindingSeverity.from_string("critical") == FindingSeverity.CRITICAL
    assert FindingSeverity.from_string("HIGH") == FindingSeverity.HIGH
    assert FindingSeverity.from_string("medium") == FindingSeverity.MEDIUM
    assert FindingSeverity.from_string("unknown") == FindingSeverity.LOW


def test_clean_traffic_produces_no_findings(sample_clean_csv: Path) -> None:
    """Verify that legitimate visitor traffic results in clean report."""
    report = audit_visitor_traffic(sample_clean_csv)
    assert report.findings_count == 0
    assert report.risk_score == 0
    assert report.records_analyzed == 3
    assert report.unique_ips == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-001: Sensitive File & Repository Probing Detected (CRITICAL) ---
    # Evaluates security posture against sensitive file & repository probing
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_001_sensitive_probing() -> None:
    """Verify LH-VIS-001 detects sensitive file and repo probes."""
    records = [
        VisitorRecord(ip_address="1.2.3.4", page="/.git/config"),
        VisitorRecord(ip_address="1.2.3.4", page="/.env"),
        VisitorRecord(ip_address="1.2.3.4", page="/db_backup.sql"),
        VisitorRecord(ip_address="1.2.3.4", page="/.aws/credentials"),
        VisitorRecord(ip_address="1.2.3.4", page="/id_rsa"),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-001" in rule_ids
    f = next(item for item in findings if item.rule_id == "LH-VIS-001")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-002: High-Velocity Credential Stuffing Burst (CRITICAL) ---
    # Evaluates security posture against high-velocity credential stuffing burst.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_002_credential_stuffing_burst() -> None:
    """Verify LH-VIS-002 flags rapid bursts against auth endpoints."""
    records = [
        VisitorRecord(ip_address="5.5.5.5", page="/login"),
        VisitorRecord(ip_address="5.5.5.5", page="/auth"),
        VisitorRecord(ip_address="5.5.5.5", page="/admin"),
        VisitorRecord(ip_address="5.5.5.5", page="/wp-login.php"),
        VisitorRecord(ip_address="5.5.5.5", page="/api/login"),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-002" in rule_ids
    f = next(item for item in findings if item.rule_id == "LH-VIS-002")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-003: Automated Vulnerability Scanner Footprint Detected (HIGH) ---
    # Evaluates security posture against automated vulnerability scanner footprint
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_003_scanner_footprint() -> None:
    """Verify LH-VIS-003 detects offensive scanner signatures and attack sweeps."""
    records = [
        VisitorRecord(
            ip_address="6.6.6.6",
            page="/catalog",
            user_agent="sqlmap/1.7.2#stable (https://sqlmap.org)",
        ),
        VisitorRecord(
            ip_address="7.7.7.7",
            page="/app/../../../../etc/passwd",
            user_agent="Mozilla/5.0",
        ),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-003" in rule_ids
    matches = [f for f in findings if f.rule_id == "LH-VIS-003"]
    assert len(matches) == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-004: Subdomain & Virtual Host Enumeration Sweep (HIGH) ---
    # Evaluates security posture against subdomain & virtual host enumeration sweep.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_004_subdomain_sweep() -> None:
    """Verify LH-VIS-004 detects sweeping across multiple virtual hosts/subdomains."""
    records = [
        VisitorRecord(ip_address="8.8.8.8", page="https://careers.example.com/apply"),
        VisitorRecord(ip_address="8.8.8.8", page="https://admin.example.com/portal"),
        VisitorRecord(ip_address="8.8.8.8", page="https://staging.example.com/api"),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-004" in rule_ids
    f = next(item for item in findings if item.rule_id == "LH-VIS-004")
    assert f.severity == FindingSeverity.HIGH
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


def test_rule_lh_vis_005_fingerprint_rotation() -> None:
    """Verify LH-VIS-005 detects device and OS fingerprint rotation spoofing."""
    records = [
        VisitorRecord(
            ip_address="9.9.9.9",
            device="Desktop",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ),
        VisitorRecord(
            ip_address="9.9.9.9",
            device="Mobile",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        ),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-005" in rule_ids
    f = next(item for item in findings if item.rule_id == "LH-VIS-005")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-006: Unresolved or Anonymized GeoIP Traffic Spike (MEDIUM) ---
    # Evaluates security posture against unresolved or anonymized geoip traffic
    # spike.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_006_geoip_unknown_spike() -> None:
    """Verify LH-VIS-006 detects burst from unresolved/anonymized locations."""
    records = [VisitorRecord(ip_address="10.10.10.10", location="Unknown") for _ in range(5)]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-006" in rule_ids
    f = next(item for item in findings if item.rule_id == "LH-VIS-006")
    assert f.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-007: Suspicious Referrer Injection or Downgrade Attack (HIGH) ---
    # Evaluates security posture against suspicious referrer injection or downgrade
    # attack.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_007_referrer_injection_and_downgrade() -> None:
    """Verify LH-VIS-007 flags script injection and cleartext downgrades."""
    records = [
        VisitorRecord(
            ip_address="11.11.11.11",
            page="/products",
            referrer="https://example.com/?q=<script>alert(1)</script>",
        ),
        VisitorRecord(
            ip_address="12.12.12.12",
            page="/checkout",
            referrer="http://insecure-shop.com/cart",
        ),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-007" in rule_ids
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-008: Headless Automation or Scraper Bot Detected (MEDIUM) ---
    # Evaluates security posture against headless automation or scraper bot
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_008_headless_and_obsolete_clients() -> None:
    """Verify LH-VIS-008 detects headless automation and obsolete browser agents."""
    records = [
        VisitorRecord(
            ip_address="13.13.13.13",
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/93.0",
        ),
        VisitorRecord(
            ip_address="14.14.14.14",
            user_agent="python-requests/2.28.1",
        ),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-008" in rule_ids
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


def test_rule_lh_vis_009_robots_followed_by_probing() -> None:
    """Verify LH-VIS-009 detects robots.txt recon followed by private probing."""
    records = [
        VisitorRecord(ip_address="15.15.15.15", page="/robots.txt"),
        VisitorRecord(ip_address="15.15.15.15", page="/admin/dashboard"),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-009" in rule_ids
    # --------------------------------------------------------------------------
    # --- Rule LH-VIS-010: Missing User-Agent or Malformed Visitor Telemetry (LOW) ---
    # Evaluates security posture against missing user-agent or malformed visitor
    # telemetry.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_vis_010_missing_ua_or_malformed_ip() -> None:
    """Verify LH-VIS-010 detects empty UA and invalid IP formatting."""
    records = [
        VisitorRecord(
            ip_address="invalid-ip-format",
            user_agent="-",
            timestamp="",
        ),
    ]
    analyzer = VisitorAnalyzer(records)
    findings = analyzer.analyze()
    rule_ids = [f.rule_id for f in findings]
    assert "LH-VIS-010" in rule_ids


def test_malicious_fixture_comprehensive(sample_malicious_csv: Path) -> None:
    """Verify malicious CSV fixture triggers complete rule spectrum."""
    report = audit_visitor_traffic(sample_malicious_csv)
    assert report.findings_count >= 10
    assert report.risk_score > 50

    triggered_rules = {f.rule_id for f in report.findings}
    for rule_num in range(1, 11):
        rule_key = f"LH-VIS-{rule_num:03d}"
        assert rule_key in triggered_rules, f"Expected {rule_key} to be triggered"


def test_calculate_risk_score() -> None:
    """Verify risk score bounded calculation."""
    assert calculate_risk_score([]) == 0
