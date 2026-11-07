# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-visitor-audit test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def sample_clean_csv(tmp_path: Path) -> Path:
    """Fixture providing benign visitor traffic in CSV format."""
    csv_file = tmp_path / "clean_traffic.csv"
    content = (
        "Time,IP Address,Location,Device,Page,Referrer,User Agent\n"
        "2026-11-01T10:00:00Z,203.0.113.10,United States,Desktop,/home,https://google.com,"
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/125.0.0.0 Safari/537.36"\n'
        "2026-11-01T10:01:00Z,203.0.113.10,United States,Desktop,/products,https://google.com,"
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/125.0.0.0 Safari/537.36"\n'
        "2026-11-01T10:02:00Z,198.51.100.22,Germany,Mobile,/about,https://example.com,"
        '"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 '
        '(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"\n'
    )
    csv_file.write_text(content, encoding="utf-8")
    return csv_file


@pytest.fixture
def sample_malicious_csv(tmp_path: Path) -> Path:
    """Fixture providing visitor traffic triggering various detection rules."""
    csv_file = tmp_path / "suspicious_traffic.csv"
    lines = [
        "Time,IP Address,Location,Device,Page,Referrer,User Agent",
        # LH-VIS-001: Sensitive file probing
        (
            "2026-11-01T11:00:00Z,192.0.2.1,United States,Desktop,/.git/config,"
            "https://evil.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:00:02Z,192.0.2.1,United States,Desktop,/.env,"
            "https://evil.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:00:05Z,192.0.2.1,United States,Desktop,/wp-config.php,"
            "https://evil.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-002: Brute force burst (5 auth requests from 192.0.2.2)
        (
            "2026-11-01T11:05:00Z,192.0.2.2,United States,Desktop,/login,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:05:01Z,192.0.2.2,United States,Desktop,/api/v1/auth,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:05:02Z,192.0.2.2,United States,Desktop,/admin,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:05:03Z,192.0.2.2,United States,Desktop,/wp-login.php,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:05:04Z,192.0.2.2,United States,Desktop,/signin,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-003: Scanner footprint
        (
            "2026-11-01T11:10:00Z,192.0.2.3,Canada,Desktop,/search?q=1,"
            "https://example.com,sqlmap/1.6.0#stable"
        ),
        # LH-VIS-004: Subdomain sweep
        (
            "2026-11-01T11:15:00Z,192.0.2.4,United States,Desktop,"
            "https://careers.example.com/apply,https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:15:02Z,192.0.2.4,United States,Desktop,"
            "https://admin.example.com/portal,https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:15:04Z,192.0.2.4,United States,Desktop,"
            "https://staging.example.com/api,https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-005: Device rotation spoofing
        (
            "2026-11-01T11:20:00Z,192.0.2.5,France,Desktop,/dashboard,"
            "https://google.com,Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
        ),
        (
            "2026-11-01T11:20:02Z,192.0.2.5,France,Mobile,/dashboard,"
            "https://google.com,Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
        ),
        # LH-VIS-006: Unknown GeoIP burst (5 requests from Unknown location)
        (
            "2026-11-01T11:25:00Z,192.0.2.6,Unknown,Desktop,/page1,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:25:01Z,192.0.2.6,Unknown,Desktop,/page2,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:25:02Z,192.0.2.6,Unknown,Desktop,/page3,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:25:03Z,192.0.2.6,Unknown,Desktop,/page4,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:25:04Z,192.0.2.6,Unknown,Desktop,/page5,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-007: Referrer injection & Cleartext downgrade
        (
            "2026-11-01T11:30:00Z,192.0.2.7,United States,Desktop,/checkout,"
            "http://external-insecure.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-008: Headless browser & Obsolete Chrome
        (
            "2026-11-01T11:35:00Z,192.0.2.8,United Kingdom,Bot,/items,"
            "https://google.com,Mozilla/5.0 HeadlessChrome/93.0.4577.82"
        ),
        # LH-VIS-009: Robots.txt followed by private probing
        (
            "2026-11-01T11:40:00Z,192.0.2.9,United States,Desktop,/robots.txt,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        (
            "2026-11-01T11:40:05Z,192.0.2.9,United States,Desktop,/internal/docs,"
            "https://google.com,Mozilla/5.0 Chrome/120.0"
        ),
        # LH-VIS-010: Missing User-Agent
        ("2026-11-01T11:45:00Z,192.0.2.10,United States,Unknown,/index.html,https://google.com,-"),
    ]
    csv_file.write_text("\n".join(lines), encoding="utf-8")
    return csv_file


@pytest.fixture
def sample_nginx_log(tmp_path: Path) -> Path:
    """Fixture providing sample Nginx combined format access log."""
    log_file = tmp_path / "access.log"
    lines = [
        (
            '198.51.100.5 - - [01/Nov/2026:10:00:00 +0000] "GET /home HTTP/1.1" 200 1024 '
            '"https://google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0"'
        ),
        (
            '198.51.100.6 - - [01/Nov/2026:10:05:00 +0000] "GET /.env HTTP/1.1" 404 230 '
            '"-" "curl/7.81.0"'
        ),
    ]
    log_file.write_text("\n".join(lines), encoding="utf-8")
    return log_file


@pytest.fixture
def sample_telemetry_json(tmp_path: Path) -> Path:
    """Fixture providing structured JSON visitor telemetry."""
    json_file = tmp_path / "telemetry.json"
    data = [
        {
            "timestamp": "2026-11-01T12:00:00Z",
            "ip_address": "203.0.113.50",
            "location": "Japan",
            "device": "Desktop",
            "page": "/products",
            "referrer": "https://bing.com",
            "user_agent": "Mozilla/5.0 Chrome/122.0",
            "status_code": 200,
            "method": "GET",
        },
        {
            "timestamp": "2026-11-01T12:01:00Z",
            "ip_address": "203.0.113.50",
            "location": "Japan",
            "device": "Desktop",
            "page": "/.aws/credentials",
            "referrer": "https://bing.com",
            "user_agent": "Mozilla/5.0 Chrome/122.0",
            "status_code": 403,
            "method": "GET",
        },
    ]
    json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return json_file
