# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        tests.test_traffic_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for visitor traffic and log parsers."""

from __future__ import annotations

import json
from pathlib import Path

from lh_visitor_audit.traffic_parser import (
    _infer_device_from_ua,
    find_traffic_files,
    parse_csv_file,
    parse_json_file,
    parse_log_file,
    parse_traffic_file,
)


def test_infer_device_from_ua() -> None:
    """Verify device inference from user agent strings."""
    assert _infer_device_from_ua("-") == "Unknown"
    assert _infer_device_from_ua("") == "Unknown"
    assert _infer_device_from_ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)") == "Mobile"
    assert _infer_device_from_ua("Mozilla/5.0 (Android 14; Mobile)") == "Mobile"
    assert _infer_device_from_ua("Mozilla/5.0 (iPad; CPU OS 16_0)") == "Tablet"
    assert _infer_device_from_ua("curl/7.88.1") == "Bot"
    assert _infer_device_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)") == "Desktop"


def test_parse_csv_file_standard(sample_clean_csv: Path) -> None:
    """Verify parsing standard CSV traffic export."""
    records = parse_csv_file(sample_clean_csv)
    assert len(records) == 3
    assert records[0].ip_address == "203.0.113.10"
    assert records[0].location == "United States"
    assert records[0].device == "Desktop"
    assert records[0].page == "/home"
    assert records[0].status_code == 200
    assert records[2].device == "Mobile"


def test_parse_csv_file_alternate_headers(tmp_path: Path) -> None:
    """Verify parsing CSV with alternate header naming conventions."""
    alt_csv = tmp_path / "alternate.csv"
    alt_csv.write_text(
        "timestamp,client_ip,country,platform,request_uri,http_referer,http_user_agent,code,method\n"
        "2026-11-01T12:00:00Z,10.0.0.1,Germany,Desktop,/api/v1/users,https://auth.com,MyAgent,201,POST\n",
        encoding="utf-8",
    )
    records = parse_csv_file(alt_csv)
    assert len(records) == 1
    assert records[0].ip_address == "10.0.0.1"
    assert records[0].location == "Germany"
    assert records[0].device == "Desktop"
    assert records[0].page == "/api/v1/users"
    assert records[0].status_code == 201
    assert records[0].method == "POST"


def test_parse_log_file_combined_and_common(tmp_path: Path) -> None:
    """Verify parsing both Combined and Common log formats."""
    log_file = tmp_path / "mixed.log"
    content = (
        "# This is a comment\n"
        '1.2.3.4 - - [01/Nov/2026:10:00:00 +0000] "GET /test HTTP/1.1" 200 123 "-" "curl/7.68.0"\n'
        '5.6.7.8 - - [01/Nov/2026:10:01:00 +0000] "POST /submit HTTP/1.1" 500 456\n'
    )
    log_file.write_text(content, encoding="utf-8")
    records = parse_log_file(log_file)
    assert len(records) == 2
    assert records[0].ip_address == "1.2.3.4"
    assert records[0].page == "/test"
    assert records[0].status_code == 200
    assert records[0].device == "Bot"

    assert records[1].ip_address == "5.6.7.8"
    assert records[1].page == "/submit"
    assert records[1].status_code == 500


def test_parse_json_file_array(sample_telemetry_json: Path) -> None:
    """Verify parsing JSON telemetry formatted as a JSON array."""
    records = parse_json_file(sample_telemetry_json)
    assert len(records) == 2
    assert records[0].ip_address == "203.0.113.50"
    assert records[1].page == "/.aws/credentials"
    assert records[1].status_code == 403


def test_parse_json_file_ndjson(tmp_path: Path) -> None:
    """Verify parsing newline-delimited JSON (NDJSON) telemetry."""
    ndjson_file = tmp_path / "telemetry.jsonl"
    lines = [
        json.dumps({"ip": "1.1.1.1", "page": "/index", "status": 200}),
        json.dumps({"ip": "2.2.2.2", "page": "/login", "status": 401}),
    ]
    ndjson_file.write_text("\n".join(lines), encoding="utf-8")
    records = parse_json_file(ndjson_file)
    assert len(records) == 2
    assert records[0].ip_address == "1.1.1.1"
    assert records[1].ip_address == "2.2.2.2"


def test_find_traffic_files(tmp_path: Path) -> None:
    """Verify file discovery logic in directory hierarchies."""
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "traffic.csv").write_text("Time,IP Address\n", encoding="utf-8")
    (sub / "access.log").write_text("log data\n", encoding="utf-8")
    (sub / "telemetry.json").write_text("[]\n", encoding="utf-8")
    (sub / "ignore.pdf").write_text("fake pdf\n", encoding="utf-8")

    found = find_traffic_files(tmp_path)
    found_names = [f.name for f in found]
    assert "traffic.csv" in found_names
    assert "access.log" in found_names
    assert "telemetry.json" in found_names
    assert "ignore.pdf" not in found_names

    # Direct file target
    direct = find_traffic_files(sub / "traffic.csv")
    assert len(direct) == 1
    assert direct[0].name == "traffic.csv"

    # Non-existent target
    assert find_traffic_files(tmp_path / "nonexistent") == []


def test_parse_traffic_file_dispatch(tmp_path: Path, sample_clean_csv: Path) -> None:
    """Verify parse_traffic_file dispatches to correct parser."""
    recs = parse_traffic_file(sample_clean_csv)
    assert len(recs) == 3

    # Fallback when file has unknown extension
    unknown_ext = tmp_path / "data.unknown"
    unknown_ext.write_text(sample_clean_csv.read_text(encoding="utf-8"), encoding="utf-8")
    recs_fallback = parse_traffic_file(unknown_ext)
    assert len(recs_fallback) == 3
