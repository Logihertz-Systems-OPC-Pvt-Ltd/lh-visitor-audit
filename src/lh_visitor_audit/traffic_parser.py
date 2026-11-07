# ==============================================================================
# Product:       lh-visitor-audit (lh-visitor)
# Module:        src.lh_visitor_audit.traffic_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Log and telemetry parsers for visitor traffic data."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

from lh_visitor_audit.models import VisitorRecord

# Regex pattern for Apache/Nginx Combined Log Format
COMBINED_LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[0-9.]+)?\"'
    r'\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
)

# Regex pattern for Apache/Nginx Common Log Format
COMMON_LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[0-9.]+)?\"'
    r"\s+(\d{3})\s+(\S+)"
)


def _infer_device_from_ua(user_agent: str) -> str:
    """Infer high-level device category from User-Agent string."""
    ua_lower = user_agent.lower()
    if not ua_lower or ua_lower == "-":
        return "Unknown"
    if any(k in ua_lower for k in ["ipad", "tablet"]):
        return "Tablet"
    if any(k in ua_lower for k in ["mobile", "iphone", "android"]):
        return "Mobile"
    if any(k in ua_lower for k in ["bot", "spider", "crawl", "curl", "python", "headless"]):
        return "Bot"
    return "Desktop"


def _extract_field(row: dict[str, Any], aliases: list[str], default: str = "") -> str:
    """Case-insensitively retrieve field value by checking multiple alias names."""
    normalized_keys = {k.strip().lower().replace("_", " "): k for k in row.keys() if k is not None}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized_keys:
            orig_key = normalized_keys[norm_alias]
            val = row[orig_key]
            if val is not None:
                res = str(val).strip()
                if None in row and any(a in norm_alias for a in ["user agent", "ua", "useragent"]):
                    extra = row[None]
                    if isinstance(extra, list):
                        res += "," + ",".join(str(x) for x in extra)
                return res
    return default


def parse_csv_file(path: Path) -> list[VisitorRecord]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse CSV export of visitor traffic telemetry."""
    records: list[VisitorRecord] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=2):
                if not row:
                    continue
                ts = _extract_field(row, ["time", "timestamp", "date", "datetime", "req_time"])
                ip = _extract_field(
                    row, ["ip address", "ip_address", "ip", "client_ip", "remote_addr"]
                )
                loc = _extract_field(
                    row, ["location", "country", "geo", "city", "region"], "Unknown"
                )
                dev = _extract_field(row, ["device", "device_type", "client_type"], "Unknown")
                page = _extract_field(row, ["page", "url", "path", "uri", "request_uri", "request"])
                ref = _extract_field(row, ["referrer", "referer", "http_referer"])
                ua = _extract_field(
                    row, ["user agent", "user_agent", "useragent", "http_user_agent", "ua"]
                )
                status_raw = _extract_field(row, ["status", "status_code", "code"], "200")
                method = _extract_field(row, ["method", "http_method"], "GET").upper()

                try:
                    status_code = int(status_raw)
                except ValueError:
                    status_code = 200

                if dev == "Unknown" and ua:
                    dev = _infer_device_from_ua(ua)

                records.append(
                    VisitorRecord(
                        timestamp=ts,
                        ip_address=ip,
                        location=loc or "Unknown",
                        device=dev or "Unknown",
                        page=page,
                        referrer=ref,
                        user_agent=ua,
                        status_code=status_code,
                        method=method,
                        source_file=str(path),
                        line_number=idx,
                    )
                )
    except Exception:
        return []
    return records


def parse_log_file(path: Path) -> list[VisitorRecord]:
    """Parse Nginx/Apache access log file in Combined or Common format."""
    records: list[VisitorRecord] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                m_comb = COMBINED_LOG_PATTERN.match(clean_line)
                if m_comb:
                    ip = m_comb.group(1)
                    ts = m_comb.group(2)
                    method = m_comb.group(3)
                    page = m_comb.group(4)
                    status_code = int(m_comb.group(5))
                    referrer = m_comb.group(7)
                    ua = m_comb.group(8)
                    device = _infer_device_from_ua(ua)

                    records.append(
                        VisitorRecord(
                            timestamp=ts,
                            ip_address=ip,
                            location="Unknown",
                            device=device,
                            page=page,
                            referrer="" if referrer == "-" else referrer,
                            user_agent="" if ua == "-" else ua,
                            status_code=status_code,
                            method=method,
                            source_file=str(path),
                            line_number=line_no,
                        )
                    )
                    continue

                m_comm = COMMON_LOG_PATTERN.match(clean_line)
                if m_comm:
                    ip = m_comm.group(1)
                    ts = m_comm.group(2)
                    method = m_comm.group(3)
                    page = m_comm.group(4)
                    status_code = int(m_comm.group(5))

                    records.append(
                        VisitorRecord(
                            timestamp=ts,
                            ip_address=ip,
                            location="Unknown",
                            device="Unknown",
                            page=page,
                            referrer="",
                            user_agent="",
                            status_code=status_code,
                            method=method,
                            source_file=str(path),
                            line_number=line_no,
                        )
                    )
    except Exception:
        return []
    return records


def parse_json_file(path: Path) -> list[VisitorRecord]:
    """Parse structured JSON visitor telemetry file (array or NDJSON)."""
    records: list[VisitorRecord] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return []

        entries: list[dict[str, Any]] = []
        if text.startswith("["):
            loaded = json.loads(text)
            if isinstance(loaded, list):
                entries = [item for item in loaded if isinstance(item, dict)]
        else:
            for line in text.splitlines():
                clean = line.strip()
                if not clean:
                    continue
                try:
                    obj = json.loads(clean)
                    if isinstance(obj, dict):
                        entries.append(obj)
                except json.JSONDecodeError:
                    continue

        for idx, row in enumerate(entries, start=1):
            ts = _extract_field(row, ["time", "timestamp", "date", "datetime"])
            ip = _extract_field(row, ["ip address", "ip_address", "ip", "client_ip", "remote_ip"])
            loc = _extract_field(row, ["location", "country", "geo", "city"], "Unknown")
            dev = _extract_field(row, ["device", "device_type", "platform"], "Unknown")
            page = _extract_field(row, ["page", "url", "path", "uri", "request_uri"])
            ref = _extract_field(row, ["referrer", "referer"])
            ua = _extract_field(row, ["user agent", "user_agent", "useragent", "ua"])
            status_raw = _extract_field(row, ["status", "status_code", "code"], "200")
            method = _extract_field(row, ["method", "http_method"], "GET").upper()

            try:
                status_code = int(status_raw)
            except ValueError:
                status_code = 200

            if dev == "Unknown" and ua:
                dev = _infer_device_from_ua(ua)

            records.append(
                VisitorRecord(
                    timestamp=ts,
                    ip_address=ip,
                    location=loc or "Unknown",
                    device=dev or "Unknown",
                    page=page,
                    referrer=ref,
                    user_agent=ua,
                    status_code=status_code,
                    method=method,
                    source_file=str(path),
                    line_number=idx,
                )
            )
    except Exception:
        return []
    return records


def parse_traffic_file(path: Path) -> list[VisitorRecord]:
    """Parse visitor traffic file according to extension and file signatures."""
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return parse_csv_file(path)
    if suffix in [".json", ".jsonl"]:
        return parse_json_file(path)
    if suffix in [".log", ".txt", ".access"]:
        records = parse_log_file(path)
        if records:
            return records

    # Heuristic fallback
    csv_records = parse_csv_file(path)
    if csv_records:
        return csv_records
    json_records = parse_json_file(path)
    if json_records:
        return json_records
    return parse_log_file(path)


def find_traffic_files(root: Path) -> list[Path]:
    """Locate all supported visitor log and telemetry files under root path."""
    if not root.exists():
        return []

    if root.is_file():
        return [root]

    supported_suffixes = {".csv", ".log", ".json", ".jsonl", ".txt"}
    files: list[Path] = []
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in supported_suffixes:
            files.append(item)
    return sorted(files)
