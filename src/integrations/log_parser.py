"""Multi-format log parser for Sentinel-AI.

Supports CEF (Common Event Format), LEEF (Log Event Extended Format),
Syslog (RFC 3164/5424), JSON, and key=value log formats.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Syslog priority facility/severity mapping
SYSLOG_SEVERITY = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

CEF_SEVERITY_MAP = {
    "0": "info", "1": "info", "2": "info", "3": "low",
    "4": "low", "5": "medium", "6": "medium", "7": "high",
    "8": "high", "9": "critical", "10": "critical",
}


@dataclass
class ParsedEvent:
    """A normalized log event parsed from any supported format."""
    timestamp: datetime | None = None
    source: str = ""
    severity: str = "info"
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    format: str = "unknown"


class LogParser:
    """Multi-format log parser with auto-detection."""

    # RFC 3164 syslog: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
    _syslog_3164_re = re.compile(
        r"^<(\d{1,3})>"
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(.+)$"
    )

    # RFC 5424 syslog: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
    _syslog_5424_re = re.compile(
        r"^<(\d{1,3})>(\d+)\s+"
        r"(\S+)\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"(\S+)\s+"  # app-name
        r"(\S+)\s+"  # procid
        r"(\S+)\s+"  # msgid
        r"(.*)$"     # structured-data + message
    )

    _kv_re = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

    def detect_and_parse(self, line: str) -> ParsedEvent:
        """Auto-detect log format and parse."""
        stripped = line.strip()
        if not stripped:
            return ParsedEvent(raw=line, format="empty")

        if stripped.startswith("CEF:"):
            return self.parse_cef(stripped)
        if stripped.startswith("LEEF:"):
            return self.parse_leef(stripped)
        if stripped.startswith("<") and len(stripped) > 1 and stripped[1:4].replace(">", "").isdigit():
            return self.parse_syslog(stripped)
        if stripped.startswith("{"):
            return self.parse_json(stripped)
        if "=" in stripped and not stripped.startswith("="):
            return self.parse_kv(stripped)

        return ParsedEvent(raw=line, message=stripped, format="plaintext")

    def parse_cef(self, line: str) -> ParsedEvent:
        """Parse Common Event Format (CEF) log line.

        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension
        """
        raw = line
        if line.startswith("CEF:"):
            line = line[4:]

        parts = line.split("|", 7)
        if len(parts) < 7:
            return ParsedEvent(raw=raw, message=line, format="cef", severity="info")

        version = parts[0]
        vendor = parts[1]
        product = parts[2]
        device_version = parts[3]
        sig_id = parts[4]
        name = parts[5]
        severity_raw = parts[6]
        extension = parts[7] if len(parts) > 7 else ""

        # Parse extension key=value pairs
        ext_fields = self._parse_cef_extension(extension)

        severity = CEF_SEVERITY_MAP.get(severity_raw.strip(), "medium")

        timestamp = None
        for ts_key in ("rt", "start", "end", "deviceReceiptTime"):
            if ts_key in ext_fields:
                timestamp = self._try_parse_timestamp(str(ext_fields[ts_key]))
                break

        return ParsedEvent(
            timestamp=timestamp,
            source=f"{vendor}:{product}",
            severity=severity,
            message=name,
            fields={
                "cef_version": version,
                "vendor": vendor,
                "product": product,
                "device_version": device_version,
                "signature_id": sig_id,
                "name": name,
                "severity_raw": severity_raw,
                **ext_fields,
            },
            raw=raw,
            format="cef",
        )

    def parse_leef(self, line: str) -> ParsedEvent:
        """Parse Log Event Extended Format (LEEF) — IBM QRadar native format.

        Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
        LEEF 2.0 uses a configurable delimiter in extension; LEEF 1.0 uses tab.
        """
        raw = line
        if line.startswith("LEEF:"):
            line = line[5:]

        parts = line.split("|", 4)
        if len(parts) < 5:
            return ParsedEvent(raw=raw, message=line, format="leef", severity="info")

        version = parts[0]
        vendor = parts[1]
        product = parts[2]
        product_version = parts[3]
        remainder = parts[4]  # EventID + extension (tab-separated in LEEF 1.0)

        # In LEEF 1.0, event_id and extension are separated by tab
        # In LEEF 2.0, a custom delimiter may be specified
        delimiter = "\t"
        if version.startswith("2"):
            # LEEF 2.0: first char after event_id pipe may be custom delimiter
            # Format: EventID|^key=value^key=value  (^ = custom delimiter)
            pass

        # Split remainder into event_id and extension
        if delimiter in remainder:
            first_delim = remainder.index(delimiter)
            event_id = remainder[:first_delim]
            extension = remainder[first_delim + 1:]
        else:
            event_id = remainder
            extension = ""

        ext_fields = {}
        pairs = extension.split(delimiter) if extension else []

        for pair in pairs:
            if "=" in pair:
                key, _, value = pair.partition("=")
                ext_fields[key.strip()] = value.strip()

        severity = ext_fields.get("sev", ext_fields.get("severity", "info"))
        timestamp = None
        for ts_key in ("devTime", "devTimeFormat"):
            if ts_key in ext_fields:
                timestamp = self._try_parse_timestamp(str(ext_fields[ts_key]))
                break

        return ParsedEvent(
            timestamp=timestamp,
            source=f"{vendor}:{product}",
            severity=str(severity).lower(),
            message=f"{event_id}",
            fields={
                "leef_version": version,
                "vendor": vendor,
                "product": product,
                "product_version": product_version,
                "event_id": event_id,
                **ext_fields,
            },
            raw=raw,
            format="leef",
        )

    def parse_syslog(self, line: str) -> ParsedEvent:
        """Parse RFC 3164 or RFC 5424 syslog messages."""
        raw = line

        # Try RFC 5424 first
        match_5424 = self._syslog_5424_re.match(line)
        if match_5424:
            pri = int(match_5424.group(1))
            _version = match_5424.group(2)
            ts_str = match_5424.group(3)
            hostname = match_5424.group(4)
            app = match_5424.group(5)
            procid = match_5424.group(6)
            msgid = match_5424.group(7)
            rest = match_5424.group(8)

            severity_num = pri % 8
            facility_num = pri // 8

            timestamp = self._try_parse_timestamp(ts_str)
            # Extract message after structured data
            msg = rest
            if msg.startswith("["):
                bracket_end = msg.rfind("]")
                if bracket_end >= 0:
                    msg = msg[bracket_end + 1:].strip()

            return ParsedEvent(
                timestamp=timestamp,
                source=hostname,
                severity=SYSLOG_SEVERITY.get(severity_num, "info"),
                message=msg,
                fields={
                    "facility": facility_num,
                    "severity_num": severity_num,
                    "hostname": hostname,
                    "app": app,
                    "procid": procid,
                    "msgid": msgid,
                    "syslog_version": _version,
                },
                raw=raw,
                format="syslog_5424",
            )

        # Try RFC 3164
        match_3164 = self._syslog_3164_re.match(line)
        if match_3164:
            pri = int(match_3164.group(1))
            ts_str = match_3164.group(2)
            hostname = match_3164.group(3)
            msg = match_3164.group(4)

            severity_num = pri % 8
            facility_num = pri // 8
            timestamp = self._try_parse_timestamp(ts_str)

            return ParsedEvent(
                timestamp=timestamp,
                source=hostname,
                severity=SYSLOG_SEVERITY.get(severity_num, "info"),
                message=msg,
                fields={
                    "facility": facility_num,
                    "severity_num": severity_num,
                    "hostname": hostname,
                },
                raw=raw,
                format="syslog_3164",
            )

        return ParsedEvent(raw=raw, message=line, format="syslog_unknown")

    def parse_json(self, line: str) -> ParsedEvent:
        """Parse JSON-formatted log line."""
        raw = line
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return ParsedEvent(raw=raw, message=line, format="json_invalid")

        if not isinstance(data, dict):
            return ParsedEvent(raw=raw, message=str(data), format="json", fields={"value": data})

        # Extract common fields
        timestamp = None
        for ts_key in ("timestamp", "@timestamp", "time", "datetime", "ts", "date"):
            if ts_key in data:
                timestamp = self._try_parse_timestamp(str(data[ts_key]))
                if timestamp:
                    break

        severity = "info"
        for sev_key in ("severity", "level", "log_level", "priority", "sev"):
            if sev_key in data:
                severity = str(data[sev_key]).lower()
                break

        message = ""
        for msg_key in ("message", "msg", "description", "text", "event"):
            if msg_key in data:
                message = str(data[msg_key])
                break

        source = ""
        for src_key in ("source", "host", "hostname", "src", "origin"):
            if src_key in data:
                source = str(data[src_key])
                break

        return ParsedEvent(
            timestamp=timestamp,
            source=source,
            severity=severity,
            message=message,
            fields=data,
            raw=raw,
            format="json",
        )

    def parse_kv(self, line: str) -> ParsedEvent:
        """Parse key=value formatted log line."""
        raw = line
        fields: dict[str, Any] = {}

        for match in self._kv_re.finditer(line):
            key = match.group(1)
            value = match.group(2)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            fields[key] = value

        timestamp = None
        for ts_key in ("timestamp", "time", "ts", "datetime"):
            if ts_key in fields:
                timestamp = self._try_parse_timestamp(str(fields[ts_key]))
                if timestamp:
                    break

        severity = str(fields.get("severity", fields.get("level", "info"))).lower()
        message = str(fields.get("message", fields.get("msg", "")))
        source = str(fields.get("source", fields.get("host", "")))

        return ParsedEvent(
            timestamp=timestamp,
            source=source,
            severity=severity,
            message=message,
            fields=fields,
            raw=raw,
            format="kv",
        )

    @staticmethod
    def _parse_cef_extension(ext: str) -> dict[str, Any]:
        """Parse CEF extension field (space-separated key=value, values may contain spaces)."""
        fields: dict[str, Any] = {}
        if not ext:
            return fields

        # CEF extension keys are defined without spaces; values can contain spaces.
        # Keys follow the pattern: key=value key2=value2
        # We split on known key boundaries: a word followed by =
        tokens = re.split(r"\s+(?=\w+=)", ext.strip())
        for token in tokens:
            if "=" in token:
                key, _, value = token.partition("=")
                fields[key.strip()] = value.strip()
        return fields

    @staticmethod
    def _try_parse_timestamp(ts_str: str) -> datetime | None:
        """Attempt to parse a timestamp string in common formats."""
        if not ts_str or ts_str == "-":
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        # Try epoch seconds/milliseconds
        try:
            val = float(ts_str)
            if val > 1e12:
                val /= 1000  # milliseconds
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (ValueError, OSError):
            pass

        return None
