"""Data models for DNS penetration testing results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def sort_key(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    category: str = ""
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "mitre_technique": self.mitre_technique,
            "mitre_name": self.mitre_name,
        }


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0
    source: str = "external_dns"  # "azure_api" or "external_dns"

    def to_dict(self) -> dict:
        return {
            "type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
            "source": self.source,
        }


@dataclass
class AzureZoneInfo:
    zone_name: str
    resource_group: str
    record_count: int = 0
    nameservers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "zone_name": self.zone_name,
            "resource_group": self.resource_group,
            "record_count": self.record_count,
            "nameservers": self.nameservers,
        }


@dataclass
class ScanResult:
    target_domain: str
    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_end: Optional[datetime] = None
    dns_records: list[DNSRecord] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    wildcard_detected: bool = False
    nameservers: list[str] = field(default_factory=list)
    azure_zones: list[AzureZoneInfo] = field(default_factory=list)
    reverse_dns: dict[str, str] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_record(self, record: DNSRecord) -> None:
        self.dns_records.append(record)

    @property
    def severity_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def to_dict(self) -> dict:
        return {
            "meta": {
                "tool": "Sentinel-AI DNS Pentest Scanner",
                "version": "1.0.0",
                "target": self.target_domain,
                "scan_start": self.scan_start.isoformat(),
                "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.severity_summary,
                "subdomains_found": len(self.subdomains),
                "dns_records_found": len(self.dns_records),
                "wildcard_detected": self.wildcard_detected,
            },
            "azure_zones": [z.to_dict() for z in self.azure_zones],
            "nameservers": self.nameservers,
            "dns_records": [r.to_dict() for r in self.dns_records],
            "subdomains": sorted(self.subdomains),
            "findings": [
                f.to_dict()
                for f in sorted(self.findings, key=lambda x: x.severity.sort_key)
            ],
            "reverse_dns": self.reverse_dns,
        }
