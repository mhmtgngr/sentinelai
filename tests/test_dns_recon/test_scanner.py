"""Tests for the DNS Pentest Scanner — using mocked DNS responses."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel_ai.agents.dns_recon.models import (
    AzureZoneInfo,
    DNSRecord,
    Finding,
    ScanResult,
    Severity,
)
from sentinel_ai.agents.dns_recon.report import ReportGenerator
from sentinel_ai.agents.dns_recon.wordlist import DEFAULT_SUBDOMAINS, load_wordlist


class TestModels:
    """Test data model classes."""

    def test_severity_ordering(self):
        assert Severity.CRITICAL.sort_key < Severity.HIGH.sort_key
        assert Severity.HIGH.sort_key < Severity.MEDIUM.sort_key
        assert Severity.MEDIUM.sort_key < Severity.LOW.sort_key
        assert Severity.LOW.sort_key < Severity.INFO.sort_key

    def test_finding_to_dict(self):
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="A test",
            evidence="proof",
            remediation="fix it",
            category="Test",
            mitre_technique="T1234",
            mitre_name="Test Technique",
        )
        d = finding.to_dict()
        assert d["title"] == "Test Finding"
        assert d["severity"] == "High"
        assert d["mitre_technique"] == "T1234"

    def test_dns_record_to_dict(self):
        record = DNSRecord("A", "example.com", "1.2.3.4", 3600, "external_dns")
        d = record.to_dict()
        assert d["type"] == "A"
        assert d["value"] == "1.2.3.4"
        assert d["source"] == "external_dns"

    def test_scan_result_severity_summary(self):
        result = ScanResult(target_domain="example.com")
        result.add_finding(
            Finding("F1", Severity.CRITICAL, "d", "e", "r", "c")
        )
        result.add_finding(
            Finding("F2", Severity.HIGH, "d", "e", "r", "c")
        )
        result.add_finding(
            Finding("F3", Severity.HIGH, "d", "e", "r", "c")
        )
        result.add_finding(
            Finding("F4", Severity.INFO, "d", "e", "r", "c")
        )

        summary = result.severity_summary
        assert summary["Critical"] == 1
        assert summary["High"] == 2
        assert summary["Info"] == 1
        assert "Medium" not in summary

    def test_scan_result_to_dict(self):
        result = ScanResult(target_domain="example.com")
        result.add_record(
            DNSRecord("A", "example.com", "1.2.3.4", 3600)
        )
        result.add_finding(
            Finding("F1", Severity.MEDIUM, "desc", "ev", "rem", "cat")
        )
        result.subdomains = ["www.example.com"]

        d = result.to_dict()
        assert d["meta"]["target"] == "example.com"
        assert d["summary"]["total_findings"] == 1
        assert d["summary"]["subdomains_found"] == 1
        assert len(d["dns_records"]) == 1
        assert len(d["findings"]) == 1

    def test_azure_zone_info_to_dict(self):
        zone = AzureZoneInfo(
            zone_name="example.com",
            resource_group="rg-dns",
            record_count=42,
            nameservers=["ns1.azure-dns.com"],
        )
        d = zone.to_dict()
        assert d["zone_name"] == "example.com"
        assert d["record_count"] == 42


class TestWordlist:
    """Test wordlist functionality."""

    def test_default_wordlist_not_empty(self):
        assert len(DEFAULT_SUBDOMAINS) > 100

    def test_default_wordlist_contains_common(self):
        for word in ["www", "mail", "api", "admin", "vpn"]:
            assert word in DEFAULT_SUBDOMAINS

    def test_load_wordlist_default(self):
        words = load_wordlist(None)
        assert words == DEFAULT_SUBDOMAINS

    def test_load_wordlist_from_file(self, tmp_path: Path):
        wordlist_file = tmp_path / "words.txt"
        wordlist_file.write_text("sub1\nsub2\n# comment\nsub3\n")
        words = load_wordlist(str(wordlist_file))
        assert words == ["sub1", "sub2", "sub3"]

    def test_load_wordlist_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_wordlist("/nonexistent/path.txt")


class TestReportGenerator:
    """Test report generation."""

    def _make_result(self) -> ScanResult:
        result = ScanResult(target_domain="test.example.com")
        result.scan_end = datetime.now(timezone.utc)
        result.nameservers = ["1.2.3.4"]
        result.add_record(
            DNSRecord("A", "test.example.com", "1.2.3.4", 3600, "external_dns")
        )
        result.add_record(
            DNSRecord("MX", "test.example.com", "10 mail.example.com", 3600, "azure_api")
        )
        result.add_finding(
            Finding(
                title="Test Critical Finding",
                severity=Severity.CRITICAL,
                description="Critical issue found",
                evidence="AXFR successful",
                remediation="Fix it now",
                category="Zone Transfer",
                mitre_technique="T1590.002",
                mitre_name="Gather Victim Network Info: DNS",
            )
        )
        result.add_finding(
            Finding(
                title="Missing DNSSEC",
                severity=Severity.MEDIUM,
                description="No DNSSEC",
                evidence="No DNSKEY records",
                remediation="Enable DNSSEC",
                category="DNSSEC",
            )
        )
        result.subdomains = ["www.test.example.com", "mail.test.example.com"]
        result.reverse_dns = {"1.2.3.4": "host.example.com"}
        return result

    def test_generate_json(self, tmp_path: Path):
        result = self._make_result()
        gen = ReportGenerator(str(tmp_path))
        path = gen.generate_json(result)

        assert Path(path).exists()
        with open(path) as f:
            data = json.load(f)
        assert data["meta"]["target"] == "test.example.com"
        assert data["summary"]["total_findings"] == 2
        assert len(data["dns_records"]) == 2

    def test_generate_html(self, tmp_path: Path):
        result = self._make_result()
        gen = ReportGenerator(str(tmp_path))
        path = gen.generate_html(result)

        assert Path(path).exists()
        content = Path(path).read_text()
        assert "test.example.com" in content
        assert "Critical" in content
        assert "Test Critical Finding" in content
        assert "T1590.002" in content
        assert "Sentinel-AI" in content

    def test_generate_both(self, tmp_path: Path):
        result = self._make_result()
        gen = ReportGenerator(str(tmp_path))
        paths = gen.generate(result, "both")
        assert len(paths) == 2
        extensions = {Path(p).suffix for p in paths}
        assert extensions == {".json", ".html"}

    def test_generate_json_only(self, tmp_path: Path):
        result = self._make_result()
        gen = ReportGenerator(str(tmp_path))
        paths = gen.generate(result, "json")
        assert len(paths) == 1
        assert paths[0].endswith(".json")

    def test_html_escapes_special_chars(self, tmp_path: Path):
        result = ScanResult(target_domain="test.example.com")
        result.scan_end = datetime.now(timezone.utc)
        result.add_finding(
            Finding(
                title="XSS <script>alert(1)</script>",
                severity=Severity.INFO,
                description="Test <b>bold</b>",
                evidence="a & b < c",
                remediation="Fix \"it\"",
                category="Test",
            )
        )
        gen = ReportGenerator(str(tmp_path))
        path = gen.generate_html(result)
        content = Path(path).read_text()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content
        assert "&amp;" in content
