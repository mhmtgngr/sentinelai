"""Main DNS Pentest Scanner — orchestrates all reconnaissance and security checks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .azure_dns import AzureDNSClient
from .enumerator import DNSEnumerator
from .models import DNSRecord, Finding, ScanResult, Severity
from .reverse_dns import ReverseDNSChecker
from .security_checks import DNSSecurityChecker
from .wordlist import load_wordlist
from .zone_transfer import ZoneTransferChecker

logger = logging.getLogger(__name__)


class DNSPentestScanner:
    """Top-level orchestrator for DNS penetration testing."""

    def __init__(
        self,
        domain: str | None = None,
        nameserver: str | None = None,
        wordlist_path: str | None = None,
        timeout: float = 5.0,
        concurrency: int = 50,
        output_dir: str = "./reports",
        report_format: str = "both",
        skip_brute: bool = False,
        skip_zone_transfer: bool = False,
        verbose: bool = False,
        # Azure credentials
        azure_tenant_id: str | None = None,
        azure_client_id: str | None = None,
        azure_client_secret: str | None = None,
        azure_subscription_id: str | None = None,
    ):
        self.domain = domain
        self.nameserver = nameserver
        self.wordlist = load_wordlist(wordlist_path)
        self.timeout = timeout
        self.concurrency = concurrency
        self.output_dir = output_dir
        self.report_format = report_format
        self.skip_brute = skip_brute
        self.skip_zone_transfer = skip_zone_transfer
        self.verbose = verbose

        # Azure config
        self.azure_tenant_id = azure_tenant_id
        self.azure_client_id = azure_client_id
        self.azure_client_secret = azure_client_secret
        self.azure_subscription_id = azure_subscription_id

        # Components
        self.enumerator = DNSEnumerator(nameserver, timeout, concurrency)
        self.zone_checker = ZoneTransferChecker(timeout)
        self.security_checker = DNSSecurityChecker(nameserver, timeout)
        self.reverse_checker = ReverseDNSChecker(nameserver, timeout, concurrency)

    async def run(self) -> list[ScanResult]:
        """Execute the full DNS pentest pipeline.

        Returns a list of ScanResults (one per domain/zone scanned).
        """
        domains_to_scan: list[str] = []
        azure_client: Optional[AzureDNSClient] = None

        # Phase 1: Azure DNS — discover zones or use provided domain
        if self._has_azure_creds():
            logger.info("Authenticating with Azure DNS...")
            try:
                azure_client = AzureDNSClient(
                    tenant_id=self.azure_tenant_id,
                    client_id=self.azure_client_id,
                    client_secret=self.azure_client_secret,
                    subscription_id=self.azure_subscription_id,
                )

                if self.domain:
                    domains_to_scan = [self.domain]
                else:
                    zones = azure_client.list_zones()
                    domains_to_scan = [z.zone_name for z in zones]
                    logger.info(
                        "Auto-discovered %d Azure DNS zones", len(domains_to_scan)
                    )
            except Exception as e:
                logger.error("Azure DNS connection failed: %s", e)
                if self.domain:
                    domains_to_scan = [self.domain]
        elif self.domain:
            domains_to_scan = [self.domain]
        else:
            raise ValueError(
                "Either --domain or Azure credentials must be provided."
            )

        if not domains_to_scan:
            logger.warning("No domains to scan.")
            return []

        # Phase 2: Scan each domain
        results: list[ScanResult] = []
        for domain in domains_to_scan:
            logger.info("=" * 60)
            logger.info("Starting DNS pentest for: %s", domain)
            logger.info("=" * 60)
            result = await self._scan_domain(domain, azure_client)
            results.append(result)

        return results

    async def _scan_domain(
        self, domain: str, azure_client: Optional[AzureDNSClient]
    ) -> ScanResult:
        """Run the full scan pipeline for a single domain."""
        result = ScanResult(target_domain=domain)

        # Step 1: Fetch Azure DNS records if available
        if azure_client:
            await self._phase_azure(domain, azure_client, result)

        # Step 2: External DNS enumeration
        self._log_phase("DNS Record Enumeration")
        records = await self.enumerator.enumerate_records(domain)
        for r in records:
            result.add_record(r)

        # Step 3: Resolve nameservers
        self._log_phase("Nameserver Discovery")
        ns_hostnames = await self.enumerator.get_nameserver_hostnames(domain)
        ns_ips = await self.enumerator.get_nameservers(domain)
        result.nameservers = ns_ips
        logger.info("Nameservers: %s", ", ".join(ns_ips) if ns_ips else "none found")

        # Step 4: Cross-reference Azure vs External
        if azure_client:
            self._cross_reference_records(domain, result)

        # Step 5: Wildcard detection
        self._log_phase("Wildcard Detection")
        wildcard_ip = await self.enumerator.detect_wildcard(domain)
        result.wildcard_detected = wildcard_ip is not None
        if wildcard_ip:
            result.add_finding(
                Finding(
                    title=f"Wildcard DNS Detected for {domain}",
                    severity=Severity.INFO,
                    description=(
                        f"Wildcard DNS is configured. Any non-existent subdomain "
                        f"resolves to {wildcard_ip}."
                    ),
                    evidence=f"Random subdomain resolved to {wildcard_ip}",
                    remediation="Review if wildcard DNS is intentional.",
                    category="Wildcard DNS",
                )
            )

        # Step 6: Subdomain brute force
        if not self.skip_brute:
            self._log_phase("Subdomain Brute Force")
            subdomains = await self.enumerator.brute_force_subdomains(
                domain, self.wordlist, wildcard_ip
            )
            result.subdomains = subdomains
            logger.info("Discovered %d subdomains", len(subdomains))

        # Step 7: Zone transfer
        if not self.skip_zone_transfer:
            self._log_phase("Zone Transfer (AXFR) Testing")
            for ns_ip in ns_ips:
                finding, axfr_records = await self.zone_checker.attempt_transfer(
                    domain, ns_ip
                )
                if finding:
                    result.add_finding(finding)
                    for r in axfr_records:
                        result.add_record(r)

        # Step 8: DNSSEC
        self._log_phase("DNSSEC Validation")
        dnssec_findings = await self.security_checker.check_dnssec(domain)
        for f in dnssec_findings:
            result.add_finding(f)

        # Step 9: SPF/DMARC
        self._log_phase("Email Security (SPF/DMARC)")
        spf_findings = await self.security_checker.check_spf(domain)
        for f in spf_findings:
            result.add_finding(f)

        dmarc_findings = await self.security_checker.check_dmarc(domain)
        for f in dmarc_findings:
            result.add_finding(f)

        # Step 10: Open resolver test
        self._log_phase("Open Resolver Testing")
        for ns_ip in ns_ips:
            resolver_findings = await self.security_checker.check_open_resolver(ns_ip)
            for f in resolver_findings:
                result.add_finding(f)

        # Step 11: NS version disclosure
        self._log_phase("Nameserver Version Disclosure")
        for ns_ip in ns_ips:
            version_findings = await self.security_checker.check_nameserver_version(
                ns_ip
            )
            for f in version_findings:
                result.add_finding(f)

        # Step 12: Cache poisoning
        self._log_phase("Cache Poisoning Susceptibility")
        for ns_ip in ns_ips:
            poison_findings = await self.security_checker.check_cache_poisoning(
                domain, ns_ip
            )
            for f in poison_findings:
                result.add_finding(f)

        # Step 13: Stale NS
        self._log_phase("Stale NS Detection")
        stale_findings = await self.security_checker.check_stale_ns(
            domain, ns_hostnames
        )
        for f in stale_findings:
            result.add_finding(f)

        # Step 14: NS diversity
        diversity_findings = await self.security_checker.check_ns_diversity(
            domain, ns_ips
        )
        for f in diversity_findings:
            result.add_finding(f)

        # Step 15: TXT leakage
        self._log_phase("TXT Record Analysis")
        txt_findings = await self.security_checker.check_txt_leakage(result.dns_records)
        for f in txt_findings:
            result.add_finding(f)

        # Step 16: Reverse DNS
        self._log_phase("Reverse DNS Lookups")
        discovered_ips = self._extract_ips(result)
        if discovered_ips:
            reverse_map = await self.reverse_checker.bulk_reverse(discovered_ips)
            result.reverse_dns = {k: v for k, v in reverse_map.items() if v}

            # Forward/reverse consistency check
            forward_map = self._build_forward_map(result)
            consistency_findings = await self.reverse_checker.check_ptr_consistency(
                forward_map, reverse_map
            )
            for f in consistency_findings:
                result.add_finding(f)

        result.scan_end = datetime.now(timezone.utc)

        # Print summary
        self._print_summary(result)

        return result

    async def _phase_azure(
        self,
        domain: str,
        azure_client: AzureDNSClient,
        result: ScanResult,
    ) -> None:
        """Fetch and analyze Azure DNS zone data."""
        self._log_phase("Azure DNS Data Collection")
        try:
            zones = azure_client.list_zones()
            matching_zones = [z for z in zones if z.zone_name == domain]

            if not matching_zones:
                logger.warning("Domain %s not found in Azure DNS zones", domain)
                return

            for zone_info in matching_zones:
                result.azure_zones.append(zone_info)
                records = azure_client.get_zone_records(
                    zone_info.zone_name, zone_info.resource_group
                )
                for r in records:
                    result.add_record(r)

                # Azure-specific analysis
                azure_findings = azure_client.analyze_zone(
                    zone_info.zone_name, zone_info.resource_group, records
                )
                for f in azure_findings:
                    result.add_finding(f)

                logger.info(
                    "Azure zone %s: %d records fetched",
                    zone_info.zone_name,
                    len(records),
                )
        except Exception as e:
            logger.error("Azure DNS data collection failed: %s", e)

    def _cross_reference_records(self, domain: str, result: ScanResult) -> None:
        """Compare Azure DNS records with external DNS records."""
        azure_records = {
            (r.record_type, r.name, r.value)
            for r in result.dns_records
            if r.source == "azure_api"
        }
        external_records = {
            (r.record_type, r.name, r.value)
            for r in result.dns_records
            if r.source == "external_dns"
        }

        # Records in Azure but not visible externally
        azure_only = azure_records - external_records
        # Records visible externally but not in Azure
        external_only = external_records - azure_records

        if azure_only or external_only:
            evidence_lines = []
            if azure_only:
                evidence_lines.append("Records in Azure but not externally visible:")
                for rtype, name, value in list(azure_only)[:5]:
                    evidence_lines.append(f"  {rtype} {name} -> {value}")
            if external_only:
                evidence_lines.append("Records visible externally but not in Azure:")
                for rtype, name, value in list(external_only)[:5]:
                    evidence_lines.append(f"  {rtype} {name} -> {value}")

            result.add_finding(
                Finding(
                    title=f"Azure DNS / External DNS Record Mismatch for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Discrepancies found between Azure DNS zone data and external "
                        "DNS resolution. This may indicate propagation delays, split-horizon "
                        "DNS, or unauthorized DNS modifications."
                    ),
                    evidence="\n".join(evidence_lines),
                    remediation=(
                        "Investigate mismatches. Ensure Azure DNS is the authoritative source "
                        "and records are consistent."
                    ),
                    category="Azure DNS",
                )
            )

    def _extract_ips(self, result: ScanResult) -> list[str]:
        """Extract all unique IP addresses from scan results."""
        ips: set[str] = set()
        for record in result.dns_records:
            if record.record_type in ("A", "AAAA"):
                ips.add(record.value)
        return list(ips)

    def _build_forward_map(self, result: ScanResult) -> dict[str, str]:
        """Build hostname -> IP map from A records."""
        forward: dict[str, str] = {}
        for record in result.dns_records:
            if record.record_type == "A":
                forward[record.name] = record.value
        return forward

    def _has_azure_creds(self) -> bool:
        """Check if Azure credentials are available."""
        import os

        return bool(
            (self.azure_tenant_id or os.environ.get("AZURE_TENANT_ID"))
            and (self.azure_client_id or os.environ.get("AZURE_CLIENT_ID"))
            and (self.azure_client_secret or os.environ.get("AZURE_CLIENT_SECRET"))
            and (self.azure_subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID"))
        )

    @staticmethod
    def _log_phase(name: str) -> None:
        logger.info("[*] %s", name)

    @staticmethod
    def _print_summary(result: ScanResult) -> None:
        """Print a concise scan summary to logger."""
        summary = result.severity_summary
        total = len(result.findings)
        logger.info("")
        logger.info("=" * 60)
        logger.info("SCAN COMPLETE: %s", result.target_domain)
        logger.info("=" * 60)
        logger.info("DNS Records:   %d", len(result.dns_records))
        logger.info("Subdomains:    %d", len(result.subdomains))
        logger.info("Findings:      %d total", total)
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = summary.get(sev, 0)
            if count > 0:
                logger.info("  %-12s %d", sev + ":", count)
        logger.info("Wildcard:      %s", "Yes" if result.wildcard_detected else "No")
        logger.info("=" * 60)
