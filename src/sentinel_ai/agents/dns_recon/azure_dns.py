"""Azure DNS client for fetching zones and records via Azure Management SDK."""

from __future__ import annotations

import logging
import os
from typing import Optional

from azure.identity import ClientSecretCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, Zone

from .models import AzureZoneInfo, DNSRecord, Finding, Severity

logger = logging.getLogger(__name__)


class AzureDNSClient:
    """Fetch DNS zones and records from Azure DNS using service principal auth."""

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subscription_id: str | None = None,
    ):
        self.tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        self.client_id = client_id or os.environ.get("AZURE_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET", "")
        self.subscription_id = subscription_id or os.environ.get(
            "AZURE_SUBSCRIPTION_ID", ""
        )

        if not all(
            [self.tenant_id, self.client_id, self.client_secret, self.subscription_id]
        ):
            raise ValueError(
                "Azure credentials required. Provide via arguments or env vars: "
                "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID"
            )

        self._credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        self._dns_client = DnsManagementClient(
            credential=self._credential,
            subscription_id=self.subscription_id,
        )

    def list_zones(self) -> list[AzureZoneInfo]:
        """List all DNS zones in the Azure subscription."""
        zones: list[AzureZoneInfo] = []
        for zone in self._dns_client.zones.list():
            # Extract resource group from zone ID
            # ID format: /subscriptions/.../resourceGroups/RG/providers/Microsoft.Network/dnsZones/name
            rg = self._extract_resource_group(zone.id or "")
            info = AzureZoneInfo(
                zone_name=zone.name or "",
                resource_group=rg,
                record_count=zone.number_of_record_sets or 0,
                nameservers=list(zone.name_servers or []),
            )
            zones.append(info)
            logger.info(
                "Found Azure DNS zone: %s (RG: %s, records: %d)",
                info.zone_name,
                info.resource_group,
                info.record_count,
            )
        return zones

    def get_zone_records(
        self, zone_name: str, resource_group: str
    ) -> list[DNSRecord]:
        """Fetch all record sets for a DNS zone."""
        records: list[DNSRecord] = []
        for rs in self._dns_client.record_sets.list_all_by_dns_zone(
            resource_group_name=resource_group,
            zone_name=zone_name,
        ):
            records.extend(self._parse_record_set(rs, zone_name))
        logger.info(
            "Fetched %d records from Azure zone %s", len(records), zone_name
        )
        return records

    def analyze_zone(
        self, zone_name: str, resource_group: str, records: list[DNSRecord]
    ) -> list[Finding]:
        """Run Azure-specific checks on zone data."""
        findings: list[Finding] = []

        # Check for wildcard records
        wildcard_records = [r for r in records if r.name.startswith("*.")]
        if wildcard_records:
            findings.append(
                Finding(
                    title=f"Wildcard DNS record found in Azure zone {zone_name}",
                    severity=Severity.INFO,
                    description=(
                        "Wildcard DNS records (*) were found in the Azure DNS zone. "
                        "This means any subdomain not explicitly defined will resolve."
                    ),
                    evidence="\n".join(
                        f"{r.record_type} {r.name} -> {r.value}"
                        for r in wildcard_records
                    ),
                    remediation=(
                        "Review wildcard records and ensure they are intentional. "
                        "Wildcard records can mask subdomain takeover vulnerabilities."
                    ),
                    category="Azure DNS",
                )
            )

        # Check for records with unusually long TTLs (> 1 week)
        long_ttl_records = [r for r in records if r.ttl > 604800]
        if long_ttl_records:
            findings.append(
                Finding(
                    title=f"Records with unusually long TTL in zone {zone_name}",
                    severity=Severity.LOW,
                    description=(
                        "Some DNS records have TTL values exceeding 1 week (604800s). "
                        "Long TTLs slow down DNS propagation during incidents."
                    ),
                    evidence="\n".join(
                        f"{r.record_type} {r.name} TTL={r.ttl}s"
                        for r in long_ttl_records[:10]
                    ),
                    remediation="Consider reducing TTL values to allow faster failover.",
                    category="Azure DNS",
                )
            )

        # Check for CNAME records at zone apex
        apex_cnames = [
            r
            for r in records
            if r.record_type == "CNAME" and r.name in (zone_name, f"{zone_name}.")
        ]
        if apex_cnames:
            findings.append(
                Finding(
                    title=f"CNAME record at zone apex for {zone_name}",
                    severity=Severity.MEDIUM,
                    description=(
                        "A CNAME record exists at the zone apex. This violates RFC 1034 "
                        "and can cause issues with other record types (MX, NS, SOA)."
                    ),
                    evidence="\n".join(
                        f"CNAME {r.name} -> {r.value}" for r in apex_cnames
                    ),
                    remediation="Use an ALIAS/ANAME record or A record at the zone apex instead.",
                    category="Azure DNS",
                )
            )

        # Check for dangling CNAME records pointing to external services
        external_cnames = [
            r
            for r in records
            if r.record_type == "CNAME"
            and any(
                svc in r.value.lower()
                for svc in [
                    "azurewebsites.net",
                    "cloudapp.azure.com",
                    "trafficmanager.net",
                    "blob.core.windows.net",
                    "azureedge.net",
                    "cloudfront.net",
                    "herokuapp.com",
                    "s3.amazonaws.com",
                    "github.io",
                    "firebaseapp.com",
                ]
            )
        ]
        if external_cnames:
            findings.append(
                Finding(
                    title=f"CNAME records pointing to external services in {zone_name}",
                    severity=Severity.MEDIUM,
                    description=(
                        "CNAME records point to external cloud services. If these services "
                        "are deprovisioned, the subdomains become vulnerable to takeover."
                    ),
                    evidence="\n".join(
                        f"CNAME {r.name} -> {r.value}" for r in external_cnames
                    ),
                    remediation=(
                        "Verify that all external service targets are active. "
                        "Remove CNAME records for deprovisioned services."
                    ),
                    category="Azure DNS",
                    mitre_technique="T1584.001",
                    mitre_name="Compromise Infrastructure: Domains",
                )
            )

        return findings

    def _parse_record_set(
        self, rs: RecordSet, zone_name: str
    ) -> list[DNSRecord]:
        """Convert an Azure RecordSet to our DNSRecord model."""
        records: list[DNSRecord] = []
        name = rs.name or "@"
        fqdn = f"{name}.{zone_name}" if name != "@" else zone_name
        ttl = rs.ttl or 3600

        if rs.a_records:
            for a in rs.a_records:
                records.append(
                    DNSRecord("A", fqdn, a.ipv4_address or "", ttl, "azure_api")
                )
        if rs.aaaa_records:
            for aaaa in rs.aaaa_records:
                records.append(
                    DNSRecord("AAAA", fqdn, aaaa.ipv6_address or "", ttl, "azure_api")
                )
        if rs.mx_records:
            for mx in rs.mx_records:
                records.append(
                    DNSRecord(
                        "MX",
                        fqdn,
                        f"{mx.preference} {mx.exchange}",
                        ttl,
                        "azure_api",
                    )
                )
        if rs.ns_records:
            for ns in rs.ns_records:
                records.append(
                    DNSRecord("NS", fqdn, ns.nsdname or "", ttl, "azure_api")
                )
        if rs.txt_records:
            for txt in rs.txt_records:
                value = " ".join(txt.value or [])
                records.append(DNSRecord("TXT", fqdn, value, ttl, "azure_api"))
        if rs.cname_record:
            records.append(
                DNSRecord(
                    "CNAME", fqdn, rs.cname_record.cname or "", ttl, "azure_api"
                )
            )
        if rs.soa_record:
            soa = rs.soa_record
            soa_value = (
                f"{soa.host} {soa.email} {soa.serial_number} "
                f"{soa.refresh_time} {soa.retry_time} {soa.expire_time} {soa.minimum_ttl}"
            )
            records.append(DNSRecord("SOA", fqdn, soa_value, ttl, "azure_api"))
        if rs.srv_records:
            for srv in rs.srv_records:
                records.append(
                    DNSRecord(
                        "SRV",
                        fqdn,
                        f"{srv.priority} {srv.weight} {srv.port} {srv.target}",
                        ttl,
                        "azure_api",
                    )
                )
        if rs.ptr_records:
            for ptr in rs.ptr_records:
                records.append(
                    DNSRecord("PTR", fqdn, ptr.ptrdname or "", ttl, "azure_api")
                )

        return records

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group name from Azure resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
