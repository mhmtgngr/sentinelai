"""Zone transfer (AXFR) testing against nameservers."""

from __future__ import annotations

import logging

import dns.query
import dns.zone

from .models import DNSRecord, Finding, Severity

logger = logging.getLogger(__name__)


class ZoneTransferChecker:
    """Test nameservers for unauthorized zone transfer (AXFR)."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def attempt_transfer(
        self, domain: str, nameserver: str
    ) -> tuple[Finding | None, list[DNSRecord]]:
        """Attempt AXFR zone transfer against a nameserver.

        Returns a Critical finding if successful, along with any records obtained.
        This runs synchronously (dns.query.xfr is not async) but is called from async context.
        """
        records: list[DNSRecord] = []
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            zone_data = await loop.run_in_executor(
                None, self._do_transfer, domain, nameserver
            )

            if zone_data is None:
                return None, []

            # Parse transferred zone data
            for name, node in zone_data.nodes.items():
                fqdn = f"{name}.{domain}" if str(name) != "@" else domain
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(
                            DNSRecord(
                                record_type=dns.rdatatype.to_text(rdataset.rdtype),
                                name=str(fqdn),
                                value=str(rdata),
                                ttl=rdataset.ttl,
                                source="zone_transfer",
                            )
                        )

            finding = Finding(
                title=f"Zone Transfer (AXFR) Allowed on {nameserver}",
                severity=Severity.CRITICAL,
                description=(
                    f"The nameserver {nameserver} allows unauthorized zone transfers "
                    f"for {domain}. This exposes the entire DNS zone contents including "
                    f"all hostnames, IP addresses, and service records to any attacker."
                ),
                evidence=(
                    f"Successful AXFR transfer from {nameserver} for {domain}\n"
                    f"Records obtained: {len(records)}\n"
                    f"Sample records:\n"
                    + "\n".join(
                        f"  {r.record_type} {r.name} -> {r.value}"
                        for r in records[:10]
                    )
                ),
                remediation=(
                    "Restrict zone transfers to authorized secondary nameservers only. "
                    "Configure allow-transfer ACLs on the DNS server to limit AXFR "
                    "to specific IP addresses."
                ),
                category="Zone Transfer",
                mitre_technique="T1590.002",
                mitre_name="Gather Victim Network Info: DNS",
            )

            logger.warning(
                "CRITICAL: Zone transfer successful on %s for %s (%d records)",
                nameserver,
                domain,
                len(records),
            )
            return finding, records

        except Exception as e:
            logger.debug(
                "Zone transfer failed on %s for %s: %s", nameserver, domain, e
            )
            return None, []

    def _do_transfer(self, domain: str, nameserver: str) -> dns.zone.Zone | None:
        """Perform the actual zone transfer (synchronous)."""
        try:
            zone_data = dns.zone.from_xfr(
                dns.query.xfr(nameserver, domain, timeout=self.timeout)
            )
            return zone_data
        except Exception:
            return None
