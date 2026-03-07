"""Reverse DNS (PTR) lookup operations."""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.reversename

from .models import Finding, Severity
from .utils import create_resolver

logger = logging.getLogger(__name__)


class ReverseDNSChecker:
    """Perform reverse DNS lookups and consistency checks."""

    def __init__(
        self,
        nameserver: str | None = None,
        timeout: float = 5.0,
        concurrency: int = 20,
    ):
        self.resolver = create_resolver(nameserver, timeout)
        self.concurrency = concurrency

    async def reverse_lookup(self, ip: str) -> str | None:
        """Perform a PTR lookup for a single IP address."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = await self.resolver.resolve(rev_name, "PTR")
            for rdata in answer:
                return str(rdata.target).rstrip(".")
        except Exception:
            return None

    async def bulk_reverse(self, ips: list[str]) -> dict[str, str | None]:
        """Concurrent reverse lookups for a list of IPs."""
        results: dict[str, str | None] = {}
        semaphore = asyncio.Semaphore(self.concurrency)

        async def lookup(ip: str) -> tuple[str, str | None]:
            async with semaphore:
                hostname = await self.reverse_lookup(ip)
                return ip, hostname

        tasks = [lookup(ip) for ip in set(ips)]
        completed = await asyncio.gather(*tasks)

        for ip, hostname in completed:
            if hostname:
                results[ip] = hostname
                logger.debug("PTR %s -> %s", ip, hostname)

        logger.info(
            "Reverse DNS: %d/%d IPs resolved", len(results), len(ips)
        )
        return results

    async def check_ptr_consistency(
        self,
        forward_map: dict[str, str],
        reverse_map: dict[str, str | None],
    ) -> list[Finding]:
        """Check forward/reverse DNS consistency.

        Args:
            forward_map: hostname -> IP from forward lookups
            reverse_map: IP -> hostname from reverse lookups
        """
        findings: list[Finding] = []
        mismatches: list[str] = []

        for hostname, ip in forward_map.items():
            if ip in reverse_map and reverse_map[ip]:
                ptr_hostname = reverse_map[ip]
                if ptr_hostname and ptr_hostname.lower() != hostname.lower():
                    mismatches.append(
                        f"{hostname} -> {ip} -> PTR: {ptr_hostname}"
                    )

        if mismatches:
            findings.append(
                Finding(
                    title="Forward/Reverse DNS Mismatch Detected",
                    severity=Severity.LOW,
                    description=(
                        "Some IP addresses have PTR records that do not match the "
                        "forward DNS hostname. This can indicate misconfiguration "
                        "or shared hosting."
                    ),
                    evidence="\n".join(mismatches[:10]),
                    remediation=(
                        "Ensure PTR records match forward DNS entries for proper "
                        "email deliverability and security tool compatibility."
                    ),
                    category="Reverse DNS",
                )
            )

        return findings
