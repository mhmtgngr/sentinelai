"""DNS record enumeration and subdomain brute-force discovery."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import dns.asyncresolver
import dns.name
import dns.rdatatype

from .models import DNSRecord
from .utils import create_resolver, random_string

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]


class DNSEnumerator:
    """Handles DNS record enumeration and subdomain discovery."""

    def __init__(
        self,
        nameserver: str | None = None,
        timeout: float = 5.0,
        concurrency: int = 50,
    ):
        self.resolver = create_resolver(nameserver, timeout)
        self.concurrency = concurrency

    async def enumerate_records(self, domain: str) -> list[DNSRecord]:
        """Query all standard DNS record types for a domain."""
        records: list[DNSRecord] = []

        tasks = [
            self._query_record(domain, rtype) for rtype in RECORD_TYPES
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                records.extend(result)

        logger.info("Enumerated %d DNS records for %s", len(records), domain)
        return records

    async def get_nameservers(self, domain: str) -> list[str]:
        """Resolve the NS records for a domain and return their IP addresses."""
        nameservers: list[str] = []
        try:
            answer = await self.resolver.resolve(domain, "NS")
            for rdata in answer:
                ns_name = str(rdata.target).rstrip(".")
                # Resolve NS hostname to IP
                try:
                    a_answer = await self.resolver.resolve(ns_name, "A")
                    for a_rdata in a_answer:
                        nameservers.append(str(a_rdata.address))
                except Exception:
                    nameservers.append(ns_name)
        except Exception as e:
            logger.warning("Failed to resolve NS records for %s: %s", domain, e)
        return nameservers

    async def get_nameserver_hostnames(self, domain: str) -> list[str]:
        """Get NS record hostnames (not IPs) for a domain."""
        hostnames: list[str] = []
        try:
            answer = await self.resolver.resolve(domain, "NS")
            for rdata in answer:
                hostnames.append(str(rdata.target).rstrip("."))
        except Exception as e:
            logger.warning("Failed to get NS hostnames for %s: %s", domain, e)
        return hostnames

    async def detect_wildcard(self, domain: str) -> Optional[str]:
        """Check if wildcard DNS is configured. Returns the wildcard IP or None."""
        random_sub = f"{random_string()}.{domain}"
        try:
            answer = await self.resolver.resolve(random_sub, "A")
            wildcard_ip = str(list(answer)[0].address)
            logger.info("Wildcard DNS detected for %s -> %s", domain, wildcard_ip)
            return wildcard_ip
        except (
            dns.asyncresolver.NXDOMAIN,
            dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers,
            dns.asyncresolver.LifetimeTimeout,
        ):
            return None
        except Exception as e:
            logger.debug("Wildcard check error for %s: %s", domain, e)
            return None

    async def brute_force_subdomains(
        self,
        domain: str,
        wordlist: list[str],
        wildcard_ip: str | None = None,
    ) -> list[str]:
        """Brute-force subdomains using async concurrent DNS lookups."""
        found: list[str] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_subdomain(word: str) -> Optional[str]:
            fqdn = f"{word}.{domain}"
            async with semaphore:
                try:
                    answer = await self.resolver.resolve(fqdn, "A")
                    ip = str(list(answer)[0].address)
                    if wildcard_ip and ip == wildcard_ip:
                        return None
                    logger.debug("Found subdomain: %s -> %s", fqdn, ip)
                    return fqdn
                except (
                    dns.asyncresolver.NXDOMAIN,
                    dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers,
                    dns.asyncresolver.LifetimeTimeout,
                ):
                    return None
                except Exception:
                    return None

        tasks = [check_subdomain(word) for word in wordlist]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                found.append(result)

        logger.info(
            "Subdomain brute force complete: %d found out of %d tested",
            len(found),
            len(wordlist),
        )
        return sorted(found)

    async def _query_record(
        self, domain: str, record_type: str
    ) -> list[DNSRecord]:
        """Query a specific DNS record type."""
        records: list[DNSRecord] = []
        try:
            answer = await self.resolver.resolve(domain, record_type)
            ttl = answer.rrset.ttl if answer.rrset else 0

            for rdata in answer:
                value = self._format_rdata(rdata, record_type)
                records.append(
                    DNSRecord(
                        record_type=record_type,
                        name=domain,
                        value=value,
                        ttl=ttl,
                        source="external_dns",
                    )
                )
        except (
            dns.asyncresolver.NXDOMAIN,
            dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers,
            dns.asyncresolver.LifetimeTimeout,
        ):
            pass
        except Exception as e:
            logger.debug("Query %s %s failed: %s", domain, record_type, e)

        return records

    @staticmethod
    def _format_rdata(rdata: dns.rdata.Rdata, record_type: str) -> str:
        """Format DNS rdata to a human-readable string."""
        if record_type == "MX":
            return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
        elif record_type == "NS":
            return str(rdata.target).rstrip(".")
        elif record_type == "SOA":
            return (
                f"{str(rdata.mname).rstrip('.')} {str(rdata.rname).rstrip('.')} "
                f"{rdata.serial} {rdata.refresh} {rdata.retry} "
                f"{rdata.expire} {rdata.minimum}"
            )
        elif record_type == "SRV":
            return (
                f"{rdata.priority} {rdata.weight} {rdata.port} "
                f"{str(rdata.target).rstrip('.')}"
            )
        elif record_type == "CNAME":
            return str(rdata.target).rstrip(".")
        elif record_type in ("A", "AAAA"):
            return str(rdata.address)
        elif record_type == "TXT":
            return " ".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
        else:
            return str(rdata)
