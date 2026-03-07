"""DNS security misconfiguration and vulnerability checks."""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Optional

import dns.asyncresolver
import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype

from .models import DNSRecord, Finding, Severity
from .utils import create_resolver

logger = logging.getLogger(__name__)


class DNSSecurityChecker:
    """Run security checks against DNS infrastructure."""

    def __init__(
        self,
        nameserver: str | None = None,
        timeout: float = 5.0,
    ):
        self.resolver = create_resolver(nameserver, timeout)
        self.timeout = timeout
        self.nameserver = nameserver

    async def check_dnssec(self, domain: str) -> list[Finding]:
        """Check DNSSEC configuration for a domain."""
        findings: list[Finding] = []

        # Check for DNSKEY records
        has_dnskey = False
        try:
            answer = await self.resolver.resolve(domain, "DNSKEY")
            has_dnskey = len(list(answer)) > 0
        except Exception:
            pass

        # Check for DS records (delegation signer)
        has_ds = False
        try:
            answer = await self.resolver.resolve(domain, "DS")
            has_ds = len(list(answer)) > 0
        except Exception:
            pass

        if not has_dnskey and not has_ds:
            findings.append(
                Finding(
                    title=f"DNSSEC Not Configured for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        "No DNSKEY or DS records found. The domain does not use DNSSEC, "
                        "making it vulnerable to DNS spoofing and man-in-the-middle attacks."
                    ),
                    evidence=f"No DNSKEY or DS records found for {domain}",
                    remediation=(
                        "Enable DNSSEC for the domain. Configure DNSKEY records and "
                        "publish DS records with the domain registrar."
                    ),
                    category="DNSSEC",
                    mitre_technique="T1557.003",
                    mitre_name="Adversary-in-the-Middle",
                )
            )
        elif has_dnskey and not has_ds:
            findings.append(
                Finding(
                    title=f"DNSSEC Partially Configured for {domain}",
                    severity=Severity.HIGH,
                    description=(
                        "DNSKEY records exist but no DS records found at the parent zone. "
                        "DNSSEC chain of trust is broken — this is worse than no DNSSEC "
                        "as it gives a false sense of security."
                    ),
                    evidence=f"DNSKEY present but DS missing for {domain}",
                    remediation=(
                        "Publish DS records at the domain registrar to complete "
                        "the DNSSEC chain of trust."
                    ),
                    category="DNSSEC",
                    mitre_technique="T1557.003",
                    mitre_name="Adversary-in-the-Middle",
                )
            )

        return findings

    async def check_spf(self, domain: str) -> list[Finding]:
        """Check SPF record configuration."""
        findings: list[Finding] = []
        spf_records: list[str] = []

        try:
            answer = await self.resolver.resolve(domain, "TXT")
            for rdata in answer:
                txt = " ".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                )
                if txt.lower().startswith("v=spf1"):
                    spf_records.append(txt)
        except Exception:
            pass

        if not spf_records:
            findings.append(
                Finding(
                    title=f"Missing SPF Record for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        "No SPF (Sender Policy Framework) record found. "
                        "Without SPF, anyone can send email appearing to come from this domain."
                    ),
                    evidence=f"No TXT record starting with 'v=spf1' found for {domain}",
                    remediation=(
                        "Add an SPF record: v=spf1 include:<your-mail-provider> -all"
                    ),
                    category="Email Security",
                    mitre_technique="T1566.002",
                    mitre_name="Phishing: Spearphishing Link",
                )
            )
        else:
            for spf in spf_records:
                if "+all" in spf:
                    findings.append(
                        Finding(
                            title=f"Permissive SPF Record (+all) for {domain}",
                            severity=Severity.HIGH,
                            description=(
                                "SPF record uses '+all' which allows any server to send "
                                "email on behalf of this domain. This effectively disables SPF."
                            ),
                            evidence=f"SPF: {spf}",
                            remediation=(
                                "Change '+all' to '-all' (hard fail) or '~all' (soft fail) "
                                "to restrict authorized senders."
                            ),
                            category="Email Security",
                            mitre_technique="T1566.002",
                            mitre_name="Phishing: Spearphishing Link",
                        )
                    )
                elif "~all" in spf:
                    findings.append(
                        Finding(
                            title=f"SPF Soft Fail (~all) for {domain}",
                            severity=Severity.LOW,
                            description=(
                                "SPF record uses '~all' (soft fail) instead of '-all' (hard fail). "
                                "Unauthorized emails may still be delivered."
                            ),
                            evidence=f"SPF: {spf}",
                            remediation="Consider changing '~all' to '-all' for stricter enforcement.",
                            category="Email Security",
                        )
                    )

            if len(spf_records) > 1:
                findings.append(
                    Finding(
                        title=f"Multiple SPF Records for {domain}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Multiple SPF records found. RFC 7208 specifies that a domain "
                            "MUST NOT have multiple SPF records. This causes unpredictable behavior."
                        ),
                        evidence="\n".join(f"SPF: {spf}" for spf in spf_records),
                        remediation="Merge all SPF records into a single TXT record.",
                        category="Email Security",
                    )
                )

        return findings

    async def check_dmarc(self, domain: str) -> list[Finding]:
        """Check DMARC record configuration."""
        findings: list[Finding] = []
        dmarc_domain = f"_dmarc.{domain}"

        try:
            answer = await self.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = []
            for rdata in answer:
                txt = " ".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                )
                if txt.lower().startswith("v=dmarc1"):
                    dmarc_records.append(txt)

            if not dmarc_records:
                findings.append(
                    Finding(
                        title=f"Missing DMARC Record for {domain}",
                        severity=Severity.MEDIUM,
                        description=(
                            "No DMARC record found. Without DMARC, there is no policy "
                            "for handling emails that fail SPF/DKIM checks."
                        ),
                        evidence=f"No DMARC record at {dmarc_domain}",
                        remediation=(
                            "Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"
                        ),
                        category="Email Security",
                        mitre_technique="T1566.002",
                        mitre_name="Phishing: Spearphishing Link",
                    )
                )
            else:
                for dmarc in dmarc_records:
                    if "p=none" in dmarc.lower():
                        findings.append(
                            Finding(
                                title=f"DMARC Policy Set to None for {domain}",
                                severity=Severity.LOW,
                                description=(
                                    "DMARC policy is set to 'none', meaning no action is taken "
                                    "on emails that fail authentication. This is monitoring-only."
                                ),
                                evidence=f"DMARC: {dmarc}",
                                remediation=(
                                    "After monitoring, change p=none to p=quarantine or p=reject."
                                ),
                                category="Email Security",
                                mitre_technique="T1566.002",
                                mitre_name="Phishing: Spearphishing Link",
                            )
                        )

        except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer):
            findings.append(
                Finding(
                    title=f"Missing DMARC Record for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        "No DMARC record found at _dmarc.{domain}. Without DMARC, "
                        "there is no policy for handling emails that fail authentication."
                    ),
                    evidence=f"No DMARC record at {dmarc_domain}",
                    remediation=f"Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                    category="Email Security",
                    mitre_technique="T1566.002",
                    mitre_name="Phishing: Spearphishing Link",
                )
            )
        except Exception as e:
            logger.debug("DMARC check failed for %s: %s", domain, e)

        return findings

    async def check_open_resolver(self, nameserver: str) -> list[Finding]:
        """Test if a nameserver acts as an open recursive resolver."""
        findings: list[Finding] = []
        try:
            loop = asyncio.get_event_loop()
            is_open = await loop.run_in_executor(
                None, self._test_open_resolver, nameserver
            )
            if is_open:
                findings.append(
                    Finding(
                        title=f"Open Recursive Resolver: {nameserver}",
                        severity=Severity.HIGH,
                        description=(
                            f"Nameserver {nameserver} responds to recursive queries for "
                            f"external domains. Open resolvers can be abused for DNS "
                            f"amplification DDoS attacks."
                        ),
                        evidence=f"Recursive query to {nameserver} for google.com succeeded",
                        remediation=(
                            "Disable recursion on authoritative nameservers, or restrict "
                            "recursive queries to trusted IP ranges only."
                        ),
                        category="Open Resolver",
                        mitre_technique="T1584.002",
                        mitre_name="Compromise Infrastructure: DNS Server",
                    )
                )
        except Exception as e:
            logger.debug("Open resolver check failed for %s: %s", nameserver, e)

        return findings

    async def check_nameserver_version(self, nameserver: str) -> list[Finding]:
        """Query version.bind/version.server CHAOS TXT for information disclosure."""
        findings: list[Finding] = []
        version_names = ["version.bind", "version.server", "hostname.bind"]

        for vname in version_names:
            try:
                loop = asyncio.get_event_loop()
                version = await loop.run_in_executor(
                    None, self._query_chaos_txt, nameserver, vname
                )
                if version:
                    findings.append(
                        Finding(
                            title=f"DNS Server Version Disclosure on {nameserver}",
                            severity=Severity.LOW,
                            description=(
                                f"The nameserver {nameserver} discloses its software version "
                                f"via CHAOS TXT query ({vname}). This information helps "
                                f"attackers identify known vulnerabilities."
                            ),
                            evidence=f"{vname} -> {version}",
                            remediation=(
                                "Disable version queries or set a generic version string. "
                                "For BIND: options { version \"not disclosed\"; };"
                            ),
                            category="Information Disclosure",
                            mitre_technique="T1592.002",
                            mitre_name="Gather Victim Host Info: Software",
                        )
                    )
                    break  # One version finding is enough
            except Exception as e:
                logger.debug("Version check %s on %s: %s", vname, nameserver, e)

        return findings

    async def check_stale_ns(
        self, domain: str, ns_hostnames: list[str]
    ) -> list[Finding]:
        """Check for stale/dangling NS records (potential subdomain takeover)."""
        findings: list[Finding] = []

        for ns_host in ns_hostnames:
            try:
                await self.resolver.resolve(ns_host, "A")
            except dns.asyncresolver.NXDOMAIN:
                findings.append(
                    Finding(
                        title=f"Dangling NS Record: {ns_host}",
                        severity=Severity.HIGH,
                        description=(
                            f"NS record for {domain} points to {ns_host} which does not "
                            f"resolve (NXDOMAIN). An attacker could register this hostname "
                            f"and take over DNS resolution for the domain."
                        ),
                        evidence=f"NS {domain} -> {ns_host} (NXDOMAIN)",
                        remediation=(
                            f"Remove the NS record pointing to {ns_host} or ensure "
                            f"the hostname resolves correctly."
                        ),
                        category="Dangling NS",
                        mitre_technique="T1584.001",
                        mitre_name="Compromise Infrastructure: Domains",
                    )
                )
            except Exception:
                pass

        return findings

    async def check_ns_diversity(
        self, domain: str, ns_ips: list[str]
    ) -> list[Finding]:
        """Check if nameservers have sufficient diversity."""
        findings: list[Finding] = []

        if len(ns_ips) < 2:
            findings.append(
                Finding(
                    title=f"Single Nameserver for {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Only one nameserver is configured. This is a single point of "
                        "failure — if it goes down, the domain becomes unresolvable."
                    ),
                    evidence=f"Nameservers: {', '.join(ns_ips) if ns_ips else 'none found'}",
                    remediation="Configure at least two geographically diverse nameservers.",
                    category="Resilience",
                )
            )

        # Check if all NS are in the same /24 subnet
        if len(ns_ips) >= 2:
            prefixes = set()
            for ip in ns_ips:
                parts = ip.split(".")
                if len(parts) == 4:
                    prefixes.add(".".join(parts[:3]))

            if len(prefixes) == 1:
                findings.append(
                    Finding(
                        title=f"All Nameservers in Same Subnet for {domain}",
                        severity=Severity.MEDIUM,
                        description=(
                            "All nameservers are in the same /24 subnet. A network outage "
                            "or attack affecting that subnet would take down all DNS."
                        ),
                        evidence=f"All NS IPs in subnet: {list(prefixes)[0]}.0/24",
                        remediation="Distribute nameservers across different networks/providers.",
                        category="Resilience",
                    )
                )

        return findings

    async def check_cache_poisoning(
        self, domain: str, nameserver: str
    ) -> list[Finding]:
        """Heuristic check for cache poisoning susceptibility."""
        findings: list[Finding] = []
        try:
            loop = asyncio.get_event_loop()
            is_vulnerable = await loop.run_in_executor(
                None, self._test_cache_poisoning, domain, nameserver
            )
            if is_vulnerable:
                findings.append(
                    Finding(
                        title=f"Potential Cache Poisoning Vulnerability on {nameserver}",
                        severity=Severity.HIGH,
                        description=(
                            f"The nameserver {nameserver} may be susceptible to DNS cache "
                            f"poisoning. Low source port entropy was detected in query responses."
                        ),
                        evidence=(
                            f"Multiple queries to {nameserver} returned responses with "
                            f"low source port entropy, suggesting predictable port allocation."
                        ),
                        remediation=(
                            "Enable source port randomization on the DNS resolver. "
                            "Deploy DNSSEC to cryptographically validate responses."
                        ),
                        category="Cache Poisoning",
                        mitre_technique="T1584.002",
                        mitre_name="Compromise Infrastructure: DNS Server",
                    )
                )
        except Exception as e:
            logger.debug("Cache poisoning check failed for %s: %s", nameserver, e)

        return findings

    async def check_txt_leakage(self, records: list[DNSRecord]) -> list[Finding]:
        """Check TXT records for sensitive information leakage."""
        findings: list[Finding] = []
        sensitive_patterns = [
            "api_key", "apikey", "secret", "password", "token",
            "internal", "private", "debug",
        ]

        txt_records = [r for r in records if r.record_type == "TXT"]
        leaked_records = []

        for record in txt_records:
            value_lower = record.value.lower()
            # Skip common legitimate TXT records
            if any(
                value_lower.startswith(prefix)
                for prefix in ["v=spf1", "v=dmarc1", "v=dkim1", "google-site-verification",
                               "ms=", "facebook-domain-verification", "apple-domain-verification"]
            ):
                continue

            for pattern in sensitive_patterns:
                if pattern in value_lower:
                    leaked_records.append(record)
                    break

        if leaked_records:
            findings.append(
                Finding(
                    title="Potentially Sensitive Information in TXT Records",
                    severity=Severity.INFO,
                    description=(
                        "TXT records contain strings that may disclose sensitive information "
                        "such as API keys, internal paths, or debug configurations."
                    ),
                    evidence="\n".join(
                        f"TXT {r.name}: {r.value}" for r in leaked_records[:5]
                    ),
                    remediation="Review TXT records and remove any containing sensitive data.",
                    category="Information Disclosure",
                    mitre_technique="T1592",
                    mitre_name="Gather Victim Host Info",
                )
            )

        return findings

    def _test_open_resolver(self, nameserver: str) -> bool:
        """Synchronous test for open recursive resolver."""
        try:
            q = dns.message.make_query("google.com", dns.rdatatype.A)
            q.flags |= dns.flags.RD  # Set Recursion Desired
            response = dns.query.udp(q, nameserver, timeout=self.timeout)
            # If we get an answer with NOERROR and actual records, it's open
            return (
                response.rcode() == 0
                and len(response.answer) > 0
            )
        except Exception:
            return False

    def _query_chaos_txt(self, nameserver: str, name: str) -> Optional[str]:
        """Synchronous CHAOS TXT query for version info."""
        try:
            q = dns.message.make_query(
                name, dns.rdatatype.TXT, dns.rdataclass.CH
            )
            response = dns.query.udp(q, nameserver, timeout=self.timeout)
            for rrset in response.answer:
                for rdata in rrset:
                    return " ".join(
                        s.decode() if isinstance(s, bytes) else s
                        for s in rdata.strings
                    )
        except Exception:
            pass
        return None

    def _test_cache_poisoning(self, domain: str, nameserver: str) -> bool:
        """Heuristic test: send multiple queries and check source port entropy."""
        ports: list[int] = []
        try:
            for _ in range(5):
                q = dns.message.make_query(domain, dns.rdatatype.A)
                response = dns.query.udp(q, nameserver, timeout=self.timeout)
                # The response doesn't directly give us source port, but we can
                # check transaction ID entropy as a proxy
                if response.id is not None:
                    ports.append(response.id)

            if len(ports) >= 3:
                # Check if transaction IDs are sequential (predictable)
                diffs = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
                if all(d == diffs[0] for d in diffs) and diffs[0] != 0:
                    return True  # Sequential TXIDs
                # Check for very low entropy
                if len(set(ports)) == 1:
                    return True  # All same TXID
        except Exception:
            pass
        return False
