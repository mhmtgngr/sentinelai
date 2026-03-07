"""Shared utilities for DNS reconnaissance."""

from __future__ import annotations

import ipaddress
import random
import string

import dns.asyncresolver
import dns.resolver


def create_resolver(
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> dns.asyncresolver.Resolver:
    """Create an async DNS resolver with optional custom nameserver."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def create_sync_resolver(
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> dns.resolver.Resolver:
    """Create a synchronous DNS resolver."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    return resolver


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def random_string(length: int = 16) -> str:
    """Generate a random string for wildcard detection probes."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
