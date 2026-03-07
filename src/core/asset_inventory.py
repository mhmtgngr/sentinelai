"""Asset inventory and attack surface management for Sentinel-AI.

Discovers and tracks assets from connected adapters (Defender devices,
Entra ID users, QRadar log sources, Palo Alto zones), calculates risk
scores, and provides attack surface analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    USER = "user"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    MOBILE_DEVICE = "mobile_device"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Asset:
    asset_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    asset_type: AssetType = AssetType.WORKSTATION
    ip_addresses: list[str] = field(default_factory=list)
    hostname: str = ""
    os: str = ""
    criticality: Criticality = Criticality.MEDIUM
    owner: str = ""
    department: str = ""
    tags: list[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = 0.0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    open_incidents: int = 0
    external_facing: bool = False
    adapter_source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class AssetInventory:
    """Central asset inventory with risk scoring and attack surface analysis."""

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._assets: dict[str, Asset] = {}
        self._assets_by_ip: dict[str, str] = {}  # ip -> asset_id
        self._assets_by_hostname: dict[str, str] = {}  # hostname -> asset_id
        self._discovery_history: list[dict[str, Any]] = []

    def add_asset(self, asset: Asset) -> Asset:
        """Add or update an asset in the inventory."""
        # Check for duplicates by hostname or IP
        existing_id = self._find_existing(asset)
        if existing_id:
            return self._merge_asset(existing_id, asset)

        self._assets[asset.asset_id] = asset
        self._index_asset(asset)
        asset.risk_score = self.calculate_risk_score(asset)
        return asset

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def find_by_ip(self, ip: str) -> Asset | None:
        aid = self._assets_by_ip.get(ip)
        return self._assets.get(aid) if aid else None

    def find_by_hostname(self, hostname: str) -> Asset | None:
        aid = self._assets_by_hostname.get(hostname.lower())
        return self._assets.get(aid) if aid else None

    def list_assets(
        self,
        asset_type: AssetType | None = None,
        criticality: Criticality | None = None,
        min_risk: float = 0.0,
    ) -> list[Asset]:
        assets = list(self._assets.values())
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        if criticality:
            assets = [a for a in assets if a.criticality == criticality]
        if min_risk > 0:
            assets = [a for a in assets if a.risk_score >= min_risk]
        return sorted(assets, key=lambda a: a.risk_score, reverse=True)

    def get_critical_assets(self) -> list[Asset]:
        return [a for a in self._assets.values() if a.criticality == Criticality.CRITICAL]

    def calculate_risk_score(self, asset: Asset) -> float:
        """Calculate risk score (0-100) based on multiple factors."""
        score = 0.0

        # Criticality base score
        crit_scores = {
            Criticality.CRITICAL: 40,
            Criticality.HIGH: 25,
            Criticality.MEDIUM: 15,
            Criticality.LOW: 5,
        }
        score += crit_scores.get(asset.criticality, 15)

        # Vulnerability count
        vuln_count = len(asset.vulnerabilities)
        high_vulns = sum(1 for v in asset.vulnerabilities if v.get("severity") in ("critical", "high"))
        score += min(vuln_count * 3, 20)
        score += min(high_vulns * 5, 15)

        # Open incidents
        score += min(asset.open_incidents * 5, 15)

        # External facing
        if asset.external_facing:
            score += 10

        return min(round(score, 1), 100.0)

    def get_attack_surface(self) -> dict[str, Any]:
        """Generate attack surface summary."""
        all_assets = list(self._assets.values())
        if not all_assets:
            return {
                "total_assets": 0,
                "by_type": {},
                "by_criticality": {},
                "external_facing": 0,
                "high_risk_assets": 0,
                "avg_risk_score": 0.0,
                "unpatched_count": 0,
                "total_vulnerabilities": 0,
            }

        by_type: dict[str, int] = {}
        by_crit: dict[str, int] = {}
        external = 0
        high_risk = 0
        total_vulns = 0
        total_risk = 0.0

        for asset in all_assets:
            by_type[asset.asset_type.value] = by_type.get(asset.asset_type.value, 0) + 1
            by_crit[asset.criticality.value] = by_crit.get(asset.criticality.value, 0) + 1
            if asset.external_facing:
                external += 1
            if asset.risk_score >= 60:
                high_risk += 1
            total_vulns += len(asset.vulnerabilities)
            total_risk += asset.risk_score

        return {
            "total_assets": len(all_assets),
            "by_type": by_type,
            "by_criticality": by_crit,
            "external_facing": external,
            "high_risk_assets": high_risk,
            "avg_risk_score": round(total_risk / len(all_assets), 1),
            "unpatched_count": sum(
                1 for a in all_assets
                if any(v.get("type") == "missing_patch" for v in a.vulnerabilities)
            ),
            "total_vulnerabilities": total_vulns,
        }

    async def discover_from_adapter(self, adapter_name: str, adapter: Any) -> list[Asset]:
        """Discover assets from a connected adapter."""
        discovered: list[Asset] = []

        try:
            if adapter_name in ("defender_xdr", "defender"):
                discovered = await self._discover_defender_devices(adapter)
            elif adapter_name in ("entra_id", "identity"):
                discovered = await self._discover_entra_users(adapter)
            elif adapter_name in ("qradar", "siem"):
                discovered = await self._discover_qradar_sources(adapter)
            elif adapter_name in ("palo_alto", "firewall"):
                discovered = await self._discover_firewall_zones(adapter)
        except Exception:
            logger.exception("Asset discovery failed for adapter: %s", adapter_name)

        for asset in discovered:
            self.add_asset(asset)

        if discovered:
            self._discovery_history.append({
                "adapter": adapter_name,
                "count": len(discovered),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            await self.event_bus.publish(Event(
                event_type=EventType.ASSET_DISCOVERED,
                data={"adapter": adapter_name, "count": len(discovered)},
                source="asset_inventory",
            ))

        return discovered

    async def _discover_defender_devices(self, adapter: Any) -> list[Asset]:
        """Discover devices from Microsoft Defender for Endpoint."""
        assets: list[Asset] = []
        try:
            # Use Defender's device list via Advanced Hunting
            results = await adapter.advanced_hunting(
                "DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId "
                "| project DeviceName, OSPlatform, PublicIP, DeviceType, "
                "MachineGroup, ExposureLevel"
            )
            for row in results.get("Results", []):
                asset_type = AssetType.SERVER if "server" in str(row.get("DeviceType", "")).lower() else AssetType.WORKSTATION
                criticality = Criticality.HIGH if row.get("ExposureLevel") == "High" else Criticality.MEDIUM

                asset = Asset(
                    name=row.get("DeviceName", ""),
                    hostname=row.get("DeviceName", ""),
                    asset_type=asset_type,
                    os=row.get("OSPlatform", ""),
                    criticality=criticality,
                    ip_addresses=[row["PublicIP"]] if row.get("PublicIP") else [],
                    external_facing=bool(row.get("PublicIP")),
                    adapter_source="defender_xdr",
                    tags=[row.get("MachineGroup", "")],
                    metadata=row,
                )
                assets.append(asset)
        except Exception:
            logger.exception("Defender device discovery failed")
        return assets

    async def _discover_entra_users(self, adapter: Any) -> list[Asset]:
        """Discover user accounts from Entra ID."""
        assets: list[Asset] = []
        try:
            risky_users = await adapter._graph_request("GET", "/identityProtection/riskyUsers")
            for user in risky_users.get("value", []):
                criticality = Criticality.HIGH if user.get("riskLevel") == "high" else Criticality.MEDIUM
                asset = Asset(
                    name=user.get("userDisplayName", user.get("userPrincipalName", "")),
                    asset_type=AssetType.USER,
                    criticality=criticality,
                    owner=user.get("userPrincipalName", ""),
                    adapter_source="entra_id",
                    metadata=user,
                )
                assets.append(asset)
        except Exception:
            logger.exception("Entra ID user discovery failed")
        return assets

    async def _discover_qradar_sources(self, adapter: Any) -> list[Asset]:
        """Discover log sources from QRadar."""
        assets: list[Asset] = []
        try:
            sources = await adapter.run_aql_query(
                "SELECT sourceip, UNIQUECOUNT(category) as categories "
                "FROM events GROUP BY sourceip LAST 24 HOURS"
            )
            for row in sources:
                asset = Asset(
                    name=f"qradar_source_{row.get('sourceip', '')}",
                    asset_type=AssetType.SERVER,
                    ip_addresses=[row["sourceip"]] if row.get("sourceip") else [],
                    adapter_source="qradar",
                    metadata=row,
                )
                assets.append(asset)
        except Exception:
            logger.exception("QRadar source discovery failed")
        return assets

    async def _discover_firewall_zones(self, adapter: Any) -> list[Asset]:
        """Discover network zones from Palo Alto."""
        assets: list[Asset] = []
        try:
            events = await adapter.get_events()
            seen_ips: set[str] = set()
            for ev in events:
                for ip_key in ("source_ip", "dest_ip"):
                    ip = ev.get(ip_key)
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        asset = Asset(
                            name=f"firewall_host_{ip}",
                            asset_type=AssetType.NETWORK_DEVICE,
                            ip_addresses=[ip],
                            adapter_source="palo_alto",
                        )
                        assets.append(asset)
        except Exception:
            logger.exception("Firewall zone discovery failed")
        return assets

    def _find_existing(self, asset: Asset) -> str | None:
        """Find existing asset by hostname or IP."""
        if asset.hostname:
            aid = self._assets_by_hostname.get(asset.hostname.lower())
            if aid:
                return aid
        for ip in asset.ip_addresses:
            aid = self._assets_by_ip.get(ip)
            if aid:
                return aid
        return None

    def _merge_asset(self, existing_id: str, new: Asset) -> Asset:
        """Merge new asset data into existing asset."""
        existing = self._assets[existing_id]
        existing.last_seen = datetime.now(timezone.utc)

        # Merge IPs
        for ip in new.ip_addresses:
            if ip not in existing.ip_addresses:
                existing.ip_addresses.append(ip)
                self._assets_by_ip[ip] = existing_id

        # Update fields if new data is more specific
        if new.os and not existing.os:
            existing.os = new.os
        if new.owner and not existing.owner:
            existing.owner = new.owner
        if new.criticality.value < existing.criticality.value:  # higher criticality
            existing.criticality = new.criticality

        for tag in new.tags:
            if tag and tag not in existing.tags:
                existing.tags.append(tag)

        existing.metadata.update(new.metadata)
        existing.risk_score = self.calculate_risk_score(existing)
        return existing

    def _index_asset(self, asset: Asset) -> None:
        """Index asset for fast lookup."""
        if asset.hostname:
            self._assets_by_hostname[asset.hostname.lower()] = asset.asset_id
        for ip in asset.ip_addresses:
            self._assets_by_ip[ip] = asset.asset_id
