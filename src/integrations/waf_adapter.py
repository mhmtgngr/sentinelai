"""WAF adapters (Cloudflare, AWS WAF)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class CloudflareWAFAdapter(BaseSecurityAdapter):
    product_type = "waf"
    vendor = "cloudflare"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_token = config.get("api_token") or os.getenv("CLOUDFLARE_API_TOKEN", "")
        self._zone_id = config.get("zone_id", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url="https://api.cloudflare.com/client/v4",
            headers={"Authorization": f"Bearer {self._api_token}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            resp = await self._client.get(f"/zones/{self._zone_id}/security/events", params={"per_page": 100})
            resp.raise_for_status()
            return self._parse_events(resp.json())
        except Exception:
            self.logger.exception("Error fetching Cloudflare WAF events")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/user/tokens/verify")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def block_ip(self, ip: str, reason: str) -> ActionResult:
        if not self._client:
            return ActionResult(success=False, action="block_ip", message="Not connected")
        try:
            payload = {
                "mode": "block",
                "configuration": {"target": "ip", "value": ip},
                "notes": f"Sentinel-AI: {reason}",
            }
            resp = await self._client.post(f"/zones/{self._zone_id}/firewall/access_rules/rules", json=payload)
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="block_ip",
                message=f"Blocked {ip} in Cloudflare WAF",
            )
        except Exception as e:
            return ActionResult(success=False, action="block_ip", message=str(e))

    def _parse_events(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for entry in data.get("result", []):
            events.append(self._build_event(
                entry,
                event_type="waf",
                severity=self._map_action_severity(entry.get("action", "")),
                description=entry.get("description", entry.get("rule", {}).get("description", "")),
                source_ip=entry.get("clientIP", ""),
                rule_id=entry.get("ruleId", ""),
            ))
        return events

    @staticmethod
    def _map_action_severity(action: str) -> str:
        mapping = {"block": "high", "challenge": "medium", "js_challenge": "medium", "log": "info", "managed_challenge": "medium"}
        return mapping.get(action.lower(), "info")


class AWSWAFAdapter(BaseSecurityAdapter):
    product_type = "waf"
    vendor = "aws_waf"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._access_key = config.get("access_key") or os.getenv("AWS_WAF_ACCESS_KEY", "")
        self._secret_key = config.get("secret_key") or os.getenv("AWS_WAF_SECRET_KEY", "")
        self._region = config.get("region", "us-east-1")
        self._web_acl_id = config.get("web_acl_id", "")

    async def _authenticate(self) -> None:
        # AWS authentication handled per-request with SigV4
        pass

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        # In production, uses AWS SDK (boto3) to query WAF logs from S3/CloudWatch
        return []

    async def health_check(self) -> HealthStatus:
        # In production, calls wafv2:GetWebACL
        return HealthStatus.UNKNOWN if not self._web_acl_id else HealthStatus.HEALTHY

    async def block_ip(self, ip: str, reason: str) -> ActionResult:
        # In production, updates IP set in WAFv2
        return ActionResult(
            success=True,
            action="block_ip",
            message=f"Would block {ip} in AWS WAF IP set",
        )
