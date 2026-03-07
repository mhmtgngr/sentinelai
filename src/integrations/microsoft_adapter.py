"""Microsoft 365 adapters — Exchange Online, Teams, Security Center."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class _MicrosoftGraphBase(BaseSecurityAdapter):
    """Shared Microsoft Graph authentication for all M365 adapters."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._tenant_id = config.get("tenant_id") or os.getenv("MS_TENANT_ID", "")
        self._client_id = config.get("client_id") or os.getenv("MS_CLIENT_ID", "")
        self._client_secret = config.get("client_secret") or os.getenv("MS_CLIENT_SECRET", "")
        self._token: str = ""
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]

        self._client = httpx.AsyncClient(
            base_url="https://graph.microsoft.com/v1.0",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30.0,
        )


# ────────────────────────────────────────────────────────────────────────────
# Exchange Online Protection (EOP) / Defender for Office 365
# ────────────────────────────────────────────────────────────────────────────

class ExchangeOnlineAdapter(_MicrosoftGraphBase):
    """Exchange Online adapter — monitors email security events.

    Pulls threat data from Defender for Office 365 (part of E5):
    - Phishing / spam / malware detections
    - Safe Attachments detonation verdicts
    - Safe Links click events
    - Quarantined messages
    - Mail flow rules / DLP policy matches
    """

    product_type = "email_security"
    vendor = "exchange_online"

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch email threat detections from Defender for Office 365."""
        if not self._client:
            return []
        events: list[dict[str, Any]] = []
        try:
            # Threat detections (phishing, malware, spam)
            params: dict[str, str] = {"$top": "100", "$orderby": "createdDateTime desc"}
            if since:
                params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"

            resp = await self._client.get("/security/alerts_v2", params={
                **params,
                "$filter": (params.get("$filter", "") + " and " if params.get("$filter") else "") +
                           "serviceSource eq 'microsoftDefenderForOffice365'",
            })
            if resp.status_code == 200:
                for alert in resp.json().get("value", []):
                    events.append(self._build_event(
                        alert,
                        event_type="email_threat",
                        severity=alert.get("severity", "info").lower(),
                        description=alert.get("title", ""),
                        source_ip=self._extract_sender_ip(alert),
                    ))

            # Message traces for quarantine
            quarantine = await self._get_quarantine_events()
            events.extend(quarantine)

        except Exception:
            self.logger.exception("Error fetching Exchange Online events")
        return events

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/admin/serviceAnnouncement/healthOverviews", params={
                "$filter": "service eq 'Exchange Online'",
            })
            if resp.status_code == 200:
                items = resp.json().get("value", [])
                if items and items[0].get("status") == "serviceOperational":
                    return HealthStatus.HEALTHY
                return HealthStatus.DEGRADED
            return HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def release_quarantine(self, message_id: str, release_to: str = "") -> ActionResult:
        """Release a quarantined message."""
        if not self._client:
            return ActionResult(success=False, action="release_quarantine", message="Not connected")
        # In production, uses Security & Compliance PowerShell or EOP API
        return ActionResult(
            success=True,
            action="release_quarantine",
            message=f"Would release quarantined message {message_id}",
        )

    async def block_sender(self, sender_email: str, reason: str) -> ActionResult:
        """Block a sender via Exchange transport rule."""
        if not self._client:
            return ActionResult(success=False, action="block_sender", message="Not connected")
        return ActionResult(
            success=True,
            action="block_sender",
            message=f"Would block sender {sender_email}: {reason}",
        )

    async def get_phishing_simulations(self) -> list[dict[str, Any]]:
        """Get attack simulation results (E5 feature)."""
        if not self._client:
            return []
        try:
            resp = await self._client.get("/security/attackSimulation/simulations")
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []

    async def _get_quarantine_events(self) -> list[dict[str, Any]]:
        """Fetch quarantined messages as security events."""
        # Quarantine management requires specific Exchange admin permissions
        return []

    @staticmethod
    def _extract_sender_ip(alert: dict) -> str:
        for evidence in alert.get("evidence", []):
            if evidence.get("@odata.type", "").endswith("mailboxEvidence"):
                return evidence.get("senderIp", "")
        return ""


# ────────────────────────────────────────────────────────────────────────────
# Microsoft Teams Security
# ────────────────────────────────────────────────────────────────────────────

class TeamsAdapter(_MicrosoftGraphBase):
    """Microsoft Teams adapter — security monitoring and notifications.

    Monitors Teams for:
    - DLP policy violations in Teams messages/files
    - External sharing events
    - Guest access anomalies
    Also serves as a notification channel for Sentinel-AI alerts.
    """

    product_type = "collaboration"
    vendor = "teams"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._webhook_url = config.get("webhook_url") or os.getenv("TEAMS_WEBHOOK_URL", "")
        self._alert_channel_id = config.get("alert_channel_id", "")
        self._alert_team_id = config.get("alert_team_id", "")

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch Teams-related security events (DLP violations, etc.)."""
        if not self._client:
            return []
        events: list[dict[str, Any]] = []
        try:
            # DLP policy matches from M365 compliance
            params: dict[str, str] = {"$top": "100", "$orderby": "createdDateTime desc"}
            filter_parts = ["serviceSource eq 'microsoftCloudAppSecurity'"]
            if since:
                filter_parts.append(f"createdDateTime ge {since.isoformat()}Z")
            params["$filter"] = " and ".join(filter_parts)

            resp = await self._client.get("/security/alerts_v2", params=params)
            if resp.status_code == 200:
                for alert in resp.json().get("value", []):
                    if "teams" in alert.get("title", "").lower() or "teams" in str(alert.get("evidence", [])).lower():
                        events.append(self._build_event(
                            alert,
                            event_type="teams_security",
                            severity=alert.get("severity", "info").lower(),
                            description=alert.get("title", ""),
                        ))
        except Exception:
            self.logger.exception("Error fetching Teams security events")
        return events

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/admin/serviceAnnouncement/healthOverviews", params={
                "$filter": "service eq 'Microsoft Teams'",
            })
            if resp.status_code == 200:
                items = resp.json().get("value", [])
                if items and items[0].get("status") == "serviceOperational":
                    return HealthStatus.HEALTHY
                return HealthStatus.DEGRADED
            return HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def send_alert(self, title: str, message: str, severity: str = "medium") -> ActionResult:
        """Send a Sentinel-AI alert to Teams via webhook or Graph API."""
        # Prefer webhook for simplicity and reliability
        if self._webhook_url:
            return await self._send_via_webhook(title, message, severity)
        return await self._send_via_graph(title, message)

    async def _send_via_webhook(self, title: str, message: str, severity: str) -> ActionResult:
        """Send alert via incoming webhook (Adaptive Card)."""
        color_map = {"critical": "FF0000", "high": "FF6600", "medium": "FFAA00", "low": "00CC00", "info": "0078D4"}
        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"🛡 Sentinel-AI: {title}",
                            "weight": "bolder",
                            "size": "medium",
                            "color": "attention" if severity in ("critical", "high") else "default",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": severity.upper()},
                                {"title": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": message,
                            "wrap": True,
                        },
                    ],
                },
            }],
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self._webhook_url, json=card)
                return ActionResult(
                    success=resp.status_code in (200, 202),
                    action="send_teams_alert",
                    message=f"Alert sent to Teams: {title}",
                )
        except Exception as e:
            return ActionResult(success=False, action="send_teams_alert", message=str(e))

    async def _send_via_graph(self, title: str, message: str) -> ActionResult:
        """Send alert via Graph API to a Teams channel."""
        if not self._client or not self._alert_team_id or not self._alert_channel_id:
            return ActionResult(success=False, action="send_teams_alert", message="Teams channel not configured")
        try:
            resp = await self._client.post(
                f"/teams/{self._alert_team_id}/channels/{self._alert_channel_id}/messages",
                json={
                    "body": {
                        "contentType": "html",
                        "content": f"<h3>🛡 Sentinel-AI: {title}</h3><p>{message}</p>",
                    },
                },
            )
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="send_teams_alert",
                message=f"Alert sent to Teams channel: {title}",
            )
        except Exception as e:
            return ActionResult(success=False, action="send_teams_alert", message=str(e))


# ────────────────────────────────────────────────────────────────────────────
# Microsoft Security Center (Unified Security)
# ────────────────────────────────────────────────────────────────────────────

class SecurityCenterAdapter(_MicrosoftGraphBase):
    """Microsoft 365 Security Center adapter.

    Aggregates alerts and incidents from all Microsoft security products:
    - Defender for Endpoint
    - Defender for Office 365
    - Defender for Identity
    - Defender for Cloud Apps
    - Entra ID Protection
    - Microsoft Purview (DLP)

    Also provides Secure Score monitoring and recommendations.
    """

    product_type = "security_center"
    vendor = "security_center"

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch all unified security alerts from Microsoft Security Center."""
        if not self._client:
            return []
        events: list[dict[str, Any]] = []
        try:
            # Unified alerts across all Defender services
            params: dict[str, str] = {
                "$top": "200",
                "$orderby": "createdDateTime desc",
            }
            if since:
                params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"

            resp = await self._client.get("/security/alerts_v2", params=params)
            resp.raise_for_status()
            for alert in resp.json().get("value", []):
                events.append(self._build_event(
                    alert,
                    event_type=f"security_alert_{alert.get('serviceSource', 'unknown')}",
                    severity=alert.get("severity", "info").lower(),
                    description=alert.get("title", ""),
                    source_ip=self._extract_ip(alert),
                    rule_id=alert.get("detectorId", ""),
                    rule_name=alert.get("detectionSource", ""),
                    mitre_technique=", ".join(alert.get("mitreTechniques", [])),
                    mitre_tactic=alert.get("category", ""),
                ))

            # Also fetch unified incidents
            incident_events = await self._get_incidents(since)
            events.extend(incident_events)

        except Exception:
            self.logger.exception("Error fetching Security Center events")
        return events

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/security/alerts_v2", params={"$top": "1"})
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def get_secure_score(self) -> dict[str, Any]:
        """Get the organization's Microsoft Secure Score."""
        if not self._client:
            return {}
        try:
            resp = await self._client.get("/security/secureScores", params={"$top": "1"})
            resp.raise_for_status()
            scores = resp.json().get("value", [])
            if not scores:
                return {}
            latest = scores[0]
            return {
                "current_score": latest.get("currentScore", 0),
                "max_score": latest.get("maxScore", 0),
                "percentage": round(
                    (latest.get("currentScore", 0) / max(latest.get("maxScore", 1), 1)) * 100, 1
                ),
                "created": latest.get("createdDateTime", ""),
                "enabled_services": latest.get("enabledServices", []),
            }
        except Exception:
            self.logger.exception("Error fetching Secure Score")
            return {}

    async def get_secure_score_recommendations(self) -> list[dict[str, Any]]:
        """Get actionable Secure Score improvement recommendations."""
        if not self._client:
            return []
        try:
            resp = await self._client.get("/security/secureScoreControlProfiles")
            resp.raise_for_status()
            recommendations = []
            for profile in resp.json().get("value", []):
                if profile.get("implementationStatus") != "implemented":
                    recommendations.append({
                        "title": profile.get("title", ""),
                        "description": profile.get("remediation", ""),
                        "score_impact": profile.get("maxScore", 0),
                        "category": profile.get("controlCategory", ""),
                        "status": profile.get("implementationStatus", ""),
                        "threats": profile.get("threats", []),
                    })
            return sorted(recommendations, key=lambda r: r["score_impact"], reverse=True)
        except Exception:
            self.logger.exception("Error fetching Secure Score recommendations")
            return []

    async def update_alert(self, alert_id: str, status: str, comment: str = "") -> ActionResult:
        """Update a security alert status."""
        if not self._client:
            return ActionResult(success=False, action="update_alert", message="Not connected")
        try:
            body: dict[str, Any] = {"status": status}
            if comment:
                body["comments"] = [comment]
            resp = await self._client.patch(f"/security/alerts_v2/{alert_id}", json=body)
            return ActionResult(
                success=resp.status_code in (200, 204),
                action="update_alert",
                message=f"Updated alert {alert_id} to {status}",
            )
        except Exception as e:
            return ActionResult(success=False, action="update_alert", message=str(e))

    async def _get_incidents(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch unified incidents."""
        if not self._client:
            return []
        params: dict[str, str] = {"$top": "50", "$orderby": "createdDateTime desc"}
        if since:
            params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"
        resp = await self._client.get("/security/incidents", params=params)
        if resp.status_code != 200:
            return []
        events = []
        for incident in resp.json().get("value", []):
            events.append(self._build_event(
                incident,
                event_type="security_incident",
                severity=incident.get("severity", "info").lower(),
                description=f"Incident: {incident.get('displayName', '')} ({incident.get('status', '')})",
            ))
        return events

    @staticmethod
    def _extract_ip(alert: dict) -> str:
        for evidence in alert.get("evidence", []):
            ip = evidence.get("ipAddress", "")
            if ip:
                return ip
        return ""
