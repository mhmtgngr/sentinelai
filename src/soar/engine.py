"""SOAR engine — executes automated response actions based on decisions."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.core.event_bus import (
    event_bus,
    ALERT_TRIAGED,
    DECISION_MADE,
    SOAR_ACTION_EXECUTED,
)
from src.core.models import (
    Alert,
    Decision,
    DecisionAction,
    SOARAction,
    TriageResult,
)

logger = logging.getLogger(__name__)


class SOAREngine:
    """Executes SOAR playbook actions — both autonomous and decision-triggered."""

    def __init__(self) -> None:
        self._action_handlers: dict[str, Any] = {}
        self._execution_log: list[SOARAction] = []
        event_bus.subscribe(DECISION_MADE, self.handle_decision)
        event_bus.subscribe(ALERT_TRIAGED, self.handle_auto_remediation)
        self._register_builtin_actions()

    def _register_builtin_actions(self) -> None:
        """Register built-in SOAR action handlers."""
        self._action_handlers = {
            "isolate_endpoint": self._action_isolate_endpoint,
            "block_ip": self._action_block_ip,
            "block_sender": self._action_block_sender,
            "disable_account": self._action_disable_account,
            "reset_password": self._action_reset_password,
            "quarantine_email": self._action_quarantine_email,
            "quarantine_file": self._action_quarantine_file,
            "scan_endpoint": self._action_scan_endpoint,
            "revoke_sessions": self._action_revoke_sessions,
            "enforce_mfa": self._action_enforce_mfa,
            "block_transfer": self._action_block_transfer,
            "notify_manager": self._action_notify_manager,
            "monitor_user": self._action_monitor_user,
            "patch_system": self._action_patch_system,
            "investigate": self._action_investigate,
            "monitor": self._action_monitor,
            "escalate": self._action_escalate,
            "educate_user": self._action_educate_user,
        }

    async def execute_action(self, soar_action: SOARAction) -> SOARAction:
        """Execute a single SOAR action."""
        handler = self._action_handlers.get(soar_action.action_type)
        if not handler:
            soar_action.status = "failed"
            soar_action.result = f"Unknown action type: {soar_action.action_type}"
            logger.error("No handler for action type: %s", soar_action.action_type)
        else:
            try:
                result = await handler(soar_action)
                soar_action.status = "completed"
                soar_action.result = result
                soar_action.executed_at = datetime.now(timezone.utc)
                logger.info(
                    "SOAR action %s (%s) completed: %s",
                    soar_action.id, soar_action.action_type, result,
                )
            except Exception as exc:
                soar_action.status = "failed"
                soar_action.result = str(exc)
                logger.exception("SOAR action %s failed", soar_action.id)

        self._execution_log.append(soar_action)
        await event_bus.publish(SOAR_ACTION_EXECUTED, {
            "action": soar_action.model_dump(mode="json"),
        })
        return soar_action

    async def execute_playbook(
        self, alert: Alert, actions: list[str], decision_id: str | None = None
    ) -> list[SOARAction]:
        """Execute a sequence of SOAR actions for an alert."""
        results = []
        for action_type in actions:
            target = self._resolve_target(alert, action_type)
            soar_action = SOARAction(
                alert_id=alert.id,
                decision_id=decision_id,
                action_type=action_type,
                target=target,
                parameters={
                    "affected_user": alert.affected_user,
                    "affected_endpoint": alert.affected_endpoint,
                    "affected_ip": alert.affected_ip,
                },
            )
            result = await self.execute_action(soar_action)
            results.append(result)
        return results

    async def handle_decision(self, data: dict) -> None:
        """React to a decision event and execute appropriate SOAR actions."""
        decision = Decision(**data["decision"])
        alert = Alert(**data["alert"])

        action_map: dict[DecisionAction, list[str]] = {
            DecisionAction.APPROVE_REMEDIATE: alert.recommended_actions,
            DecisionAction.ISOLATE_ENDPOINT: ["isolate_endpoint"],
            DecisionAction.BLOCK_IP: ["block_ip"],
            DecisionAction.DISABLE_ACCOUNT: ["disable_account"],
            DecisionAction.RESET_PASSWORD: ["reset_password"],
            DecisionAction.ESCALATE: ["escalate"],
            DecisionAction.EDUCATE_USER: ["educate_user"],
            DecisionAction.IGNORE: [],
        }
        actions = action_map.get(decision.action, alert.recommended_actions)
        if actions:
            await self.execute_playbook(alert, actions, decision.id)

    async def handle_auto_remediation(self, data: dict) -> None:
        """Auto-remediate low-severity alerts when autonomous mode is active."""
        triage = TriageResult(**data["triage"])
        if not triage.auto_remediation_possible:
            return
        alert = Alert(**data["alert"])
        logger.info("Auto-remediating alert %s", alert.id)
        safe_actions = [a for a in triage.recommended_actions if a not in ("escalate",)]
        if safe_actions:
            await self.execute_playbook(alert, safe_actions)

    def _resolve_target(self, alert: Alert, action_type: str) -> str:
        ip_actions = {"block_ip"}
        user_actions = {"disable_account", "reset_password", "revoke_sessions",
                        "enforce_mfa", "educate_user", "monitor_user", "notify_manager"}
        endpoint_actions = {"isolate_endpoint", "scan_endpoint", "quarantine_file",
                            "patch_system"}
        if action_type in ip_actions:
            return alert.affected_ip or "unknown"
        if action_type in user_actions:
            return alert.affected_user or "unknown"
        if action_type in endpoint_actions:
            return alert.affected_endpoint or "unknown"
        return alert.title

    # ── Built-in action handlers ──
    # In production these would call real APIs (firewall, EDR, IAM, etc.)

    async def _action_isolate_endpoint(self, action: SOARAction) -> str:
        logger.info("[SOAR] Isolating endpoint: %s", action.target)
        return f"Endpoint {action.target} isolated from network"

    async def _action_block_ip(self, action: SOARAction) -> str:
        logger.info("[SOAR] Blocking IP: %s", action.target)
        return f"IP {action.target} blocked on firewall"

    async def _action_block_sender(self, action: SOARAction) -> str:
        logger.info("[SOAR] Blocking sender for alert: %s", action.alert_id)
        return "Sender blocked in email gateway"

    async def _action_disable_account(self, action: SOARAction) -> str:
        logger.info("[SOAR] Disabling account: %s", action.target)
        return f"Account {action.target} disabled in IAM"

    async def _action_reset_password(self, action: SOARAction) -> str:
        logger.info("[SOAR] Forcing password reset: %s", action.target)
        return f"Password reset forced for {action.target}"

    async def _action_quarantine_email(self, action: SOARAction) -> str:
        logger.info("[SOAR] Quarantining email for alert: %s", action.alert_id)
        return "Email quarantined in mail gateway"

    async def _action_quarantine_file(self, action: SOARAction) -> str:
        logger.info("[SOAR] Quarantining file on: %s", action.target)
        return f"Malicious file quarantined on {action.target}"

    async def _action_scan_endpoint(self, action: SOARAction) -> str:
        logger.info("[SOAR] Triggering endpoint scan: %s", action.target)
        return f"Full scan initiated on {action.target}"

    async def _action_revoke_sessions(self, action: SOARAction) -> str:
        logger.info("[SOAR] Revoking sessions: %s", action.target)
        return f"All active sessions revoked for {action.target}"

    async def _action_enforce_mfa(self, action: SOARAction) -> str:
        logger.info("[SOAR] Enforcing MFA: %s", action.target)
        return f"MFA enforcement enabled for {action.target}"

    async def _action_block_transfer(self, action: SOARAction) -> str:
        logger.info("[SOAR] Blocking data transfer for alert: %s", action.alert_id)
        return "Data transfer blocked via DLP policy"

    async def _action_notify_manager(self, action: SOARAction) -> str:
        logger.info("[SOAR] Notifying manager for: %s", action.target)
        return f"Manager notified about policy violation by {action.target}"

    async def _action_monitor_user(self, action: SOARAction) -> str:
        logger.info("[SOAR] Enhanced monitoring: %s", action.target)
        return f"Enhanced monitoring enabled for {action.target}"

    async def _action_patch_system(self, action: SOARAction) -> str:
        logger.info("[SOAR] Scheduling patch: %s", action.target)
        return f"Patch deployment scheduled for {action.target}"

    async def _action_investigate(self, action: SOARAction) -> str:
        logger.info("[SOAR] Creating investigation task for alert: %s", action.alert_id)
        return "Investigation task created and assigned"

    async def _action_monitor(self, action: SOARAction) -> str:
        logger.info("[SOAR] Adding to watchlist: %s", action.alert_id)
        return "Added to active monitoring watchlist"

    async def _action_escalate(self, action: SOARAction) -> str:
        logger.info("[SOAR] Escalating alert: %s", action.alert_id)
        return "Alert escalated to senior security analyst"

    async def _action_educate_user(self, action: SOARAction) -> str:
        logger.info("[SOAR] Triggering education for: %s", action.target)
        # Education is handled by the education module via events
        return f"Education workflow triggered for {action.target}"
