"""Central AI Brain — autonomous multi-agent coordinator for Sentinel-AI.

The brain operates autonomously: collecting events, triaging, detecting threats,
and responding — escalating to the human operator only at critical decision points.
All outcomes feed back into the self-learning system.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.asset_inventory import AssetInventory
from src.core.autonomous import AutonomousDecisionEngine, DecisionOutcome
from src.core.config import SentinelConfig
from src.core.event_bus import Event, EventBus, EventType
from src.core.playbook_engine import PlaybookEngine
from src.core.self_learning import SelfLearningSystem
from src.core.threat_modeling import ThreatModeler

logger = logging.getLogger(__name__)


class SentinelBrain:
    """Autonomous orchestrator with self-learning and human-in-the-loop at critical points.

    Autonomous loop:
    1. Heartbeat -> collect events from all adapters
    2. Triage agent scores and classifies each alert
    3. Check against learned false positive signatures -> auto-dismiss
    4. Run autonomous agent tasks (threat hunting, compliance, vuln scanning)
    5. For each proposed action:
       - Decision engine evaluates confidence
       - High confidence + safe action -> auto-execute
       - Low confidence / destructive action -> escalate to human
    6. All outcomes tracked -> self-learning adjusts thresholds

    Human involvement:
    - Approval queue for critical/destructive actions
    - Outcome feedback (was the action correct?)
    - Override capability at any point
    """

    def __init__(self, config: SentinelConfig, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self._agents: dict[str, Any] = {}
        self._adapters: dict[str, Any] = {}
        self._running = False
        self._heartbeat_task: asyncio.Task | None = None
        self._autonomous_task: asyncio.Task | None = None

        # Autonomous decision engine
        self.decision_engine = AutonomousDecisionEngine(event_bus)

        # Self-learning system
        self.learning = SelfLearningSystem(event_bus)

        # Asset inventory, playbook engine, threat modeler
        self.asset_inventory = AssetInventory(event_bus)
        self.playbook_engine = PlaybookEngine(event_bus)
        self.threat_modeler = ThreatModeler()

        # Track cycle metrics
        self._cycle_count = 0
        self._events_processed = 0
        self._actions_auto_executed = 0
        self._actions_escalated = 0

    def register_agent(self, name: str, agent: Any) -> None:
        self._agents[name] = agent
        logger.info("Registered agent: %s", name)

    def register_adapter(self, name: str, adapter: Any) -> None:
        self._adapters[name] = adapter
        logger.info("Registered adapter: %s", name)

    async def start(self) -> None:
        """Start the autonomous brain."""
        logger.info("Starting Sentinel-AI Brain (autonomous mode)...")
        self._running = True

        # Initialize all adapters
        for name, adapter in self._adapters.items():
            try:
                await adapter.connect()
                await self.event_bus.publish(Event(
                    event_type=EventType.ADAPTER_CONNECTED,
                    data={"adapter": name},
                    source="brain",
                ))
            except Exception:
                logger.exception("Failed to connect adapter: %s", name)

        # Initialize all agents
        for name, agent in self._agents.items():
            try:
                await agent.initialize()
            except Exception:
                logger.exception("Failed to initialize agent: %s", name)

        # Load playbooks
        self.playbook_engine.load_playbooks("config/playbooks")

        # Wire purple team to red team if both registered
        purple = self._agents.get("purple_team")
        red = self._agents.get("red_team")
        if purple and red:
            purple.set_red_team(red)

        # Subscribe to events
        self.event_bus.subscribe(EventType.ALERT_RECEIVED, self._handle_alert)
        self.event_bus.subscribe(EventType.THREAT_DETECTED, self._handle_threat)
        self.event_bus.subscribe(EventType.ACTION_EXECUTED, self._handle_action_outcome)
        self.event_bus.subscribe(EventType.ACTION_FAILED, self._handle_action_outcome)
        self.event_bus.subscribe(EventType.RED_TEAM_CAMPAIGN_COMPLETED, self._handle_red_team_result)

        # Start autonomous loops
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._autonomous_task = asyncio.create_task(self._autonomous_agent_loop())

        logger.info(
            "Sentinel-AI Brain started: %d agents, %d adapters (autonomous mode)",
            len(self._agents), len(self._adapters),
        )

    async def stop(self) -> None:
        """Gracefully stop the brain and take a learning snapshot."""
        logger.info("Stopping Sentinel-AI Brain...")
        self._running = False

        # Final learning snapshot
        self.learning.take_snapshot()

        for task in (self._heartbeat_task, self._autonomous_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        for name, adapter in self._adapters.items():
            try:
                await adapter.disconnect()
            except Exception:
                logger.exception("Error disconnecting adapter: %s", name)

        logger.info(
            "Sentinel-AI Brain stopped. Cycles: %d, Events: %d, Auto: %d, Escalated: %d",
            self._cycle_count, self._events_processed,
            self._actions_auto_executed, self._actions_escalated,
        )

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat — collect events from all adapters."""
        while self._running:
            try:
                self._cycle_count += 1
                await self.event_bus.publish(Event(
                    event_type=EventType.HEARTBEAT,
                    data={
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cycle": self._cycle_count,
                    },
                    source="brain",
                ))
                await self._collect_events()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in heartbeat loop")
            await asyncio.sleep(self.config.heartbeat_interval)

    async def _autonomous_agent_loop(self) -> None:
        """Run all agents' autonomous tasks periodically."""
        while self._running:
            try:
                for name, agent in self._agents.items():
                    try:
                        results = await agent.run_autonomous()
                        for result in results:
                            if result.success and result.data:
                                await self._process_agent_finding(name, result)
                    except Exception:
                        logger.exception("Error in autonomous task for agent: %s", name)

                # Periodic learning snapshot
                if self._cycle_count % 10 == 0 and self._cycle_count > 0:
                    self.learning.take_snapshot()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in autonomous agent loop")
            await asyncio.sleep(self.config.heartbeat_interval * 5)

    async def _collect_events(self) -> None:
        """Pull events from all connected adapters, filtering learned false positives."""
        for name, adapter in self._adapters.items():
            try:
                events = await adapter.get_events()
                for event_data in events:
                    self._events_processed += 1

                    # Check learned false positive signatures before processing
                    fp_score = self.learning.is_known_false_positive(event_data)
                    if fp_score > 0.8:
                        logger.debug("Suppressed learned FP (score=%.2f): %s",
                                     fp_score, event_data.get("description", "")[:80])
                        continue

                    await self.event_bus.publish(Event(
                        event_type=EventType.ALERT_RECEIVED,
                        data=event_data,
                        source=name,
                    ))
            except Exception:
                logger.exception("Error collecting events from adapter: %s", name)

    async def _handle_alert(self, event: Event) -> None:
        """Route incoming alert through the autonomous triage pipeline."""
        triage = self._agents.get("triage")
        if not triage:
            return

        result = await triage.process(event)

        # If triage escalated (high severity), publish as threat
        if result.success and result.data.get("severity_score", 0) >= 75:
            attack_type = result.data.get("attack_type", "unknown")
            severity = event.data.get("severity", "medium")

            # Get learned recommendations
            recommendations = self.learning.get_recommended_actions(attack_type, severity)
            confidence = recommendations[0]["confidence"] if recommendations else 0.6

            await self.event_bus.publish(Event(
                event_type=EventType.THREAT_DETECTED,
                data={
                    **result.data,
                    "learned_confidence": confidence,
                    "recommendations": recommendations[:3],
                },
                source="brain",
            ))

    async def _handle_threat(self, event: Event) -> None:
        """Handle detected threat — create incident, propose actions via decision engine."""
        responder = self._agents.get("incident_responder")
        if not responder:
            return

        result = await responder.process(event)
        if not result.success:
            return

        # Route each playbook action through the decision engine
        for action_record in result.data.get("actions_executed", []):
            action = action_record.get("action", "")
            severity = event.data.get("severity", "medium")
            base_confidence = event.data.get("learned_confidence", 0.7)

            decision = await self.decision_engine.propose_action(
                agent="incident_responder",
                action=action,
                target=event.data.get("source_ip", event.data.get("hostname", "unknown")),
                severity=severity,
                confidence=base_confidence,
                reasoning=[
                    f"Attack type: {event.data.get('attack_type', 'unknown')}",
                    f"Source: {event.data.get('source', 'unknown')}",
                    f"Playbook step for {event.data.get('attack_type', 'unknown')}",
                    f"Learned threshold: {self.learning.get_confidence_threshold(action):.0%}",
                ],
                evidence=[event.data],
                params=action_record.get("params", {}),
            )

            if decision.requires_approval:
                self._actions_escalated += 1
            else:
                self._actions_auto_executed += 1

    async def _process_agent_finding(self, agent_name: str, result: Any) -> None:
        """Process an autonomous agent finding."""
        data = result.data
        if result.action in ("periodic_scan", "correlate", "audit"):
            return  # Informational only

        if data.get("vulnerabilities_found", 0) > 0 or data.get("threats_found", 0) > 0:
            await self.event_bus.publish(Event(
                event_type=EventType.THREAT_DETECTED,
                data={**data, "source_agent": agent_name, "severity": data.get("severity", "medium")},
                source=agent_name,
            ))

    async def _handle_red_team_result(self, event: Event) -> None:
        """Feed red team campaign results to purple team for coverage analysis."""
        purple = self._agents.get("purple_team")
        if purple:
            purple.build_coverage_matrix()

    async def _handle_action_outcome(self, event: Event) -> None:
        """Track action outcomes for self-learning."""
        result_data = event.data.get("result", {})
        decision_id = result_data.get("decision_id", "")
        if not decision_id:
            return

        outcome = DecisionOutcome.SUCCESS if result_data.get("success") else DecisionOutcome.FAILURE
        await self.decision_engine.record_outcome(decision_id, outcome)

        decision = self.decision_engine.get_decision(decision_id)
        if decision:
            decision.outcome = outcome
            await self.learning.learn_from_decision(decision)

    async def record_human_feedback(
        self,
        decision_id: str,
        outcome: str,
        notes: str = "",
    ) -> dict[str, Any]:
        """Human operator provides feedback on a past decision.

        Outcomes: correct, wrong, false_positive, overreaction, missed_threat
        This feedback directly improves future autonomous decisions.
        """
        outcome_map = {
            "correct": DecisionOutcome.SUCCESS,
            "wrong": DecisionOutcome.FAILURE,
            "false_positive": DecisionOutcome.FALSE_POSITIVE,
            "overreaction": DecisionOutcome.OVERREACTION,
            "missed_threat": DecisionOutcome.MISSED_THREAT,
        }
        outcome_enum = outcome_map.get(outcome, DecisionOutcome.FAILURE)

        await self.decision_engine.record_outcome(decision_id, outcome_enum, notes)

        decision = self.decision_engine.get_decision(decision_id)
        if decision:
            decision.outcome = outcome_enum
            decision.outcome_notes = notes
            insights = await self.learning.learn_from_decision(decision)
            return {"decision_id": decision_id, "outcome": outcome, "insights": insights}
        return {"error": "Decision not found"}

    def get_status(self) -> dict[str, Any]:
        """Return full system status including autonomy and learning metrics."""
        status = {
            "running": self._running,
            "mode": "autonomous",
            "agents": list(self._agents.keys()),
            "adapters": list(self._adapters.keys()),
            "cycles": self._cycle_count,
            "events_processed": self._events_processed,
            "actions_auto_executed": self._actions_auto_executed,
            "actions_escalated": self._actions_escalated,
            "pending_approvals": len(self.decision_engine.get_pending_approvals()),
            "decision_stats": self.decision_engine.get_stats(),
            "learning": self.learning.get_learning_report(),
            "event_history_size": len(self.event_bus._history),
            "attack_surface": self.asset_inventory.get_attack_surface(),
            "playbook_stats": self.playbook_engine.get_stats(),
        }

        # Add purple team coverage if available
        purple = self._agents.get("purple_team")
        if purple:
            status["coverage_score"] = purple.get_coverage_score()

        return status
