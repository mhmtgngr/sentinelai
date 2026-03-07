"""Purple Team Agent — ATT&CK coverage mapping and detection validation for Sentinel-AI.

Bridges Red Team attack simulations with Blue Team detection capabilities.
Maintains an ATT&CK coverage matrix, identifies detection gaps, coordinates
exercises, and tracks improvement trends over time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


@dataclass
class TechniqueCoverage:
    """Detection coverage status for a single ATT&CK technique."""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    has_detection: bool = False
    detection_sources: list[str] = field(default_factory=list)
    detection_rules: list[str] = field(default_factory=list)
    last_tested: datetime | None = None
    times_tested: int = 0
    times_detected: int = 0
    detection_rate: float = 0.0
    gap_status: str = "unknown"  # covered, partial, gap, unknown
    priority: str = "medium"  # critical, high, medium, low
    recommendations: list[str] = field(default_factory=list)


@dataclass
class Exercise:
    """A purple team exercise coordinating red + blue team activities."""
    exercise_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    technique_ids: list[str] = field(default_factory=list)
    campaign_id: str | None = None
    status: str = "planned"  # planned, running, completed
    results: dict[str, dict[str, Any]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    coverage_before: float = 0.0
    coverage_after: float = 0.0


@dataclass
class CoverageSnapshot:
    """Point-in-time snapshot of overall coverage metrics."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_techniques: int = 0
    covered: int = 0
    partial: int = 0
    gaps: int = 0
    coverage_score: float = 0.0
    by_tactic: dict[str, dict[str, int]] = field(default_factory=dict)


# Techniques commonly targeted by threat actors — higher priority for coverage
HIGH_PRIORITY_TECHNIQUES = {
    "T1566.001", "T1566.002",  # Phishing
    "T1059.001",  # PowerShell
    "T1078",  # Valid Accounts
    "T1003.001",  # LSASS Memory
    "T1021.001", "T1021.002",  # Lateral Movement (RDP, SMB)
    "T1486",  # Ransomware
    "T1071.001",  # Web C2
    "T1110.003",  # Password Spraying
    "T1547.001",  # Registry Persistence
    "T1562.001",  # Disable Tools
}


class PurpleTeamAgent(BaseAgent):
    """Purple Team Agent — Detection validation and ATT&CK coverage analysis.

    Coordinates between Red Team simulations and Blue Team detections to:
    1. Build and maintain an ATT&CK coverage matrix
    2. Identify detection gaps
    3. Run exercises that test specific techniques
    4. Track coverage improvement over time
    5. Recommend detection improvements
    """

    name = "purple_team"
    capability = AgentCapability.PURPLE_TEAM

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._coverage: dict[str, TechniqueCoverage] = {}
        self._exercises: dict[str, Exercise] = {}
        self._snapshots: list[CoverageSnapshot] = []
        self._detection_events: list[dict[str, Any]] = []  # recent detections
        self._red_team_agent: Any = None
        self._sigma_engine: Any = None
        self._threat_hunter: Any = None

    async def initialize(self) -> None:
        await super().initialize()
        # Subscribe to relevant events
        self.event_bus.subscribe(EventType.RED_TEAM_SIMULATION, self._handle_simulation)
        self.event_bus.subscribe(EventType.THREAT_DETECTED, self._handle_detection)
        self.event_bus.subscribe(EventType.ALERT_TRIAGED, self._handle_detection)

    def set_red_team(self, red_team: Any) -> None:
        self._red_team_agent = red_team

    def set_sigma_engine(self, sigma_engine: Any) -> None:
        self._sigma_engine = sigma_engine

    def set_threat_hunter(self, threat_hunter: Any) -> None:
        self._threat_hunter = threat_hunter

    async def process(self, event: Event) -> AgentResult:
        """Process purple team requests."""
        data = event.data
        action = data.get("action", "")

        if action == "build_coverage_matrix":
            matrix = self.build_coverage_matrix()
            return AgentResult(
                agent_name=self.name,
                action="build_coverage_matrix",
                success=True,
                data={"coverage": matrix, "score": self.get_coverage_score()},
            )

        if action == "get_gaps":
            gaps = self.get_detection_gaps()
            return AgentResult(
                agent_name=self.name,
                action="get_gaps",
                success=True,
                data={"gaps": gaps, "count": len(gaps)},
            )

        if action == "run_exercise":
            technique_ids = data.get("technique_ids", [])
            exercise = await self.run_exercise(technique_ids, data.get("name", ""))
            return AgentResult(
                agent_name=self.name,
                action="run_exercise",
                success=exercise.status == "completed",
                data={
                    "exercise_id": exercise.exercise_id,
                    "status": exercise.status,
                    "results": exercise.results,
                },
            )

        if action == "get_report":
            report = self.get_coverage_report()
            return AgentResult(
                agent_name=self.name,
                action="get_report",
                success=True,
                data=report,
            )

        return AgentResult(
            agent_name=self.name,
            action=action or "unknown",
            success=False,
            error=f"Unknown purple team action: {action}",
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Periodic coverage gap analysis."""
        results: list[AgentResult] = []

        # Rebuild coverage matrix
        self.build_coverage_matrix()

        # Check for new gaps
        gaps = self.get_detection_gaps()
        critical_gaps = [g for g in gaps if g.get("priority") == "critical"]

        if critical_gaps:
            await self.event_bus.publish(Event(
                event_type=EventType.COVERAGE_GAP_DETECTED,
                data={
                    "critical_gaps": len(critical_gaps),
                    "total_gaps": len(gaps),
                    "techniques": [g["technique_id"] for g in critical_gaps],
                },
                source="purple_team",
            ))

            results.append(AgentResult(
                agent_name=self.name,
                action="gap_analysis",
                success=True,
                data={
                    "critical_gaps": len(critical_gaps),
                    "total_gaps": len(gaps),
                    "coverage_score": self.get_coverage_score(),
                },
            ))

        # Take periodic snapshot
        self.take_snapshot()

        return results

    def build_coverage_matrix(self, technique_library: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
        """Build ATT&CK coverage matrix from detection sources.

        Scans sigma rules, hunting hypotheses, and adapter detection capabilities
        to map which ATT&CK techniques are covered.
        """
        # Import technique library if available
        if technique_library is None:
            try:
                from src.agents.red_team_agent import TECHNIQUE_LIBRARY
                technique_library = TECHNIQUE_LIBRARY
            except ImportError:
                technique_library = {}

        # Build coverage entries for each technique
        for tech_id, tech in technique_library.items():
            if tech_id not in self._coverage:
                self._coverage[tech_id] = TechniqueCoverage(
                    technique_id=tech_id,
                    technique_name=tech["name"],
                    tactic=tech["tactic"],
                )

            coverage = self._coverage[tech_id]
            coverage.technique_name = tech["name"]
            coverage.tactic = tech["tactic"]

            # Check detection sources
            detection_sources = self._check_detection_sources(tech_id, tech)
            coverage.detection_sources = detection_sources
            coverage.has_detection = len(detection_sources) > 0

            # Calculate detection rate from test history
            if coverage.times_tested > 0:
                coverage.detection_rate = round(coverage.times_detected / coverage.times_tested, 3)

            # Determine gap status
            if coverage.has_detection and coverage.detection_rate >= 0.7:
                coverage.gap_status = "covered"
            elif coverage.has_detection and coverage.detection_rate > 0:
                coverage.gap_status = "partial"
            elif coverage.has_detection and coverage.times_tested == 0:
                coverage.gap_status = "untested"
            else:
                coverage.gap_status = "gap"

            # Set priority
            if tech_id in HIGH_PRIORITY_TECHNIQUES:
                coverage.priority = "critical" if coverage.gap_status == "gap" else "high"
            else:
                coverage.priority = "high" if coverage.gap_status == "gap" else "medium"

            # Generate recommendations
            coverage.recommendations = self._generate_recommendations(coverage, tech)

        return self._format_matrix()

    def get_detection_gaps(self) -> list[dict[str, Any]]:
        """Get techniques with no detection or low detection rate."""
        gaps = []
        for tech_id, coverage in self._coverage.items():
            if coverage.gap_status in ("gap", "partial", "untested"):
                gaps.append({
                    "technique_id": tech_id,
                    "technique_name": coverage.technique_name,
                    "tactic": coverage.tactic,
                    "gap_status": coverage.gap_status,
                    "detection_rate": coverage.detection_rate,
                    "priority": coverage.priority,
                    "recommendations": coverage.recommendations,
                    "detection_sources": coverage.detection_sources,
                })

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gaps.sort(key=lambda g: priority_order.get(g["priority"], 99))
        return gaps

    def get_coverage_score(self) -> float:
        """Get overall coverage percentage."""
        if not self._coverage:
            return 0.0
        covered = sum(1 for c in self._coverage.values() if c.gap_status == "covered")
        partial = sum(1 for c in self._coverage.values() if c.gap_status == "partial")
        total = len(self._coverage)
        return round((covered + partial * 0.5) / max(total, 1) * 100, 1)

    def get_coverage_report(self) -> dict[str, Any]:
        """Full coverage report with matrix, scores, trends, and recommendations."""
        matrix = self._format_matrix()
        gaps = self.get_detection_gaps()
        score = self.get_coverage_score()

        # By-tactic breakdown
        by_tactic: dict[str, dict[str, int]] = {}
        for coverage in self._coverage.values():
            tactic = coverage.tactic
            if tactic not in by_tactic:
                by_tactic[tactic] = {"covered": 0, "partial": 0, "gap": 0, "untested": 0, "total": 0}
            by_tactic[tactic]["total"] += 1
            status_key = coverage.gap_status if coverage.gap_status in by_tactic[tactic] else "gap"
            by_tactic[tactic][status_key] += 1

        # Trend from snapshots
        trend = []
        for snap in self._snapshots[-10:]:
            trend.append({
                "timestamp": snap.timestamp.isoformat(),
                "coverage_score": snap.coverage_score,
                "covered": snap.covered,
                "gaps": snap.gaps,
            })

        # Top recommendations
        all_recs: list[dict[str, Any]] = []
        for gap in gaps[:10]:
            for rec in gap.get("recommendations", []):
                all_recs.append({
                    "technique": gap["technique_id"],
                    "recommendation": rec,
                    "priority": gap["priority"],
                })

        return {
            "coverage_score": score,
            "total_techniques": len(self._coverage),
            "covered": sum(1 for c in self._coverage.values() if c.gap_status == "covered"),
            "partial": sum(1 for c in self._coverage.values() if c.gap_status == "partial"),
            "gaps": sum(1 for c in self._coverage.values() if c.gap_status in ("gap", "untested")),
            "by_tactic": by_tactic,
            "top_gaps": gaps[:10],
            "trend": trend,
            "recommendations": all_recs[:15],
            "exercises_completed": sum(1 for e in self._exercises.values() if e.status == "completed"),
            "matrix": matrix,
        }

    async def run_exercise(
        self,
        technique_ids: list[str],
        name: str = "",
    ) -> Exercise:
        """Run a purple team exercise: simulate techniques and measure detection."""
        exercise = Exercise(
            name=name or f"Exercise {len(self._exercises) + 1}",
            technique_ids=technique_ids,
            coverage_before=self.get_coverage_score(),
        )
        self._exercises[exercise.exercise_id] = exercise
        exercise.status = "running"

        await self.event_bus.publish(Event(
            event_type=EventType.PURPLE_TEAM_EXERCISE,
            data={
                "exercise_id": exercise.exercise_id,
                "action": "started",
                "techniques": technique_ids,
            },
            source="purple_team",
        ))

        # Simulate each technique
        for tech_id in technique_ids:
            # Run red team simulation
            if self._red_team_agent:
                result = await self._red_team_agent.simulate_technique(tech_id)
                exercise.results[tech_id] = {
                    "simulated": True,
                    "simulation_status": result.status,
                    "detected": False,
                    "detected_by": [],
                }
            else:
                exercise.results[tech_id] = {
                    "simulated": False,
                    "error": "Red team agent not available",
                    "detected": False,
                    "detected_by": [],
                }

            # Update coverage tracking
            if tech_id in self._coverage:
                self._coverage[tech_id].times_tested += 1

        exercise.status = "completed"
        exercise.completed_at = datetime.now(timezone.utc)
        exercise.coverage_after = self.get_coverage_score()

        return exercise

    def take_snapshot(self) -> CoverageSnapshot:
        """Take a point-in-time coverage snapshot for trend tracking."""
        covered = sum(1 for c in self._coverage.values() if c.gap_status == "covered")
        partial = sum(1 for c in self._coverage.values() if c.gap_status == "partial")
        gaps = sum(1 for c in self._coverage.values() if c.gap_status in ("gap", "untested"))

        by_tactic: dict[str, dict[str, int]] = {}
        for coverage in self._coverage.values():
            tactic = coverage.tactic
            if tactic not in by_tactic:
                by_tactic[tactic] = {"covered": 0, "partial": 0, "gap": 0}
            if coverage.gap_status == "covered":
                by_tactic[tactic]["covered"] += 1
            elif coverage.gap_status == "partial":
                by_tactic[tactic]["partial"] += 1
            else:
                by_tactic[tactic]["gap"] += 1

        snapshot = CoverageSnapshot(
            total_techniques=len(self._coverage),
            covered=covered,
            partial=partial,
            gaps=gaps,
            coverage_score=self.get_coverage_score(),
            by_tactic=by_tactic,
        )
        self._snapshots.append(snapshot)

        # Keep last 100 snapshots
        if len(self._snapshots) > 100:
            self._snapshots = self._snapshots[-100:]

        return snapshot

    def get_exercise(self, exercise_id: str) -> Exercise | None:
        return self._exercises.get(exercise_id)

    def list_exercises(self) -> list[dict[str, Any]]:
        return [
            {
                "exercise_id": e.exercise_id,
                "name": e.name,
                "status": e.status,
                "techniques": len(e.technique_ids),
                "created_at": e.created_at.isoformat(),
                "coverage_before": e.coverage_before,
                "coverage_after": e.coverage_after,
            }
            for e in self._exercises.values()
        ]

    async def _handle_simulation(self, event: Event) -> None:
        """Track red team simulation events."""
        tech_id = event.data.get("technique_id", "")
        if tech_id and tech_id in self._coverage:
            self._coverage[tech_id].last_tested = datetime.now(timezone.utc)

    async def _handle_detection(self, event: Event) -> None:
        """Track blue team detection events and correlate with red team simulations."""
        data = event.data
        self._detection_events.append(data)

        # Keep only recent detections
        if len(self._detection_events) > 5000:
            self._detection_events = self._detection_events[-5000:]

        # Check if this detection correlates with a red team simulation
        mitre_ids = data.get("mitre_techniques", [])
        attack_type = data.get("attack_type", "")

        for tech_id in mitre_ids:
            if tech_id in self._coverage:
                self._coverage[tech_id].times_detected += 1
                detection_source = data.get("source", data.get("source_agent", "unknown"))
                if detection_source not in self._coverage[tech_id].detection_sources:
                    self._coverage[tech_id].detection_sources.append(detection_source)

                # Notify red team
                if self._red_team_agent:
                    self._red_team_agent.mark_technique_detected(
                        tech_id, detected_by=detection_source,
                    )

    def _check_detection_sources(
        self,
        technique_id: str,
        technique: dict[str, Any],
    ) -> list[str]:
        """Check which detection sources can detect this technique."""
        sources: list[str] = []

        # Check sigma rules
        if self._sigma_engine:
            for rule in self._sigma_engine._rules.values():
                tags = rule.tags or []
                for tag in tags:
                    if technique_id.lower() in tag.lower():
                        sources.append(f"sigma:{rule.title}")
                        break

        # Check threat hunter hypotheses
        if self._threat_hunter:
            for hyp in getattr(self._threat_hunter, '_hypotheses', []):
                mitre = hyp.get("mitre_technique", "")
                if technique_id in mitre:
                    sources.append(f"hunt:{hyp.get('name', 'hypothesis')}")

        # Check adapter-based detection (from technique library)
        adapter_sources = technique.get("detection_sources", [])
        for src in adapter_sources:
            source_name = f"adapter:{src}"
            if source_name not in sources:
                sources.append(source_name)

        # Check from actual detection history
        existing = self._coverage.get(technique_id)
        if existing:
            for src in existing.detection_sources:
                if src not in sources:
                    sources.append(src)

        return sources

    def _generate_recommendations(
        self,
        coverage: TechniqueCoverage,
        technique: dict[str, Any],
    ) -> list[str]:
        """Generate detection improvement recommendations."""
        recs: list[str] = []

        if coverage.gap_status == "gap":
            recs.append(f"Create Sigma detection rule for {coverage.technique_name} ({coverage.technique_id})")
            expected_sources = technique.get("detection_sources", [])
            if expected_sources:
                recs.append(f"Configure detection in: {', '.join(expected_sources)}")

        elif coverage.gap_status == "partial":
            if coverage.detection_rate < 0.5:
                recs.append(f"Improve detection rate for {coverage.technique_name} (currently {coverage.detection_rate:.0%})")
            if len(coverage.detection_sources) < 2:
                recs.append("Add additional detection sources for defense-in-depth")

        elif coverage.gap_status == "untested":
            recs.append(f"Run red team simulation to validate detection of {coverage.technique_name}")

        if coverage.priority == "critical":
            recs.append("HIGH PRIORITY: This technique is commonly used by threat actors")

        return recs

    def _format_matrix(self) -> dict[str, Any]:
        """Format coverage matrix for reporting."""
        matrix: dict[str, list[dict[str, Any]]] = {}
        for coverage in self._coverage.values():
            tactic = coverage.tactic
            if tactic not in matrix:
                matrix[tactic] = []
            matrix[tactic].append({
                "technique_id": coverage.technique_id,
                "technique_name": coverage.technique_name,
                "gap_status": coverage.gap_status,
                "detection_rate": coverage.detection_rate,
                "detection_sources": coverage.detection_sources,
                "priority": coverage.priority,
                "last_tested": coverage.last_tested.isoformat() if coverage.last_tested else None,
            })
        return matrix
