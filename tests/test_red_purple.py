"""Tests for Red Team, Purple Team, SOAR, Asset Inventory, Threat Modeling, Log Parser, and Reporting."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from src.core.event_bus import Event, EventBus, EventType
from src.core.asset_inventory import Asset, AssetInventory, AssetType, Criticality
from src.core.playbook_engine import Playbook, PlaybookEngine, PlaybookStep
from src.core.threat_modeling import ThreatModeler, STRIDECategory, Threat
from src.integrations.log_parser import LogParser
from src.agents.red_team_agent import (
    RedTeamAgent,
    TECHNIQUE_LIBRARY,
    CAMPAIGN_TEMPLATES,
    TACTIC_MAP,
)
from src.agents.purple_team_agent import PurpleTeamAgent


# ───────────────────────── Fixtures ─────────────────────────

@pytest_asyncio.fixture
async def event_bus():
    return EventBus()


@pytest_asyncio.fixture
async def red_team(event_bus):
    agent = RedTeamAgent(event_bus)
    await agent.initialize()
    return agent


@pytest_asyncio.fixture
async def purple_team(event_bus):
    agent = PurpleTeamAgent(event_bus)
    await agent.initialize()
    return agent


# ───────────────────────── Red Team Tests ─────────────────────────

class TestRedTeamAgent:
    """Red Team Agent tests."""

    @pytest.mark.asyncio
    async def test_technique_library_populated(self):
        """Technique library has entries across multiple tactics."""
        assert len(TECHNIQUE_LIBRARY) >= 30
        tactics = {t["tactic"] for t in TECHNIQUE_LIBRARY.values()}
        assert "initial_access" in tactics
        assert "execution" in tactics
        assert "lateral_movement" in tactics
        assert "exfiltration" in tactics
        assert "impact" in tactics

    @pytest.mark.asyncio
    async def test_simulate_technique(self, red_team):
        """Simulating a technique generates events."""
        result = await red_team.simulate_technique("T1059.001")
        assert result.technique_id == "T1059.001"
        assert result.technique_name == "PowerShell"
        assert result.status == "simulated"
        assert len(result.simulation_events) > 0

    @pytest.mark.asyncio
    async def test_simulate_unknown_technique(self, red_team):
        """Unknown technique returns error status."""
        result = await red_team.simulate_technique("T9999")
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_create_campaign(self, red_team):
        """Create a custom campaign."""
        campaign = red_team.create_campaign(
            name="Test Campaign",
            techniques=["T1059.001", "T1078"],
            description="Test",
        )
        assert campaign.name == "Test Campaign"
        assert campaign.status == "planned"
        assert len(campaign.techniques) == 2

    @pytest.mark.asyncio
    async def test_create_campaign_from_template(self, red_team):
        """Create campaign from pre-built template."""
        campaign = red_team.create_campaign_from_template("ransomware_simulation")
        assert "Ransomware" in campaign.name
        assert len(campaign.techniques) > 0

    @pytest.mark.asyncio
    async def test_run_campaign(self, red_team):
        """Run a campaign and get results."""
        campaign = red_team.create_campaign(
            name="Mini Campaign",
            techniques=["T1059.001", "T1078"],
        )
        result = await red_team.run_campaign(campaign.campaign_id)
        assert result.status == "completed"
        assert len(result.results) == 2
        assert "T1059.001" in result.results

    @pytest.mark.asyncio
    async def test_campaign_results(self, red_team):
        """Get detailed campaign results."""
        campaign = red_team.create_campaign(
            name="Results Test",
            techniques=["T1566.001"],
        )
        await red_team.run_campaign(campaign.campaign_id)
        results = red_team.get_campaign_results(campaign.campaign_id)
        assert results["total_techniques"] == 1
        assert results["status"] == "completed"
        assert "detection_coverage" in results

    @pytest.mark.asyncio
    async def test_list_techniques(self, red_team):
        """List all techniques."""
        all_techs = red_team.list_techniques()
        assert len(all_techs) >= 30

        exec_techs = red_team.list_techniques(tactic="execution")
        assert len(exec_techs) > 0
        assert all(t["tactic"] == "execution" for t in exec_techs)

    @pytest.mark.asyncio
    async def test_list_campaign_templates(self, red_team):
        """Campaign templates are available."""
        templates = red_team.list_campaign_templates()
        assert len(templates) >= 5
        names = [t["template_name"] for t in templates]
        assert "ransomware_simulation" in names
        assert "apt_simulation" in names

    @pytest.mark.asyncio
    async def test_simulation_publishes_events(self, red_team, event_bus):
        """Simulation publishes RED_TEAM_SIMULATION events."""
        events_received = []

        async def handler(event):
            events_received.append(event)

        event_bus.subscribe(EventType.RED_TEAM_SIMULATION, handler)
        await red_team.simulate_technique("T1003.001")
        assert len(events_received) > 0
        assert events_received[0].data["technique_id"] == "T1003.001"

    @pytest.mark.asyncio
    async def test_mark_technique_detected(self, red_team):
        """Mark a technique as detected updates status."""
        campaign = red_team.create_campaign("Detect Test", ["T1059.001"])
        await red_team.run_campaign(campaign.campaign_id)

        red_team.mark_technique_detected("T1059.001", campaign.campaign_id, "sigma_rule_1")
        assert campaign.results["T1059.001"].status == "detected"
        assert "sigma_rule_1" in campaign.results["T1059.001"].detected_by

    @pytest.mark.asyncio
    async def test_process_simulate_technique(self, red_team, event_bus):
        """Process event with simulate_technique action."""
        event = Event(
            event_type=EventType.RED_TEAM_SIMULATION,
            data={"action": "simulate_technique", "technique_id": "T1078"},
        )
        result = await red_team.process(event)
        assert result.success
        assert result.data["technique_id"] == "T1078"

    @pytest.mark.asyncio
    async def test_process_list_techniques(self, red_team, event_bus):
        """Process event with list_techniques action."""
        event = Event(
            event_type=EventType.RED_TEAM_SIMULATION,
            data={"action": "list_techniques", "tactic": "execution"},
        )
        result = await red_team.process(event)
        assert result.success
        assert result.data["count"] > 0

    @pytest.mark.asyncio
    async def test_tactic_map_complete(self):
        """All tactics in technique library are mapped."""
        for tech in TECHNIQUE_LIBRARY.values():
            assert tech["tactic"] in TACTIC_MAP

    @pytest.mark.asyncio
    async def test_simulation_history(self, red_team):
        """Simulation history is tracked."""
        await red_team.simulate_technique("T1059.001")
        await red_team.simulate_technique("T1078")
        history = red_team.get_simulation_history()
        assert len(history) == 2


# ───────────────────────── Purple Team Tests ─────────────────────────

class TestPurpleTeamAgent:
    """Purple Team Agent tests."""

    @pytest.mark.asyncio
    async def test_build_coverage_matrix(self, purple_team):
        """Build coverage matrix from technique library."""
        matrix = purple_team.build_coverage_matrix()
        assert isinstance(matrix, dict)
        assert len(purple_team._coverage) > 0

    @pytest.mark.asyncio
    async def test_coverage_score(self, purple_team):
        """Coverage score is calculated."""
        purple_team.build_coverage_matrix()
        score = purple_team.get_coverage_score()
        assert isinstance(score, float)
        assert 0 <= score <= 100

    @pytest.mark.asyncio
    async def test_detection_gaps(self, purple_team):
        """Detection gaps are identified."""
        purple_team.build_coverage_matrix()
        gaps = purple_team.get_detection_gaps()
        assert isinstance(gaps, list)
        # All gap entries have required fields
        for gap in gaps:
            assert "technique_id" in gap
            assert "gap_status" in gap
            assert "priority" in gap

    @pytest.mark.asyncio
    async def test_coverage_report(self, purple_team):
        """Coverage report contains all sections."""
        purple_team.build_coverage_matrix()
        report = purple_team.get_coverage_report()
        assert "coverage_score" in report
        assert "total_techniques" in report
        assert "by_tactic" in report
        assert "top_gaps" in report
        assert "recommendations" in report

    @pytest.mark.asyncio
    async def test_run_exercise(self, purple_team, red_team):
        """Run a purple team exercise."""
        purple_team.set_red_team(red_team)
        purple_team.build_coverage_matrix()

        exercise = await purple_team.run_exercise(["T1059.001", "T1078"], "Test Exercise")
        assert exercise.status == "completed"
        assert len(exercise.results) == 2
        assert exercise.results["T1059.001"]["simulated"]

    @pytest.mark.asyncio
    async def test_exercise_without_red_team(self, purple_team):
        """Exercise without red team agent records error."""
        exercise = await purple_team.run_exercise(["T1059.001"])
        assert exercise.results["T1059.001"]["simulated"] is False

    @pytest.mark.asyncio
    async def test_snapshot(self, purple_team):
        """Take coverage snapshot."""
        purple_team.build_coverage_matrix()
        snapshot = purple_team.take_snapshot()
        assert snapshot.total_techniques > 0
        assert isinstance(snapshot.coverage_score, float)

    @pytest.mark.asyncio
    async def test_snapshot_trend(self, purple_team):
        """Multiple snapshots form a trend."""
        purple_team.build_coverage_matrix()
        purple_team.take_snapshot()
        purple_team.take_snapshot()
        report = purple_team.get_coverage_report()
        assert len(report["trend"]) >= 2

    @pytest.mark.asyncio
    async def test_process_build_matrix(self, purple_team, event_bus):
        """Process event to build coverage matrix."""
        event = Event(
            event_type=EventType.PURPLE_TEAM_EXERCISE,
            data={"action": "build_coverage_matrix"},
        )
        result = await purple_team.process(event)
        assert result.success

    @pytest.mark.asyncio
    async def test_process_get_gaps(self, purple_team, event_bus):
        """Process event to get gaps."""
        purple_team.build_coverage_matrix()
        event = Event(
            event_type=EventType.PURPLE_TEAM_EXERCISE,
            data={"action": "get_gaps"},
        )
        result = await purple_team.process(event)
        assert result.success
        assert "gaps" in result.data

    @pytest.mark.asyncio
    async def test_autonomous_gap_analysis(self, purple_team):
        """Autonomous run performs gap analysis."""
        purple_team.build_coverage_matrix()
        results = await purple_team.run_autonomous()
        # May or may not have critical gaps
        assert isinstance(results, list)


# ───────────────────────── SOAR Playbook Engine Tests ─────────────────────────

class TestPlaybookEngine:
    """Playbook engine tests."""

    @pytest.mark.asyncio
    async def test_load_playbooks(self, event_bus):
        """Load playbooks from YAML directory."""
        engine = PlaybookEngine(event_bus)
        loaded = engine.load_playbooks("config/playbooks")
        assert loaded >= 1  # At least block_malicious_ip.yaml

    @pytest.mark.asyncio
    async def test_add_playbook(self, event_bus):
        """Manually add a playbook."""
        engine = PlaybookEngine(event_bus)
        playbook = Playbook(
            name="test_playbook",
            trigger={"conditions": {"severity": ["high", "critical"]}},
            steps=[PlaybookStep(name="step1", action="notify_soc")],
        )
        engine.add_playbook(playbook)
        playbooks = engine.get_playbooks()
        assert len(playbooks) == 1
        assert playbooks[0]["name"] == "test_playbook"

    @pytest.mark.asyncio
    async def test_evaluate_trigger_match(self, event_bus):
        """Trigger matches event data."""
        engine = PlaybookEngine(event_bus)
        playbook = Playbook(
            name="test",
            trigger={"conditions": {"severity": ["high", "critical"]}},
        )
        assert engine.evaluate_trigger(playbook, {"severity": "high"})
        assert not engine.evaluate_trigger(playbook, {"severity": "low"})

    @pytest.mark.asyncio
    async def test_find_matching_playbooks(self, event_bus):
        """Find playbooks matching event."""
        engine = PlaybookEngine(event_bus)
        pb1 = Playbook(name="pb1", trigger={"conditions": {"severity": ["high"]}})
        pb2 = Playbook(name="pb2", trigger={"conditions": {"severity": ["low"]}})
        engine.add_playbook(pb1)
        engine.add_playbook(pb2)

        matches = engine.find_matching_playbooks({"severity": "high"})
        assert len(matches) == 1
        assert matches[0].name == "pb1"

    @pytest.mark.asyncio
    async def test_execute_playbook(self, event_bus):
        """Execute a playbook with registered action handler."""
        engine = PlaybookEngine(event_bus)

        async def mock_handler(params, context):
            return {"notified": True}

        engine.register_action("notify_soc", mock_handler)

        playbook = Playbook(
            name="test_exec",
            steps=[PlaybookStep(name="Notify", action="notify_soc", params={"msg": "test"})],
        )
        engine.add_playbook(playbook)

        execution = await engine.execute_playbook("test_exec", {"alert_id": "123"})
        assert execution.status == "completed"
        assert len(execution.step_results) == 1
        assert execution.step_results[0].success

    @pytest.mark.asyncio
    async def test_execute_missing_handler(self, event_bus):
        """Step with missing handler records failure."""
        engine = PlaybookEngine(event_bus)
        playbook = Playbook(
            name="test_fail",
            steps=[PlaybookStep(name="Bad", action="nonexistent")],
        )
        engine.add_playbook(playbook)

        execution = await engine.execute_playbook("test_fail", {})
        assert execution.step_results[0].success is False
        assert "No handler" in execution.step_results[0].error

    @pytest.mark.asyncio
    async def test_template_resolution(self, event_bus):
        """Template variables in params are resolved."""
        engine = PlaybookEngine(event_bus)

        captured_params = {}

        async def capture_handler(params, context):
            captured_params.update(params)
            return {}

        engine.register_action("test_action", capture_handler)

        playbook = Playbook(
            name="template_test",
            steps=[PlaybookStep(
                name="Step",
                action="test_action",
                params={"ip": "{{ source_ip }}", "msg": "Blocked {{ attack_type }}"},
            )],
        )
        engine.add_playbook(playbook)

        await engine.execute_playbook("template_test", {
            "source_ip": "10.0.0.1",
            "attack_type": "brute_force",
        })
        assert captured_params["ip"] == "10.0.0.1"
        assert captured_params["msg"] == "Blocked brute_force"

    @pytest.mark.asyncio
    async def test_step_abort_on_failure(self, event_bus):
        """Playbook aborts if step fails with on_failure=abort."""
        engine = PlaybookEngine(event_bus)

        playbook = Playbook(
            name="abort_test",
            steps=[
                PlaybookStep(name="Fail", action="bad", on_failure="abort"),
                PlaybookStep(name="Never", action="bad2"),
            ],
        )
        engine.add_playbook(playbook)

        execution = await engine.execute_playbook("abort_test", {})
        assert execution.status == "aborted"
        assert len(execution.step_results) == 1

    @pytest.mark.asyncio
    async def test_execution_history(self, event_bus):
        """Execution history is tracked."""
        engine = PlaybookEngine(event_bus)
        playbook = Playbook(name="hist_test", steps=[])
        engine.add_playbook(playbook)

        await engine.execute_playbook("hist_test", {})
        await engine.execute_playbook("hist_test", {})

        history = engine.get_execution_history()
        assert len(history) == 2

    @pytest.mark.asyncio
    async def test_stats(self, event_bus):
        """Engine stats are calculated."""
        engine = PlaybookEngine(event_bus)
        stats = engine.get_stats()
        assert stats["playbooks_loaded"] == 0
        assert stats["total_executions"] == 0


# ───────────────────────── Asset Inventory Tests ─────────────────────────

class TestAssetInventory:
    """Asset inventory tests."""

    @pytest.mark.asyncio
    async def test_add_asset(self, event_bus):
        """Add an asset to inventory."""
        inv = AssetInventory(event_bus)
        asset = Asset(name="server-01", asset_type=AssetType.SERVER, hostname="server-01")
        result = inv.add_asset(asset)
        assert result.name == "server-01"
        assert inv.get_asset(asset.asset_id) is not None

    @pytest.mark.asyncio
    async def test_find_by_ip(self, event_bus):
        """Find asset by IP address."""
        inv = AssetInventory(event_bus)
        asset = Asset(name="web-01", ip_addresses=["10.0.0.5"])
        inv.add_asset(asset)
        found = inv.find_by_ip("10.0.0.5")
        assert found is not None
        assert found.name == "web-01"

    @pytest.mark.asyncio
    async def test_find_by_hostname(self, event_bus):
        """Find asset by hostname."""
        inv = AssetInventory(event_bus)
        asset = Asset(name="db-01", hostname="DB-01")
        inv.add_asset(asset)
        found = inv.find_by_hostname("db-01")
        assert found is not None
        assert found.name == "db-01"

    @pytest.mark.asyncio
    async def test_deduplicate_by_hostname(self, event_bus):
        """Assets with same hostname are merged."""
        inv = AssetInventory(event_bus)
        a1 = Asset(name="host-1", hostname="host-1", os="Windows")
        a2 = Asset(name="host-1", hostname="host-1", ip_addresses=["10.0.0.1"])
        inv.add_asset(a1)
        inv.add_asset(a2)
        all_assets = inv.list_assets()
        assert len(all_assets) == 1
        assert "10.0.0.1" in all_assets[0].ip_addresses

    @pytest.mark.asyncio
    async def test_risk_score(self, event_bus):
        """Risk score calculation."""
        inv = AssetInventory(event_bus)
        asset = Asset(
            name="critical-server",
            criticality=Criticality.CRITICAL,
            vulnerabilities=[
                {"id": "CVE-1", "severity": "critical"},
                {"id": "CVE-2", "severity": "high"},
            ],
            external_facing=True,
            open_incidents=2,
        )
        score = inv.calculate_risk_score(asset)
        assert score > 60  # High risk

    @pytest.mark.asyncio
    async def test_attack_surface_empty(self, event_bus):
        """Attack surface with no assets."""
        inv = AssetInventory(event_bus)
        surface = inv.get_attack_surface()
        assert surface["total_assets"] == 0

    @pytest.mark.asyncio
    async def test_attack_surface_populated(self, event_bus):
        """Attack surface with multiple assets."""
        inv = AssetInventory(event_bus)
        inv.add_asset(Asset(name="s1", asset_type=AssetType.SERVER, criticality=Criticality.CRITICAL))
        inv.add_asset(Asset(name="w1", asset_type=AssetType.WORKSTATION, external_facing=True))
        inv.add_asset(Asset(name="u1", asset_type=AssetType.USER))

        surface = inv.get_attack_surface()
        assert surface["total_assets"] == 3
        assert surface["external_facing"] == 1
        assert "server" in surface["by_type"]

    @pytest.mark.asyncio
    async def test_list_assets_filtered(self, event_bus):
        """Filter assets by type and criticality."""
        inv = AssetInventory(event_bus)
        inv.add_asset(Asset(name="s1", asset_type=AssetType.SERVER, criticality=Criticality.CRITICAL))
        inv.add_asset(Asset(name="w1", asset_type=AssetType.WORKSTATION))

        servers = inv.list_assets(asset_type=AssetType.SERVER)
        assert len(servers) == 1
        assert servers[0].name == "s1"

    @pytest.mark.asyncio
    async def test_critical_assets(self, event_bus):
        """Get critical assets."""
        inv = AssetInventory(event_bus)
        inv.add_asset(Asset(name="crit", criticality=Criticality.CRITICAL))
        inv.add_asset(Asset(name="low", criticality=Criticality.LOW))

        critical = inv.get_critical_assets()
        assert len(critical) == 1
        assert critical[0].name == "crit"


# ───────────────────────── Threat Modeling Tests ─────────────────────────

class TestThreatModeling:
    """Threat modeling tests."""

    def test_create_model(self):
        """Create a threat model with auto-generated threats."""
        modeler = ThreatModeler()
        model = modeler.create_model(
            name="Test Model",
            assets=[
                {"name": "web-server", "asset_type": "server"},
                {"name": "admin-user", "asset_type": "user"},
            ],
        )
        assert model.name == "Test Model"
        assert len(model.threats) > 0
        assert len(model.assets) == 2

    def test_stride_categories_covered(self):
        """All STRIDE categories are generated for server assets."""
        modeler = ThreatModeler()
        model = modeler.create_model(
            name="STRIDE Test",
            assets=[{"name": "server-1", "asset_type": "server"}],
        )
        categories = {t.category for t in model.threats}
        assert STRIDECategory.SPOOFING in categories
        assert STRIDECategory.TAMPERING in categories
        assert STRIDECategory.INFORMATION_DISCLOSURE in categories
        assert STRIDECategory.DENIAL_OF_SERVICE in categories
        assert STRIDECategory.ELEVATION_OF_PRIVILEGE in categories

    def test_risk_assessment(self):
        """Risk score and level calculation."""
        modeler = ThreatModeler()
        threat = Threat(likelihood=5, impact=5)
        assessed = modeler.assess_risk(threat)
        assert assessed.risk_score == 25
        assert assessed.risk_level.value == "critical"

        low_threat = Threat(likelihood=1, impact=1)
        assessed_low = modeler.assess_risk(low_threat)
        assert assessed_low.risk_score == 1
        assert assessed_low.risk_level.value == "negligible"

    def test_risk_matrix(self):
        """Generate risk matrix for a model."""
        modeler = ThreatModeler()
        model = modeler.create_model(
            name="Matrix Test",
            assets=[{"name": "srv", "asset_type": "server"}],
        )
        matrix = modeler.get_risk_matrix(model.model_id)
        assert "matrix" in matrix
        assert "summary" in matrix
        assert matrix["summary"]["total_threats"] > 0

    def test_model_report(self):
        """Generate comprehensive model report."""
        modeler = ThreatModeler()
        model = modeler.create_model(
            name="Report Test",
            assets=[{"name": "ws-1", "asset_type": "workstation"}],
        )
        report = modeler.get_model_report(model.model_id)
        assert report["name"] == "Report Test"
        assert len(report["threats"]) > 0
        assert "risk_matrix" in report

    def test_list_models(self):
        """List all threat models."""
        modeler = ThreatModeler()
        modeler.create_model("Model A", [{"name": "a", "asset_type": "server"}])
        modeler.create_model("Model B", [{"name": "b", "asset_type": "user"}])
        models = modeler.list_models()
        assert len(models) == 2

    def test_add_custom_threat(self):
        """Add a custom threat to a model."""
        modeler = ThreatModeler()
        model = modeler.create_model("Custom", [{"name": "x", "asset_type": "server"}])
        custom = Threat(
            title="Custom Threat",
            category=STRIDECategory.TAMPERING,
            likelihood=4,
            impact=5,
        )
        result = modeler.add_threat(model.model_id, custom)
        assert result is True
        assert model.threats[-1].title == "Custom Threat"


# ───────────────────────── Log Parser Tests ─────────────────────────

class TestLogParser:
    """Log parser tests."""

    def setup_method(self):
        self.parser = LogParser()

    def test_parse_cef(self):
        """Parse CEF format."""
        line = "CEF:0|Security|Firewall|1.0|100|Connection dropped|7|src=10.0.0.1 dst=192.168.1.1 spt=12345 dpt=80"
        result = self.parser.parse_cef(line)
        assert result.format == "cef"
        assert result.severity == "high"
        assert result.message == "Connection dropped"
        assert result.fields["src"] == "10.0.0.1"
        assert result.fields["vendor"] == "Security"

    def test_parse_leef(self):
        """Parse LEEF format."""
        line = "LEEF:1.0|IBM|QRadar|7.3|EventID123\tsev=5\tsrc=10.0.0.1\tdst=10.0.0.2"
        result = self.parser.parse_leef(line)
        assert result.format == "leef"
        assert result.fields["vendor"] == "IBM"
        assert result.fields["event_id"] == "EventID123"
        assert result.fields["src"] == "10.0.0.1"

    def test_parse_syslog_3164(self):
        """Parse RFC 3164 syslog."""
        line = "<134>Jan  5 14:30:00 myhost sshd[12345]: Failed password for root"
        result = self.parser.parse_syslog(line)
        assert result.format == "syslog_3164"
        assert result.source == "myhost"
        assert result.severity == "informational"
        assert "Failed password" in result.message

    def test_parse_syslog_5424(self):
        """Parse RFC 5424 syslog."""
        line = "<34>1 2024-01-05T14:30:00Z myhost sshd 12345 - - Failed password for root"
        result = self.parser.parse_syslog(line)
        assert result.format == "syslog_5424"
        assert result.source == "myhost"
        assert result.fields["app"] == "sshd"

    def test_parse_json(self):
        """Parse JSON log line."""
        data = {
            "timestamp": "2024-01-05T14:30:00Z",
            "level": "error",
            "message": "Connection timeout",
            "source": "web-server",
            "request_id": "abc123",
        }
        line = json.dumps(data)
        result = self.parser.parse_json(line)
        assert result.format == "json"
        assert result.severity == "error"
        assert result.message == "Connection timeout"
        assert result.source == "web-server"
        assert result.fields["request_id"] == "abc123"

    def test_parse_kv(self):
        """Parse key=value format."""
        line = 'timestamp=2024-01-05 severity=high message="Login failed" source=auth-service user=admin'
        result = self.parser.parse_kv(line)
        assert result.format == "kv"
        assert result.fields["severity"] == "high"
        assert result.fields["message"] == "Login failed"
        assert result.fields["user"] == "admin"

    def test_auto_detect_cef(self):
        """Auto-detect CEF format."""
        line = "CEF:0|Vendor|Product|1.0|1|Test|5|src=10.0.0.1"
        result = self.parser.detect_and_parse(line)
        assert result.format == "cef"

    def test_auto_detect_leef(self):
        """Auto-detect LEEF format."""
        line = "LEEF:1.0|IBM|QRadar|7.3|evt\tsev=3"
        result = self.parser.detect_and_parse(line)
        assert result.format == "leef"

    def test_auto_detect_json(self):
        """Auto-detect JSON format."""
        line = '{"level": "info", "message": "ok"}'
        result = self.parser.detect_and_parse(line)
        assert result.format == "json"

    def test_auto_detect_syslog(self):
        """Auto-detect syslog format."""
        line = "<134>Jan  5 14:30:00 host app: message"
        result = self.parser.detect_and_parse(line)
        assert "syslog" in result.format

    def test_empty_line(self):
        """Handle empty lines."""
        result = self.parser.detect_and_parse("")
        assert result.format == "empty"

    def test_plaintext_fallback(self):
        """Unknown format falls back to plaintext."""
        result = self.parser.detect_and_parse("Just some random text")
        assert result.format == "plaintext"
        assert result.message == "Just some random text"

    def test_cef_severity_mapping(self):
        """CEF severity values map correctly."""
        low = self.parser.parse_cef("CEF:0|V|P|1|1|Test|2|")
        assert low.severity == "info"

        high = self.parser.parse_cef("CEF:0|V|P|1|1|Test|8|")
        assert high.severity == "high"

        critical = self.parser.parse_cef("CEF:0|V|P|1|1|Test|10|")
        assert critical.severity == "critical"


# ───────────────────────── Integration Tests ─────────────────────────

class TestIntegration:
    """Cross-module integration tests."""

    @pytest.mark.asyncio
    async def test_red_purple_integration(self, event_bus):
        """Red team simulation feeds purple team detection tracking."""
        red = RedTeamAgent(event_bus)
        purple = PurpleTeamAgent(event_bus)
        await red.initialize()
        await purple.initialize()
        purple.set_red_team(red)

        purple.build_coverage_matrix()
        exercise = await purple.run_exercise(["T1059.001", "T1078"], "Integration Test")

        assert exercise.status == "completed"
        assert len(exercise.results) == 2
        assert exercise.results["T1059.001"]["simulated"]

    @pytest.mark.asyncio
    async def test_brain_new_components(self, event_bus):
        """Brain initializes new components."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)

        assert brain.asset_inventory is not None
        assert brain.playbook_engine is not None
        assert brain.threat_modeler is not None

    @pytest.mark.asyncio
    async def test_event_types_exist(self):
        """All new event types are accessible."""
        assert EventType.RED_TEAM_SIMULATION == "red_team.simulation"
        assert EventType.RED_TEAM_CAMPAIGN_STARTED == "red_team.campaign.started"
        assert EventType.RED_TEAM_CAMPAIGN_COMPLETED == "red_team.campaign.completed"
        assert EventType.PURPLE_TEAM_EXERCISE == "purple_team.exercise"
        assert EventType.COVERAGE_GAP_DETECTED == "purple_team.coverage_gap"
        assert EventType.PLAYBOOK_EXECUTED == "playbook.executed"
        assert EventType.ASSET_DISCOVERED == "asset.discovered"
        assert EventType.ATTACK_SURFACE_CHANGED == "asset.surface_changed"

    @pytest.mark.asyncio
    async def test_agent_capabilities_exist(self):
        """New agent capabilities exist."""
        from src.agents.base_agent import AgentCapability
        assert AgentCapability.RED_TEAM == "red_team"
        assert AgentCapability.PURPLE_TEAM == "purple_team"
        assert AgentCapability.ASSET_MANAGEMENT == "asset_management"
