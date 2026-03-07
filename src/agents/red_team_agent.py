"""Red Team Agent — Attack simulation and adversary emulation for Sentinel-AI.

Provides MITRE ATT&CK-based attack simulation, campaign management,
and technique execution for validating blue team detection capabilities.
All simulations generate synthetic telemetry — no actual exploits.
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
class TechniqueResult:
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    status: str = "pending"  # pending, simulated, detected, missed
    simulation_events: list[dict[str, Any]] = field(default_factory=list)
    detected_by: list[str] = field(default_factory=list)
    detection_time_ms: float = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AttackCampaign:
    campaign_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    techniques: list[str] = field(default_factory=list)  # technique IDs
    target_scope: dict[str, Any] = field(default_factory=dict)
    status: str = "planned"  # planned, running, completed, aborted
    results: dict[str, TechniqueResult] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None


# MITRE ATT&CK technique library — key techniques for simulation
TECHNIQUE_LIBRARY: dict[str, dict[str, Any]] = {
    # Initial Access
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "initial_access",
        "description": "Adversaries send phishing emails with malicious attachments",
        "platforms": ["windows", "macos", "linux"],
        "simulation_indicators": {
            "event_type": "email_threat",
            "subject_keywords": ["urgent", "invoice", "payment"],
            "attachment_types": [".exe", ".docm", ".xlsm", ".js"],
            "sender_domain": "external",
        },
        "detection_sources": ["exchange_online", "defender_xdr"],
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "initial_access",
        "description": "Adversaries send phishing emails with malicious links",
        "platforms": ["windows", "macos", "linux"],
        "simulation_indicators": {
            "event_type": "email_threat",
            "url_indicators": ["login", "verify", "update"],
            "link_type": "credential_harvest",
        },
        "detection_sources": ["exchange_online", "defender_xdr"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial_access",
        "description": "Adversaries use stolen credentials to access systems",
        "platforms": ["windows", "azure_ad", "saas"],
        "simulation_indicators": {
            "event_type": "suspicious_login",
            "anomalies": ["impossible_travel", "new_device", "tor_exit_node"],
            "risk_level": "high",
        },
        "detection_sources": ["entra_id", "qradar"],
    },
    # Execution
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "execution",
        "description": "Adversaries use PowerShell for execution and scripting",
        "platforms": ["windows"],
        "simulation_indicators": {
            "process_name": "powershell.exe",
            "command_patterns": ["-enc", "-nop", "IEX", "Invoke-Expression", "downloadstring"],
            "event_type": "process_creation",
        },
        "detection_sources": ["defender_xdr", "sigma_rules", "qradar"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "execution",
        "description": "Adversaries use cmd.exe for execution",
        "platforms": ["windows"],
        "simulation_indicators": {
            "process_name": "cmd.exe",
            "command_patterns": ["certutil", "bitsadmin", "wmic", "mshta"],
            "parent_process": "winword.exe",
            "event_type": "process_creation",
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "execution",
        "description": "User opens a malicious file triggering execution",
        "platforms": ["windows", "macos"],
        "simulation_indicators": {
            "event_type": "file_execution",
            "file_origin": "internet",
            "file_types": [".exe", ".scr", ".hta", ".js"],
        },
        "detection_sources": ["defender_xdr"],
    },
    # Persistence
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "description": "Adversaries add programs to startup locations",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "registry_modification",
            "registry_keys": [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1136.001": {
        "name": "Local Account",
        "tactic": "persistence",
        "description": "Adversaries create local accounts for persistence",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "account_creation",
            "account_type": "local",
            "suspicious": True,
        },
        "detection_sources": ["defender_xdr", "entra_id", "qradar"],
    },
    # Privilege Escalation
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactic": "privilege_escalation",
        "description": "Adversaries bypass UAC to elevate privileges",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "uac_bypass",
            "techniques": ["fodhelper", "eventvwr", "sdclt"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "privilege_escalation",
        "description": "Adversaries exploit vulnerabilities to escalate privileges",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "exploit_attempt",
            "target": "kernel",
            "severity": "critical",
        },
        "detection_sources": ["defender_xdr", "qradar"],
    },
    # Defense Evasion
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "defense_evasion",
        "description": "Adversaries disable security tools",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "service_stopped",
            "service_names": ["WinDefend", "MsMpSvc", "SecurityHealthService"],
        },
        "detection_sources": ["defender_xdr", "security_center"],
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "defense_evasion",
        "description": "Adversaries clear event logs to cover tracks",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "log_cleared",
            "log_names": ["Security", "System", "Application"],
        },
        "detection_sources": ["qradar", "sigma_rules"],
    },
    # Credential Access
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "credential_access",
        "description": "Adversaries dump LSASS process memory for credentials",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "process_access",
            "target_process": "lsass.exe",
            "tools": ["mimikatz", "procdump", "comsvcs.dll"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules", "qradar"],
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "credential_access",
        "description": "Adversaries try one password against many accounts",
        "platforms": ["windows", "azure_ad", "saas"],
        "simulation_indicators": {
            "event_type": "authentication_failure",
            "pattern": "multiple_users_same_password",
            "failure_count": 50,
            "timeframe_minutes": 10,
        },
        "detection_sources": ["entra_id", "qradar", "defender_xdr"],
    },
    # Discovery
    "T1087.002": {
        "name": "Domain Account Discovery",
        "tactic": "discovery",
        "description": "Adversaries enumerate domain accounts",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "ldap_query",
            "queries": ["(objectClass=user)", "net user /domain"],
        },
        "detection_sources": ["defender_xdr", "qradar"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "discovery",
        "description": "Adversaries scan for open ports and services",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "port_scan",
            "ports_scanned": 100,
            "timeframe_seconds": 60,
        },
        "detection_sources": ["palo_alto", "qradar", "defender_xdr"],
    },
    # Lateral Movement
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral_movement",
        "description": "Adversaries use RDP to move between systems",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "rdp_session",
            "source": "internal",
            "anomalies": ["first_time_source", "off_hours"],
        },
        "detection_sources": ["defender_xdr", "qradar", "palo_alto"],
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "lateral_movement",
        "description": "Adversaries use admin shares for lateral movement",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "smb_connection",
            "share_names": ["C$", "ADMIN$", "IPC$"],
            "lateral": True,
        },
        "detection_sources": ["defender_xdr", "qradar"],
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "lateral_movement",
        "description": "Adversaries transfer tools between systems",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "file_transfer",
            "internal_to_internal": True,
            "file_types": [".exe", ".dll", ".ps1", ".bat"],
        },
        "detection_sources": ["defender_xdr", "palo_alto"],
    },
    # Collection
    "T1114.002": {
        "name": "Remote Email Collection",
        "tactic": "collection",
        "description": "Adversaries access email to collect sensitive information",
        "platforms": ["office365", "exchange"],
        "simulation_indicators": {
            "event_type": "mailbox_access",
            "access_type": "delegate",
            "bulk_operations": True,
        },
        "detection_sources": ["exchange_online", "security_center"],
    },
    # Command and Control
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "command_and_control",
        "description": "Adversaries use HTTP/HTTPS for C2 communication",
        "platforms": ["windows", "linux", "macos"],
        "simulation_indicators": {
            "event_type": "network_connection",
            "protocol": "https",
            "beacon_pattern": True,
            "interval_seconds": 60,
            "jitter": 0.2,
        },
        "detection_sources": ["palo_alto", "qradar", "defender_xdr"],
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "command_and_control",
        "description": "Adversaries use DNS for C2 tunneling",
        "platforms": ["windows", "linux", "macos"],
        "simulation_indicators": {
            "event_type": "dns_query",
            "query_patterns": ["long_subdomain", "high_frequency", "txt_records"],
            "entropy": "high",
        },
        "detection_sources": ["palo_alto", "qradar"],
    },
    # Exfiltration
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Protocol",
        "tactic": "exfiltration",
        "description": "Adversaries exfiltrate data over unencrypted channels",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "data_transfer",
            "protocol": "http",
            "data_volume_mb": 100,
            "destination": "external",
        },
        "detection_sources": ["palo_alto", "qradar", "defender_xdr"],
    },
    "T1567.002": {
        "name": "Exfiltration to Cloud Storage",
        "tactic": "exfiltration",
        "description": "Adversaries upload data to cloud storage services",
        "platforms": ["windows", "macos"],
        "simulation_indicators": {
            "event_type": "cloud_upload",
            "services": ["dropbox", "mega", "onedrive_personal"],
            "data_volume_mb": 50,
        },
        "detection_sources": ["palo_alto", "security_center"],
    },
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "description": "Adversaries encrypt data for ransomware impact",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "file_encryption",
            "file_count": 1000,
            "extension_change": True,
            "ransom_note": True,
        },
        "detection_sources": ["defender_xdr", "qradar"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "impact",
        "description": "Adversaries delete backups and shadow copies",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "process_creation",
            "commands": ["vssadmin delete shadows", "wbadmin delete catalog", "bcdedit /set recoveryenabled no"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    # Additional key techniques
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "persistence",
        "description": "Adversaries create scheduled tasks for persistence",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "scheduled_task_creation",
            "suspicious_patterns": ["encoded_command", "hidden", "system_account"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules", "qradar"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "defense_evasion",
        "description": "Adversaries inject code into processes",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "process_injection",
            "techniques": ["dll_injection", "process_hollowing", "thread_hijacking"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense_evasion",
        "description": "Adversaries obfuscate payloads to evade detection",
        "platforms": ["windows", "linux", "macos"],
        "simulation_indicators": {
            "event_type": "file_creation",
            "obfuscation": ["base64", "xor", "packed", "encrypted"],
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "description": "Adversaries manipulate accounts for persistence",
        "platforms": ["windows", "azure_ad"],
        "simulation_indicators": {
            "event_type": "account_modification",
            "changes": ["add_to_admin_group", "add_credentials", "modify_permissions"],
        },
        "detection_sources": ["entra_id", "qradar", "security_center"],
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactic": "credential_access",
        "description": "Adversaries request service tickets for offline cracking",
        "platforms": ["windows"],
        "simulation_indicators": {
            "event_type": "kerberos_request",
            "request_type": "TGS",
            "encryption_type": "RC4",
            "volume": "high",
        },
        "detection_sources": ["defender_xdr", "qradar", "sigma_rules"],
    },
    "T1560.001": {
        "name": "Archive via Utility",
        "tactic": "collection",
        "description": "Adversaries compress collected data before exfiltration",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "process_creation",
            "tools": ["7z", "rar", "zip", "tar"],
            "large_archive": True,
        },
        "detection_sources": ["defender_xdr", "sigma_rules"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "command_and_control",
        "description": "Adversaries download tools from external sources",
        "platforms": ["windows", "linux"],
        "simulation_indicators": {
            "event_type": "file_download",
            "tools": ["certutil", "bitsadmin", "powershell", "curl", "wget"],
            "source": "external",
        },
        "detection_sources": ["palo_alto", "defender_xdr", "sigma_rules"],
    },
}

# Pre-built campaign templates
CAMPAIGN_TEMPLATES: dict[str, dict[str, Any]] = {
    "ransomware_simulation": {
        "name": "Ransomware Attack Chain",
        "description": "Full ransomware kill chain: phishing → execution → persistence → credential theft → lateral movement → encryption",
        "techniques": [
            "T1566.001", "T1204.002", "T1059.001", "T1547.001",
            "T1003.001", "T1021.002", "T1486", "T1490",
        ],
    },
    "apt_simulation": {
        "name": "APT-style Intrusion",
        "description": "Advanced persistent threat: spearphishing → execution → persistence → discovery → lateral movement → exfiltration",
        "techniques": [
            "T1566.002", "T1078", "T1059.001", "T1053.005",
            "T1087.002", "T1046", "T1021.001", "T1560.001", "T1048.003",
        ],
    },
    "insider_threat": {
        "name": "Insider Threat Scenario",
        "description": "Malicious insider: valid accounts → email collection → archive → exfiltration",
        "techniques": [
            "T1078", "T1114.002", "T1560.001", "T1567.002",
        ],
    },
    "credential_theft": {
        "name": "Credential Theft Campaign",
        "description": "Credential-focused: password spraying → credential dumping → kerberoasting → account manipulation",
        "techniques": [
            "T1110.003", "T1003.001", "T1558.003", "T1098",
        ],
    },
    "defense_evasion_test": {
        "name": "Defense Evasion Testing",
        "description": "Test evasion detection: disable tools → log clearing → obfuscation → process injection",
        "techniques": [
            "T1562.001", "T1070.001", "T1027", "T1055",
        ],
    },
}

# Map tactics to MITRE ATT&CK tactic IDs
TACTIC_MAP = {
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


class RedTeamAgent(BaseAgent):
    """Red Team Agent — Attack simulation and adversary emulation.

    Simulates MITRE ATT&CK techniques by generating synthetic telemetry events
    that mirror real attack indicators. Does NOT execute real exploits.
    Results feed into the Purple Team agent for detection validation.
    """

    name = "red_team"
    capability = AgentCapability.RED_TEAM

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._campaigns: dict[str, AttackCampaign] = {}
        self._simulation_history: list[TechniqueResult] = []
        self._scheduled_campaigns: list[str] = []  # campaign IDs to run

    async def process(self, event: Event) -> AgentResult:
        """Handle red team exercise requests."""
        data = event.data
        action = data.get("action", "")

        if action == "simulate_technique":
            technique_id = data.get("technique_id", "")
            scope = data.get("target_scope", {})
            result = await self.simulate_technique(technique_id, scope)
            return AgentResult(
                agent_name=self.name,
                action="simulate_technique",
                success=result.status != "error",
                data={
                    "technique_id": technique_id,
                    "technique_name": result.technique_name,
                    "status": result.status,
                    "simulation_events": result.simulation_events,
                },
            )

        if action == "run_campaign":
            campaign_id = data.get("campaign_id", "")
            template = data.get("template", "")
            if template and template in CAMPAIGN_TEMPLATES:
                campaign = self.create_campaign_from_template(template, data.get("target_scope", {}))
                campaign_id = campaign.campaign_id
            if campaign_id:
                result = await self.run_campaign(campaign_id)
                return AgentResult(
                    agent_name=self.name,
                    action="run_campaign",
                    success=result.status == "completed",
                    data={
                        "campaign_id": campaign_id,
                        "name": result.name,
                        "status": result.status,
                        "techniques_tested": len(result.results),
                        "techniques_detected": sum(
                            1 for r in result.results.values() if r.status == "detected"
                        ),
                    },
                )

        if action == "list_techniques":
            tactic = data.get("tactic")
            techniques = self.list_techniques(tactic)
            return AgentResult(
                agent_name=self.name,
                action="list_techniques",
                success=True,
                data={"techniques": techniques, "count": len(techniques)},
            )

        return AgentResult(
            agent_name=self.name,
            action=action or "unknown",
            success=False,
            error=f"Unknown red team action: {action}",
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Run scheduled attack simulations."""
        results: list[AgentResult] = []

        for campaign_id in list(self._scheduled_campaigns):
            campaign = self._campaigns.get(campaign_id)
            if campaign and campaign.status == "planned":
                completed = await self.run_campaign(campaign_id)
                results.append(AgentResult(
                    agent_name=self.name,
                    action="scheduled_campaign",
                    success=completed.status == "completed",
                    data={
                        "campaign_id": campaign_id,
                        "name": completed.name,
                        "status": completed.status,
                    },
                ))
                self._scheduled_campaigns.remove(campaign_id)

        return results

    async def simulate_technique(
        self,
        technique_id: str,
        target_scope: dict[str, Any] | None = None,
    ) -> TechniqueResult:
        """Simulate a MITRE ATT&CK technique by generating synthetic telemetry."""
        technique = TECHNIQUE_LIBRARY.get(technique_id)
        if not technique:
            return TechniqueResult(
                technique_id=technique_id,
                status="error",
            )

        result = TechniqueResult(
            technique_id=technique_id,
            technique_name=technique["name"],
            tactic=technique["tactic"],
            status="simulated",
        )

        # Generate synthetic events based on technique indicators
        sim_events = self._generate_simulation_events(technique_id, technique, target_scope or {})
        result.simulation_events = sim_events

        # Publish simulation events to the event bus for blue team detection
        for sim_event in sim_events:
            await self.event_bus.publish(Event(
                event_type=EventType.RED_TEAM_SIMULATION,
                data={
                    "technique_id": technique_id,
                    "technique_name": technique["name"],
                    "tactic": technique["tactic"],
                    "tactic_id": TACTIC_MAP.get(technique["tactic"], ""),
                    "simulation": True,
                    "detection_sources": technique.get("detection_sources", []),
                    **sim_event,
                },
                source="red_team",
            ))

        self._simulation_history.append(result)
        return result

    async def run_campaign(self, campaign_id: str) -> AttackCampaign:
        """Execute all techniques in a campaign sequentially."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            empty = AttackCampaign(campaign_id=campaign_id, status="error")
            return empty

        campaign.status = "running"
        campaign.started_at = datetime.now(timezone.utc)

        await self.event_bus.publish(Event(
            event_type=EventType.RED_TEAM_CAMPAIGN_STARTED,
            data={
                "campaign_id": campaign_id,
                "name": campaign.name,
                "techniques": campaign.techniques,
            },
            source="red_team",
        ))

        for tech_id in campaign.techniques:
            result = await self.simulate_technique(tech_id, campaign.target_scope)
            campaign.results[tech_id] = result

        campaign.status = "completed"
        campaign.completed_at = datetime.now(timezone.utc)

        # Publish campaign completion
        detected = sum(1 for r in campaign.results.values() if r.status == "detected")
        total = len(campaign.results)

        await self.event_bus.publish(Event(
            event_type=EventType.RED_TEAM_CAMPAIGN_COMPLETED,
            data={
                "campaign_id": campaign_id,
                "name": campaign.name,
                "total_techniques": total,
                "detected": detected,
                "missed": total - detected,
                "detection_rate": round(detected / max(total, 1), 3),
            },
            source="red_team",
        ))

        return campaign

    def create_campaign(
        self,
        name: str,
        techniques: list[str],
        target_scope: dict[str, Any] | None = None,
        description: str = "",
    ) -> AttackCampaign:
        """Create a new attack campaign."""
        campaign = AttackCampaign(
            name=name,
            description=description,
            techniques=techniques,
            target_scope=target_scope or {},
        )
        self._campaigns[campaign.campaign_id] = campaign
        return campaign

    def create_campaign_from_template(
        self,
        template_name: str,
        target_scope: dict[str, Any] | None = None,
    ) -> AttackCampaign:
        """Create a campaign from a pre-built template."""
        template = CAMPAIGN_TEMPLATES.get(template_name, {})
        return self.create_campaign(
            name=template.get("name", template_name),
            techniques=template.get("techniques", []),
            target_scope=target_scope,
            description=template.get("description", ""),
        )

    def schedule_campaign(self, campaign_id: str) -> bool:
        """Schedule a campaign for autonomous execution."""
        if campaign_id in self._campaigns:
            self._scheduled_campaigns.append(campaign_id)
            return True
        return False

    def get_campaign(self, campaign_id: str) -> AttackCampaign | None:
        return self._campaigns.get(campaign_id)

    def get_campaign_results(self, campaign_id: str) -> dict[str, Any]:
        """Get detailed campaign results with detection coverage."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}

        results_summary = []
        for tech_id, result in campaign.results.items():
            tech = TECHNIQUE_LIBRARY.get(tech_id, {})
            results_summary.append({
                "technique_id": tech_id,
                "technique_name": result.technique_name,
                "tactic": result.tactic,
                "status": result.status,
                "detected_by": result.detected_by,
                "expected_sources": tech.get("detection_sources", []),
            })

        detected = sum(1 for r in campaign.results.values() if r.status == "detected")
        total = len(campaign.results)

        return {
            "campaign_id": campaign_id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
            "detection_coverage": round(detected / max(total, 1) * 100, 1),
            "total_techniques": total,
            "detected": detected,
            "missed": total - detected,
            "results": results_summary,
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
        }

    def list_techniques(self, tactic: str | None = None) -> list[dict[str, Any]]:
        """List available attack techniques, optionally filtered by tactic."""
        techniques = []
        for tech_id, tech in TECHNIQUE_LIBRARY.items():
            if tactic and tech["tactic"] != tactic:
                continue
            techniques.append({
                "technique_id": tech_id,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "tactic_id": TACTIC_MAP.get(tech["tactic"], ""),
                "platforms": tech["platforms"],
                "detection_sources": tech.get("detection_sources", []),
            })
        return techniques

    def list_campaigns(self) -> list[dict[str, Any]]:
        return [
            {
                "campaign_id": c.campaign_id,
                "name": c.name,
                "status": c.status,
                "techniques": len(c.techniques),
                "created_at": c.created_at.isoformat(),
            }
            for c in self._campaigns.values()
        ]

    def list_campaign_templates(self) -> list[dict[str, Any]]:
        return [
            {
                "template_name": name,
                "name": t["name"],
                "description": t["description"],
                "techniques": len(t["techniques"]),
            }
            for name, t in CAMPAIGN_TEMPLATES.items()
        ]

    def get_simulation_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "tactic": r.tactic,
                "status": r.status,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in self._simulation_history[-limit:]
        ]

    def mark_technique_detected(
        self,
        technique_id: str,
        campaign_id: str | None = None,
        detected_by: str = "",
    ) -> None:
        """Mark a simulated technique as detected by blue team (called by purple team)."""
        # Update campaign result if applicable
        if campaign_id:
            campaign = self._campaigns.get(campaign_id)
            if campaign and technique_id in campaign.results:
                campaign.results[technique_id].status = "detected"
                if detected_by:
                    campaign.results[technique_id].detected_by.append(detected_by)

        # Update simulation history
        for result in reversed(self._simulation_history):
            if result.technique_id == technique_id and result.status == "simulated":
                result.status = "detected"
                if detected_by:
                    result.detected_by.append(detected_by)
                break

    def _generate_simulation_events(
        self,
        technique_id: str,
        technique: dict[str, Any],
        target_scope: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate synthetic events that mimic real attack indicators."""
        indicators = technique.get("simulation_indicators", {})
        target_ip = target_scope.get("target_ip", "10.0.0.100")
        target_host = target_scope.get("target_host", "WORKSTATION-01")
        source_ip = target_scope.get("source_ip", "192.168.1.50")

        base_event = {
            "simulation": True,
            "technique_id": technique_id,
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "hostname": target_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": indicators.get("severity", "high"),
            **{k: v for k, v in indicators.items() if k != "severity"},
        }

        return [base_event]
