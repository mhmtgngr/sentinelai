"""STRIDE-based threat modeling for Sentinel-AI.

Provides threat modeling capabilities including STRIDE threat identification,
risk assessment, attack tree generation, and mitigation tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


class STRIDECategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class Threat:
    threat_id: str = field(default_factory=lambda: str(uuid4()))
    category: STRIDECategory = STRIDECategory.SPOOFING
    title: str = ""
    description: str = ""
    affected_assets: list[str] = field(default_factory=list)
    likelihood: int = 3  # 1-5
    impact: int = 3      # 1-5
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    mitre_techniques: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    mitigation_status: str = "open"  # open, partial, mitigated, accepted


@dataclass
class Mitigation:
    mitigation_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    threat_ids: list[str] = field(default_factory=list)
    status: str = "planned"  # planned, in_progress, implemented, verified
    control_type: str = "preventive"  # preventive, detective, corrective
    implementation_notes: str = ""


@dataclass
class ThreatModel:
    model_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    scope: str = ""
    assets: list[str] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)
    mitigations: list[Mitigation] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "draft"  # draft, active, reviewed, archived


# STRIDE threat templates per asset type
STRIDE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "server": [
        {
            "category": STRIDECategory.SPOOFING,
            "title": "Server Identity Spoofing",
            "description": "Attacker impersonates the server using stolen certificates or ARP spoofing",
            "mitre_techniques": ["T1557"],
            "likelihood": 2, "impact": 4,
            "mitigations": ["Implement certificate pinning", "Enable ARP inspection", "Use mutual TLS"],
        },
        {
            "category": STRIDECategory.TAMPERING,
            "title": "Server Configuration Tampering",
            "description": "Unauthorized modification of server configuration or binaries",
            "mitre_techniques": ["T1565.001"],
            "likelihood": 3, "impact": 5,
            "mitigations": ["File integrity monitoring", "Configuration management", "Restrict admin access"],
        },
        {
            "category": STRIDECategory.REPUDIATION,
            "title": "Log Tampering on Server",
            "description": "Attacker clears or modifies server logs to cover tracks",
            "mitre_techniques": ["T1070.001"],
            "likelihood": 3, "impact": 3,
            "mitigations": ["Centralized logging to SIEM", "Log integrity verification", "Write-once log storage"],
        },
        {
            "category": STRIDECategory.INFORMATION_DISCLOSURE,
            "title": "Server Data Exfiltration",
            "description": "Sensitive data extracted from server via exploitation or insider threat",
            "mitre_techniques": ["T1048.003", "T1567.002"],
            "likelihood": 3, "impact": 5,
            "mitigations": ["DLP controls", "Network segmentation", "Encryption at rest"],
        },
        {
            "category": STRIDECategory.DENIAL_OF_SERVICE,
            "title": "Server Resource Exhaustion",
            "description": "DoS attack exhausts server resources (CPU, memory, disk, network)",
            "mitre_techniques": ["T1499"],
            "likelihood": 3, "impact": 4,
            "mitigations": ["Rate limiting", "Auto-scaling", "DDoS protection"],
        },
        {
            "category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "title": "Server Privilege Escalation",
            "description": "Attacker escalates from low-privilege to admin/root on the server",
            "mitre_techniques": ["T1068", "T1548.002"],
            "likelihood": 3, "impact": 5,
            "mitigations": ["Patch management", "Least privilege", "Kernel hardening"],
        },
    ],
    "workstation": [
        {
            "category": STRIDECategory.SPOOFING,
            "title": "User Credential Theft",
            "description": "Attacker steals user credentials via phishing or credential dumping",
            "mitre_techniques": ["T1566.001", "T1003.001"],
            "likelihood": 4, "impact": 4,
            "mitigations": ["MFA enforcement", "Phishing awareness training", "Credential Guard"],
        },
        {
            "category": STRIDECategory.TAMPERING,
            "title": "Endpoint Malware Installation",
            "description": "Malware installed on workstation modifying system behavior",
            "mitre_techniques": ["T1204.002", "T1059.001"],
            "likelihood": 3, "impact": 4,
            "mitigations": ["EDR deployment", "Application whitelisting", "Disable macros"],
        },
        {
            "category": STRIDECategory.INFORMATION_DISCLOSURE,
            "title": "Workstation Data Theft",
            "description": "Sensitive data exfiltrated from user workstation",
            "mitre_techniques": ["T1560.001", "T1567.002"],
            "likelihood": 3, "impact": 4,
            "mitigations": ["Full disk encryption", "DLP agent", "USB device control"],
        },
        {
            "category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "title": "Local Privilege Escalation",
            "description": "User escalates to local admin on workstation",
            "mitre_techniques": ["T1548.002", "T1068"],
            "likelihood": 3, "impact": 3,
            "mitigations": ["Remove local admin rights", "UAC enforcement", "Patch management"],
        },
    ],
    "user": [
        {
            "category": STRIDECategory.SPOOFING,
            "title": "Account Takeover",
            "description": "Attacker gains access to user account via credential theft or brute force",
            "mitre_techniques": ["T1078", "T1110.003"],
            "likelihood": 4, "impact": 4,
            "mitigations": ["MFA enforcement", "Conditional Access policies", "Password policies"],
        },
        {
            "category": STRIDECategory.REPUDIATION,
            "title": "Identity Action Repudiation",
            "description": "User denies performing actions due to shared credentials or compromised account",
            "mitre_techniques": ["T1078"],
            "likelihood": 2, "impact": 3,
            "mitigations": ["Individual accounts only", "Audit logging", "Session recording"],
        },
        {
            "category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "title": "Unauthorized Role Assignment",
            "description": "User gains unauthorized privileges through role manipulation",
            "mitre_techniques": ["T1098"],
            "likelihood": 2, "impact": 5,
            "mitigations": ["Privileged access management", "Role review automation", "JIT access"],
        },
    ],
    "network_device": [
        {
            "category": STRIDECategory.SPOOFING,
            "title": "Network Device Impersonation",
            "description": "Rogue device on network impersonating legitimate infrastructure",
            "mitre_techniques": ["T1557"],
            "likelihood": 2, "impact": 4,
            "mitigations": ["802.1X authentication", "Network access control", "Device certificates"],
        },
        {
            "category": STRIDECategory.TAMPERING,
            "title": "Firewall Rule Manipulation",
            "description": "Unauthorized changes to firewall rules opening attack paths",
            "mitre_techniques": ["T1562.001"],
            "likelihood": 2, "impact": 5,
            "mitigations": ["Change management process", "Configuration backup", "Rule review automation"],
        },
        {
            "category": STRIDECategory.DENIAL_OF_SERVICE,
            "title": "Network Infrastructure DoS",
            "description": "Attack on network devices causing service disruption",
            "mitre_techniques": ["T1499"],
            "likelihood": 3, "impact": 5,
            "mitigations": ["Redundant paths", "Rate limiting", "IPS deployment"],
        },
    ],
}


class ThreatModeler:
    """STRIDE-based threat modeling engine."""

    def __init__(self) -> None:
        self._models: dict[str, ThreatModel] = {}

    def create_model(
        self,
        name: str,
        assets: list[dict[str, Any]],
        description: str = "",
        scope: str = "",
    ) -> ThreatModel:
        """Create a new threat model for a set of assets."""
        model = ThreatModel(
            name=name,
            description=description,
            scope=scope,
            assets=[a.get("name", a.get("asset_id", "")) for a in assets],
        )
        self._models[model.model_id] = model

        # Auto-generate threats based on asset types
        for asset in assets:
            asset_type = asset.get("asset_type", asset.get("type", "server"))
            self._generate_threats_for_asset(model, asset, asset_type)

        return model

    def get_model(self, model_id: str) -> ThreatModel | None:
        return self._models.get(model_id)

    def list_models(self) -> list[dict[str, Any]]:
        return [
            {
                "model_id": m.model_id,
                "name": m.name,
                "status": m.status,
                "threats": len(m.threats),
                "mitigations": len(m.mitigations),
                "created_at": m.created_at.isoformat(),
            }
            for m in self._models.values()
        ]

    def auto_generate_threats(self, model_id: str) -> list[Threat]:
        """Re-generate threats for an existing model."""
        model = self._models.get(model_id)
        if not model:
            return []
        return model.threats

    def add_threat(self, model_id: str, threat: Threat) -> bool:
        model = self._models.get(model_id)
        if not model:
            return False
        model.threats.append(threat)
        model.updated_at = datetime.now(timezone.utc)
        return True

    def add_mitigation(self, model_id: str, mitigation: Mitigation) -> bool:
        model = self._models.get(model_id)
        if not model:
            return False
        model.mitigations.append(mitigation)
        model.updated_at = datetime.now(timezone.utc)
        return True

    def assess_risk(self, threat: Threat) -> Threat:
        """Calculate risk score and level for a threat."""
        threat.risk_score = round(threat.likelihood * threat.impact, 1)
        max_score = 25

        ratio = threat.risk_score / max_score
        if ratio >= 0.8:
            threat.risk_level = RiskLevel.CRITICAL
        elif ratio >= 0.6:
            threat.risk_level = RiskLevel.HIGH
        elif ratio >= 0.35:
            threat.risk_level = RiskLevel.MEDIUM
        elif ratio >= 0.15:
            threat.risk_level = RiskLevel.LOW
        else:
            threat.risk_level = RiskLevel.NEGLIGIBLE

        return threat

    def get_risk_matrix(self, model_id: str) -> dict[str, Any]:
        """Get likelihood vs impact risk matrix for a threat model."""
        model = self._models.get(model_id)
        if not model:
            return {"error": "Model not found"}

        matrix: dict[str, list[dict[str, Any]]] = {}
        for threat in model.threats:
            self.assess_risk(threat)
            level = threat.risk_level.value
            if level not in matrix:
                matrix[level] = []
            matrix[level].append({
                "threat_id": threat.threat_id,
                "title": threat.title,
                "category": threat.category.value,
                "likelihood": threat.likelihood,
                "impact": threat.impact,
                "risk_score": threat.risk_score,
                "mitigation_status": threat.mitigation_status,
            })

        # Summary counts
        summary = {
            "total_threats": len(model.threats),
            "by_risk_level": {level: len(threats) for level, threats in matrix.items()},
            "by_category": {},
            "mitigated": sum(1 for t in model.threats if t.mitigation_status == "mitigated"),
            "open": sum(1 for t in model.threats if t.mitigation_status == "open"),
        }
        for threat in model.threats:
            cat = threat.category.value
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        return {"matrix": matrix, "summary": summary}

    def get_model_report(self, model_id: str) -> dict[str, Any]:
        """Generate comprehensive threat model report."""
        model = self._models.get(model_id)
        if not model:
            return {"error": "Model not found"}

        risk_matrix = self.get_risk_matrix(model_id)

        threats_data = []
        for threat in model.threats:
            self.assess_risk(threat)
            threats_data.append({
                "threat_id": threat.threat_id,
                "category": threat.category.value,
                "title": threat.title,
                "description": threat.description,
                "likelihood": threat.likelihood,
                "impact": threat.impact,
                "risk_score": threat.risk_score,
                "risk_level": threat.risk_level.value,
                "mitre_techniques": threat.mitre_techniques,
                "mitigations": threat.mitigations,
                "mitigation_status": threat.mitigation_status,
                "affected_assets": threat.affected_assets,
            })

        return {
            "model_id": model.model_id,
            "name": model.name,
            "description": model.description,
            "scope": model.scope,
            "status": model.status,
            "assets": model.assets,
            "threats": threats_data,
            "risk_matrix": risk_matrix,
            "mitigations": [
                {
                    "mitigation_id": m.mitigation_id,
                    "title": m.title,
                    "status": m.status,
                    "control_type": m.control_type,
                    "threat_count": len(m.threat_ids),
                }
                for m in model.mitigations
            ],
            "created_at": model.created_at.isoformat(),
            "updated_at": model.updated_at.isoformat(),
        }

    def _generate_threats_for_asset(
        self,
        model: ThreatModel,
        asset: dict[str, Any],
        asset_type: str,
    ) -> None:
        """Generate STRIDE threats based on asset type."""
        templates = STRIDE_TEMPLATES.get(asset_type, STRIDE_TEMPLATES.get("server", []))
        asset_name = asset.get("name", asset.get("asset_id", "unknown"))

        for template in templates:
            threat = Threat(
                category=template["category"],
                title=f"{template['title']} — {asset_name}",
                description=template["description"],
                affected_assets=[asset_name],
                likelihood=template.get("likelihood", 3),
                impact=template.get("impact", 3),
                mitre_techniques=template.get("mitre_techniques", []),
                mitigations=template.get("mitigations", []),
            )
            self.assess_risk(threat)
            model.threats.append(threat)
