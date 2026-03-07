"""Domain models for alerts, incidents, and decisions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    AWAITING_DECISION = "awaiting_decision"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"


class DecisionAction(str, Enum):
    APPROVE_REMEDIATE = "approve_remediate"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    RESET_PASSWORD = "reset_password"
    ESCALATE = "escalate"
    IGNORE = "ignore"
    EDUCATE_USER = "educate_user"
    CUSTOM = "custom"


class AlertCategory(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"
    INSIDER_THREAT = "insider_threat"
    VULNERABILITY = "vulnerability"
    RANSOMWARE = "ransomware"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: AlertCategory = AlertCategory.SUSPICIOUS_ACTIVITY
    status: AlertStatus = AlertStatus.NEW
    raw_data: dict[str, Any] = Field(default_factory=dict)
    affected_user: str | None = None
    affected_endpoint: str | None = None
    affected_ip: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    alert_id: str
    original_severity: Severity
    adjusted_severity: Severity
    category: AlertCategory
    confidence: float = 0.0
    summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    requires_human_decision: bool = False
    auto_remediation_possible: bool = False
    education_needed: bool = False
    education_topics: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    action: DecisionAction
    decided_by: str = "autonomous"
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""
    custom_action: str | None = None
    teams_message_id: str | None = None


class SOARAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    decision_id: str | None = None
    action_type: str
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    result: str = ""
    executed_at: datetime | None = None


class UserEducation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    user_email: str
    category: AlertCategory
    topics: list[str] = Field(default_factory=list)
    content_sent: str = ""
    sent_at: datetime | None = None
    sent_via: str = "email"
