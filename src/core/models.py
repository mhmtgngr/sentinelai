"""Core data models for Sentinel-AI.

All components communicate using these standardized Pydantic models.
See README.md 'Core Data Model' section for design rationale.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, enum.Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    UNDETERMINED = "UNDETERMINED"


class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESPONDING = "RESPONDING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"


class ActionType(str, enum.Enum):
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    ENABLE_ACCOUNT = "ENABLE_ACCOUNT"
    ISOLATE_HOST = "ISOLATE_HOST"
    UNISOLATE_HOST = "UNISOLATE_HOST"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    FORCE_PASSWORD_RESET = "FORCE_PASSWORD_RESET"
    ADD_TO_WATCHLIST = "ADD_TO_WATCHLIST"
    CREATE_ALERT = "CREATE_ALERT"


class ActionStatus(str, enum.Enum):
    PENDING = "PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class HealthState(str, enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


def _generate_id() -> str:
    return str(uuid.uuid4())


class IOC(BaseModel):
    """Indicator of Compromise extracted from a security event."""

    type: str  # ip, domain, hash, email, url, user
    value: str
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    source: str = ""


class HealthStatus(BaseModel):
    """Health status of an adapter or component."""

    state: HealthState = HealthState.HEALTHY
    message: str = ""
    last_checked: datetime = Field(default_factory=datetime.utcnow)
    latency_ms: float | None = None


class SecurityEvent(BaseModel):
    """Raw security event normalized from a security product."""

    id: str = Field(default_factory=_generate_id)
    source_adapter: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity = Severity.INFO
    event_type: str
    raw_payload: dict = Field(default_factory=dict)
    normalized: dict = Field(default_factory=dict)
    mitre_attack: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    schema_version: int = 1


class TimelineEntry(BaseModel):
    """A single entry in an incident timeline."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str = ""
    description: str
    evidence: dict = Field(default_factory=dict)


class Asset(BaseModel):
    """An affected asset with context."""

    identifier: str  # IP, hostname, user principal name
    asset_type: str  # host, user, network, application
    criticality: str = "medium"  # low, medium, high, critical
    metadata: dict = Field(default_factory=dict)


class Alert(BaseModel):
    """Correlated and triaged security events."""

    id: str = Field(default_factory=_generate_id)
    events: list[SecurityEvent] = Field(default_factory=list)
    triage_verdict: Verdict = Verdict.UNDETERMINED
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.0)
    priority: int = Field(default=100)  # Lower = higher priority
    assigned_agent: str = ""
    mitre_tactic: str = ""
    enrichment: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    schema_version: int = 1


class ActionResult(BaseModel):
    """Result of an executed remediation action."""

    id: str = Field(default_factory=_generate_id)
    action_type: ActionType
    status: ActionStatus = ActionStatus.PENDING
    target: str
    adapter_used: str = ""
    evidence: dict = Field(default_factory=dict)
    rollback_capable: bool = False
    rollback_procedure: str = ""
    executed_at: datetime | None = None
    executed_by: str = ""


class AgentDecision(BaseModel):
    """Decision output from an AI agent."""

    agent_id: str
    alert_id: str = ""
    reasoning_trace: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_actions: list[dict] = Field(default_factory=list)
    data_sources_consulted: list[str] = Field(default_factory=list)
    dissenting_signals: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Incident(BaseModel):
    """Escalated alerts forming a security incident."""

    id: str = Field(default_factory=_generate_id)
    alerts: list[Alert] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN
    timeline: list[TimelineEntry] = Field(default_factory=list)
    affected_assets: list[Asset] = Field(default_factory=list)
    actions_taken: list[ActionResult] = Field(default_factory=list)
    playbook_id: str = ""
    analyst_notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    schema_version: int = 1


class HandoffPayload(BaseModel):
    """Data passed between agents during pipeline handoffs."""

    source_agent: str
    target_agent: str
    alert_id: str
    incident_id: str | None = None
    decision: AgentDecision
    context: dict = Field(default_factory=dict)
    priority: int = Field(default=100)
    deadline: datetime | None = None
    is_complete: bool = True
    pending_items: list[str] = Field(default_factory=list)
    follow_up_required: bool = False
