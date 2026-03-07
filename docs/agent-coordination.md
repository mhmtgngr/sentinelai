# Agent Coordination Specification

> Detailed specification for Sentinel-AI's multi-agent coordination system.
> See [README.md](../README.md) for architectural overview.

## Agent Lifecycle

Each agent transitions through these states:

```
INIT -> READY -> IDLE <-> PROCESSING -> IDLE
                  |            |
                  v            v
                ERROR -------> RECOVERING -> READY
```

| State | Description |
|-------|-------------|
| **INIT** | Agent loading configuration, connecting to dependencies |
| **READY** | Agent initialized, waiting for first task |
| **IDLE** | Agent available for task assignment |
| **PROCESSING** | Agent actively working on a task |
| **ERROR** | Agent encountered an unrecoverable error in current task |
| **RECOVERING** | Agent reinitializing after error (checkpoint restore if applicable) |

## Agent Configuration Schema

Each agent is configured via `config/agents.yaml`:

```yaml
agents:
  triage:
    enabled: true
    timeout_seconds: 30
    max_concurrent_tasks: 10
    priority_boost: 0           # Lower = higher priority in queue
    llm_model: "claude-haiku-4-5-20251001"  # Fast model for classification
    confidence_threshold: 0.75
    retry_max: 3
    checkpoint_enabled: false   # Short tasks don't need checkpointing

  threat_hunter:
    enabled: true
    timeout_seconds: 120
    max_concurrent_tasks: 3
    priority_boost: 0
    llm_model: "claude-sonnet-4-6"  # Capable model for reasoning
    confidence_threshold: 0.80
    retry_max: 3
    checkpoint_enabled: true    # Long investigations benefit from checkpointing

  incident_responder:
    enabled: true
    timeout_seconds: 60
    max_concurrent_tasks: 1     # Only 1 active response to prevent conflicts
    priority_boost: -10         # Highest priority — response actions are urgent
    llm_model: "claude-sonnet-4-6"
    confidence_threshold: 0.85  # Higher bar for destructive actions
    retry_max: 2
    checkpoint_enabled: true

  compliance_auditor:
    enabled: true
    timeout_seconds: 180
    max_concurrent_tasks: 2
    priority_boost: 5
    llm_model: "claude-haiku-4-5-20251001"
    confidence_threshold: 0.70
    retry_max: 3
    checkpoint_enabled: false

  forensic_analyst:
    enabled: true
    timeout_seconds: 300
    max_concurrent_tasks: 2
    priority_boost: 5
    llm_model: "claude-sonnet-4-6"
    confidence_threshold: 0.75
    retry_max: 2
    checkpoint_enabled: true    # Long forensic investigations need checkpoints

  vuln_scanner:
    enabled: true
    timeout_seconds: 600
    max_concurrent_tasks: 1
    priority_boost: 10          # Lowest priority — background task
    llm_model: "claude-haiku-4-5-20251001"
    confidence_threshold: 0.70
    retry_max: 3
    checkpoint_enabled: true
```

## Handoff Protocol

When one agent completes processing and hands off to the next agent in the pipeline, a `HandoffPayload` is published to the event bus:

```python
class HandoffPayload:
    source_agent: str              # Agent sending the handoff
    target_agent: str              # Agent receiving the handoff
    alert_id: str                  # Alert being processed
    incident_id: str | None        # Incident if escalated
    decision: AgentDecision        # Source agent's decision
    context: dict                  # Accumulated context from pipeline
    priority: int                  # Queue priority
    deadline: datetime | None      # SLA deadline if applicable
    required_capabilities: list[str]  # What the target agent must do

    # Handoff completeness
    is_complete: bool              # True if source agent finished all work
    pending_items: list[str]       # Remaining work items if incomplete
    follow_up_required: bool       # Whether source agent expects a callback
```

### Required vs Optional Fields

| Field | Required | Notes |
|-------|----------|-------|
| `source_agent` | Yes | Must match a registered agent ID |
| `target_agent` | Yes | Must match a registered agent ID |
| `alert_id` | Yes | Links handoff to originating alert |
| `decision` | Yes | Source agent's findings and confidence |
| `context` | Yes | Can be empty dict but must be present |
| `priority` | Yes | Determines queue position |
| `incident_id` | No | Only present after escalation |
| `deadline` | No | Only for SLA-bound alerts |
| `pending_items` | No | Only for incomplete handoffs |

## Concurrency Model

### asyncio Task Management

The `brain.py` coordinator uses Python's `asyncio` for concurrency:

```
Brain Coordinator
  ├── Event Bus Listener (always running)
  ├── Agent Task Pool
  │   ├── Triage Semaphore (max 10)
  │   ├── Threat Hunter Semaphore (max 3)
  │   ├── Incident Responder Semaphore (max 1)
  │   ├── Compliance Auditor Semaphore (max 2)
  │   ├── Forensic Analyst Semaphore (max 2)
  │   └── Vuln Scanner Semaphore (max 1)
  ├── Priority Queue Consumer
  ├── Deduplication Index
  └── Health Monitor (periodic)
```

- Each agent type has a `asyncio.Semaphore` limiting concurrent tasks
- Tasks are pulled from a `asyncio.PriorityQueue` ordered by severity
- The coordinator monitors all running tasks and handles timeouts via `asyncio.wait_for()`
- Checkpointing writes intermediate state to PostgreSQL; on recovery, the agent resumes from the last checkpoint

### Task Lifecycle

1. Event arrives on bus -> coordinator checks deduplication index
2. If new: assign priority, enqueue in priority queue
3. Priority queue consumer acquires semaphore for target agent type
4. Agent task starts as `asyncio.Task` with timeout wrapper
5. On completion: release semaphore, publish handoff to event bus
6. On timeout: cancel task, increment retry counter, re-enqueue or escalate
7. On error: log full trace, increment error counter, trigger recovery

## Conflict Resolution Details

### Decision Authority Hierarchy

```
Level 1 (Highest): Human operator override (via OpenClaw or API)
Level 2: Compliance Auditor (regulatory constraints are non-negotiable)
Level 3: Incident Responder (safety-critical actions)
Level 4: Threat Hunter (investigation findings)
Level 5: Triage Agent (initial classification)
```

### Conflict Scenarios

| Scenario | Resolution |
|----------|-----------|
| Threat Hunter says "block IP" but IP is on compliance allowlist | Compliance wins — IP not blocked, alert escalated to human |
| Triage says "false positive" but Threat Hunter finds correlated IOCs | Threat Hunter overrides — alert re-escalated |
| Incident Responder wants to isolate host tagged as "critical infrastructure" | Requires human approval regardless of confidence score |
| Two agents produce contradictory assessments with similar confidence | Escalate to human with both reasoning traces side-by-side |

### Escalation Format

When conflicts are escalated to humans via OpenClaw:

```
CONFLICT DETECTED — Alert #ALT-2024-0042

Agent A (Threat Hunter, confidence: 0.82):
  Verdict: Block source IP 203.0.113.42
  Reasoning: IP matches known C2 infrastructure, 3 IOC hits
  Evidence: [SIEM logs, threat intel feed, EDR telemetry]

Agent B (Compliance Auditor, confidence: 0.91):
  Verdict: DO NOT block — IP belongs to regulated partner (ACME Corp)
  Reasoning: IP in compliance allowlist, blocking would violate SLA
  Evidence: [Compliance registry, partner IP range documentation]

Required: Human decision within 15 minutes (SLA)
Options: [Block] [Allow with monitoring] [Escalate to legal]
```

## Task Deduplication

### IOC-Based Correlation

The deduplication index maintains a sliding window (configurable, default 1 hour) of active IOCs:

```python
dedup_index = {
    "ip:203.0.113.42": ["ALT-001", "ALT-002", "ALT-005"],  # 3 alerts share this IP
    "hash:abc123...": ["ALT-003", "ALT-005"],                # 2 alerts share this hash
    "user:admin@corp.local": ["ALT-001", "ALT-004"],         # 2 alerts share this user
}
```

When a new alert arrives with IOCs already in the index:
1. Check overlap ratio — if > 50% IOC overlap with an existing correlated alert, merge
2. Create a single `Alert` with all related `SecurityEvent` entries
3. Bump the correlated alert's severity if the new event increases risk
4. Route the correlated alert (not individual events) to the next pipeline stage
