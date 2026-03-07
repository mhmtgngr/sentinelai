# 🛡️ SENTINEL-AI — Autonomous Security Agent Platform

> **Product-Agnostic, Self-Learning, OpenClaw-Managed AI Security Operations Center**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)
[![OpenClaw Compatible](https://img.shields.io/badge/OpenClaw-Compatible-orange.svg)](https://openclaw.ai)

---

## What Is Sentinel-AI?

Sentinel-AI is a **fully autonomous AI security operations platform** that acts as an always-on security expert. It integrates with **any** security product (firewalls, WAFs, SIEM, EDR, Entra ID, etc.) through a product-agnostic adapter layer, uses **OpenClaw** as its orchestration backbone for persistent execution and multi-channel communication, and continuously **self-learns** from your environment through a vector-memory system.

### Core Philosophy

| Principle | Implementation |
|-----------|---------------|
| **Product Agnostic** | Adapter pattern — any security vendor plugs in via unified interface |
| **Self-Learning** | Vector memory + feedback loops continuously improve detection |
| **Fully Autonomous** | Heartbeat-driven proactive scanning, auto-triage, auto-remediation |
| **OpenClaw-Managed** | All integrations flow through OpenClaw skills for unified orchestration |
| **Open Source First** | Built on Wazuh, Shuffle SOAR, MITRE ATT&CK, Sigma rules |

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                        SENTINEL-AI PLATFORM                           │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │           ENTRY POINTS (All converge at Event Bus)           │     │
│  │                                                              │     │
│  │  ┌──────────────────────┐  ┌──────────┐  ┌───────────────┐  │     │
│  │  │  OPENCLAW GATEWAY    │  │ FastAPI  │  │   Adapter     │  │     │
│  │  │  (Human Commands)    │  │ REST API │  │   Webhooks /  │  │     │
│  │  │  WhatsApp │ Telegram │  │ (Prog.)  │  │   Polling     │  │     │
│  │  │  Slack   │ Discord   │  │          │  │   (Automated) │  │     │
│  │  └──────────┬───────────┘  └────┬─────┘  └──────┬────────┘  │     │
│  └─────────────┼───────────────────┼───────────────┼────────────┘     │
│                └───────────────────┼───────────────┘                   │
│                                    ▼                                   │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │         EVENT BUS (Central Nervous System)                   │     │
│  │         In-process async | Redis Streams (Phase 2)           │     │
│  │         Topics: alert.new, alert.triaged, threat.confirmed,  │     │
│  │         incident.created, action.executed, adapter.health    │     │
│  └──────────────────────────┬───────────────────────────────────┘     │
│                              ▼                                        │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │         AI AGENT BRAIN (Multi-Agent Coordinator)             │     │
│  │         Priority Queue │ Conflict Resolution │ Task Dedup    │     │
│  │                                                              │     │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐          │     │
│  │  │  Triage    │  │  Threat    │  │  Incident      │          │     │
│  │  │  Agent     │  │  Hunter    │  │  Responder     │          │     │
│  │  └────────────┘  └────────────┘  └────────────────┘          │     │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐          │     │
│  │  │ Compliance │  │  Forensic  │  │  Vulnerability │          │     │
│  │  │ Auditor    │  │  Analyst   │  │  Scanner       │          │     │
│  │  └────────────┘  └────────────┘  └────────────────┘          │     │
│  └──────────────────────────┬───────────────────────────────────┘     │
│                              │                                        │
│  ┌──────────────────────────▼───────────────────────────────────┐     │
│  │         ACTION VALIDATION LAYER                               │     │
│  │         Confidence thresholds │ Blast radius limits            │     │
│  │         Corroboration check │ Human-in-the-loop gate          │     │
│  └──────────────────────────┬───────────────────────────────────┘     │
│                              │                                        │
│  ┌──────────────────────────▼───────────────────────────────────┐     │
│  │         PRODUCT-AGNOSTIC ADAPTER LAYER                        │     │
│  │         Circuit Breaker │ Retry w/ Backoff │ Health Aggregator │     │
│  │                                                               │     │
│  │  ┌─────────┐ ┌──────┐ ┌───────┐ ┌────────┐ ┌────────┐       │     │
│  │  │Firewall │ │ WAF  │ │ SIEM  │ │EntraID │ │  EDR   │       │     │
│  │  │Adapter  │ │Adapt.│ │Adapt. │ │Adapter │ │Adapter │       │     │
│  │  └────┬────┘ └──┬───┘ └──┬────┘ └───┬────┘ └───┬────┘       │     │
│  └───────┼─────────┼────────┼──────────┼──────────┼─────────────┘     │
│          │         │        │          │          │                    │
│  ┌───────▼─────────▼────────▼──────────▼──────────▼─────────────┐     │
│  │              SECURITY PRODUCTS (Your Stack)                   │     │
│  │                                                               │     │
│  │  Palo Alto │ Fortinet │ Wazuh │ Azure AD │ CrowdStrike       │     │
│  │  Cloudflare│ AWS WAF  │ Splunk│ Okta     │ SentinelOne       │     │
│  │  pfSense   │ ModSec   │ ELK   │ Ping     │ Carbon Black      │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │              PERSISTENCE & LEARNING LAYER                     │    │
│  │                                                               │    │
│  │  ┌───────────┐ ┌───────────┐ ┌──────────────┐ ┌───────────┐  │    │
│  │  │  Vector   │ │ Threat    │ │ Self-Learning │ │PostgreSQL │  │    │
│  │  │  Memory   │ │ Intel     │ │ Feedback      │ │(Ops State │  │    │
│  │  │(ChromaDB) │ │ Cache     │ │ Engine        │ │ Incidents │  │    │
│  │  └───────────┘ └───────────┘ └──────────────┘ │ Audit Log)│  │    │
│  │                                                └───────────┘  │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │              OBSERVABILITY STACK                               │    │
│  │                                                               │    │
│  │  ┌───────────┐ ┌───────────┐ ┌──────────────┐ ┌───────────┐  │    │
│  │  │Prometheus │ │Structured │ │OpenTelemetry │ │ Platform  │  │    │
│  │  │ Metrics   │ │JSON Logs  │ │  Tracing     │ │Self-Alert │  │    │
│  │  └───────────┘ └───────────┘ └──────────────┘ └───────────┘  │    │
│  └───────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Core Data Model

All components communicate using these standardized data structures:

```python
class SecurityEvent:
    id: str                          # Unique event identifier
    source_adapter: str              # Originating adapter (e.g., "wazuh", "crowdstrike")
    timestamp: datetime              # Event occurrence time
    severity: Severity               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    event_type: str                  # Normalized event type (e.g., "brute_force", "malware_detected")
    raw_payload: dict                # Original event data from security product
    normalized: dict                 # Product-agnostic normalized fields
    mitre_attack: list[str]          # MITRE ATT&CK technique IDs (e.g., ["T1110.001"])
    affected_assets: list[str]       # IPs, hostnames, user accounts involved
    iocs: list[IOC]                  # Extracted indicators of compromise

class Alert:
    id: str
    events: list[SecurityEvent]      # Correlated events that form this alert
    triage_verdict: Verdict          # TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | UNDETERMINED
    confidence_score: float          # 0.0 - 1.0, agent's confidence in verdict
    priority: int                    # Queue priority (lower = higher priority)
    assigned_agent: str              # Agent currently handling this alert
    mitre_tactic: str                # ATT&CK tactic (e.g., "Initial Access")
    enrichment: dict                 # Threat intel enrichment data

class Incident:
    id: str
    alerts: list[Alert]              # Alerts escalated into this incident
    status: IncidentStatus           # OPEN | INVESTIGATING | RESPONDING | CONTAINED | CLOSED
    timeline: list[TimelineEntry]    # Ordered sequence of events and actions
    affected_assets: list[Asset]     # All impacted assets with context
    actions_taken: list[ActionResult] # Response actions executed
    playbook_id: str                 # Playbook used for response
    analyst_notes: str               # Human analyst annotations

class ActionResult:
    id: str
    action_type: ActionType          # BLOCK_IP | DISABLE_ACCOUNT | ISOLATE_HOST | QUARANTINE | ...
    status: ActionStatus             # PENDING | EXECUTING | SUCCESS | FAILED | ROLLED_BACK
    target: str                      # What the action was applied to
    adapter_used: str                # Which adapter executed the action
    evidence: dict                   # Evidence collected during action
    rollback_capable: bool           # Whether this action can be undone
    rollback_procedure: str          # How to undo this action
    executed_at: datetime
    executed_by: str                 # Agent or human who authorized

class AgentDecision:
    agent_id: str                    # Which agent made this decision
    reasoning_trace: list[str]       # Step-by-step reasoning chain
    confidence: float                # 0.0 - 1.0
    recommended_actions: list[dict]  # Proposed actions with justification
    data_sources_consulted: list[str] # What evidence was reviewed
    dissenting_signals: list[str]    # Contradictory evidence noted
```

---

## Key GitHub References & Inspirations

| Project | Stars | Role in Sentinel-AI |
|---------|-------|-------------------|
| [OpenClaw](https://github.com/open-claw/open-claw) | 68k+ | Orchestration backbone, skill execution, multi-channel comms |
| [Wazuh](https://github.com/wazuh/wazuh) | 12k+ | Open source XDR/SIEM integration |
| [Shuffle SOAR](https://github.com/Shuffle/Shuffle) | 4k+ | Automated playbook execution |
| [CAI (Cybersecurity AI)](https://github.com/aliasrobotics/cai) | 3k+ | Agentic security patterns reference |
| [AICA Agent](https://github.com/aica-iwg/aica-agent) | — | Autonomous cyberdefense agent architecture |
| [Tracecat](https://github.com/TracecatHQ/tracecat) | 3k+ | Open source SOAR alternative |
| [Sigma Rules](https://github.com/SigmaHQ/sigma) | 8k+ | Detection rule format |
| [MITRE ATT&CK](https://github.com/mitre/cti) | 4k+ | Threat intelligence framework |
| [ChromaDB](https://github.com/chroma-core/chroma) | 16k+ | Vector memory for self-learning |
| [CrewAI](https://github.com/joaomdmoura/crewAI) | 25k+ | Multi-agent orchestration patterns |
| [LangChain](https://github.com/langchain-ai/langchain) | 100k+ | LLM tool integration |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 22k+ | Vulnerability scanning templates |
| [AgentGateway](https://github.com/agentgateway/agentgateway) | — | AI-native proxy for secure agent connectivity |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- OpenClaw installed (`npm i -g openclaw`)
- An LLM API key (Claude, OpenAI, or local via Ollama)

### 1. Clone & Configure
```bash
git clone https://github.com/your-org/sentinel-ai.git
cd sentinel-ai
cp .env.example .env
# Edit .env with your API keys and product endpoints
```

### 2. Launch with Docker
```bash
docker compose up -d
```

### 3. Install OpenClaw Skills
```bash
openclaw skill install ./openclaw-skills/sentinel-triage.md
openclaw skill install ./openclaw-skills/sentinel-hunt.md
openclaw skill install ./openclaw-skills/sentinel-respond.md
openclaw skill install ./openclaw-skills/sentinel-report.md
```

### 4. Connect Your Security Products
```bash
python -m sentinel_ai.cli configure --product paloalto --endpoint https://fw.corp.local
python -m sentinel_ai.cli configure --product wazuh --endpoint https://wazuh.corp.local:55000
python -m sentinel_ai.cli configure --product entraid --tenant-id YOUR_TENANT_ID
```

### 5. Start the Autonomous Agent
```bash
python -m sentinel_ai.main --mode autonomous
```

---

## Project Structure

```
sentinel-ai/
├── README.md                          # This file
├── docker-compose.yml                 # Full stack orchestration
├── .env.example                       # Environment configuration template
├── pyproject.toml                     # Python project config
│
├── src/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── brain.py                   # Central AI brain — multi-agent coordinator
│   │   ├── config.py                  # Configuration management
│   │   └── event_bus.py               # Internal event pub/sub system
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base_agent.py              # Abstract base for all agents
│   │   ├── triage_agent.py            # Alert triage & prioritization
│   │   ├── threat_hunter.py           # Proactive threat hunting
│   │   ├── incident_responder.py      # Automated incident response
│   │   ├── compliance_auditor.py      # Continuous compliance checking
│   │   ├── forensic_analyst.py        # Deep forensic investigation
│   │   └── vuln_scanner.py            # Vulnerability assessment
│   │
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── base_adapter.py            # Abstract adapter interface
│   │   ├── firewall_adapter.py        # Firewall adapter (PaloAlto, Fortinet, pfSense)
│   │   ├── waf_adapter.py             # WAF adapter (Cloudflare, AWS WAF, ModSec)
│   │   ├── siem_adapter.py            # SIEM adapter (Wazuh, Splunk, ELK)
│   │   ├── identity_adapter.py        # Identity adapter (Entra ID, Okta, Ping)
│   │   ├── edr_adapter.py             # EDR adapter (CrowdStrike, SentinelOne)
│   │   ├── soar_adapter.py            # SOAR adapter (Shuffle, Tracecat)
│   │   └── adapter_registry.py        # Dynamic adapter discovery & registration
│   │
│   ├── memory/
│   │   ├── __init__.py
│   │   ├── vector_store.py            # ChromaDB-based vector memory
│   │   ├── threat_intel.py            # Threat intelligence enrichment
│   │   ├── learning_engine.py         # Self-learning feedback loops
│   │   └── knowledge_graph.py         # Security knowledge graph
│   │
│   ├── skills/                        # OpenClaw skill definitions
│   │   └── __init__.py
│   │
│   └── api/
│       ├── __init__.py
│       ├── server.py                  # FastAPI REST API
│       ├── websocket.py               # Real-time WebSocket feeds
│       └── routes/
│           ├── alerts.py
│           ├── incidents.py
│           ├── adapters.py
│           └── memory.py
│
├── openclaw-skills/                   # OpenClaw skill markdown files
│   ├── sentinel-triage.md
│   ├── sentinel-hunt.md
│   ├── sentinel-respond.md
│   └── sentinel-report.md
│
├── config/
│   ├── adapters.yaml                  # Security product configurations
│   ├── agents.yaml                    # Agent behavior configurations
│   ├── sigma-rules/                   # Custom Sigma detection rules
│   └── playbooks/                     # Response playbooks
│
├── tests/
│   ├── test_agents.py
│   ├── test_adapters.py
│   └── test_memory.py
│
└── docker/
    ├── Dockerfile
    ├── Dockerfile.chromadb
    └── nginx.conf
```

---

## Adapter System (Product Agnostic)

Every security product connects through the **Adapter Pattern**. To add a new vendor:

```python
from sentinel_ai.integrations.base_adapter import BaseSecurityAdapter

class MyFirewallAdapter(BaseSecurityAdapter):
    product_type = "firewall"
    vendor = "my_vendor"

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        # Your API calls here
        ...

    async def block_ip(self, ip: str, reason: str) -> ActionResult:
        # Execute block action
        ...

    async def health_check(self) -> HealthStatus:
        # Return connectivity status
        ...
```

Register it in `config/adapters.yaml`:
```yaml
adapters:
  - type: firewall
    vendor: my_vendor
    endpoint: https://fw.example.com/api
    auth:
      type: api_key
      key_env: MY_FIREWALL_API_KEY
```

---

## Self-Learning System

Sentinel-AI continuously improves through:

1. **Alert Feedback Loops** — Analyst verdicts (true/false positive) refine future triage
2. **Threat Pattern Memory** — Novel attack patterns stored in vector DB for similarity matching
3. **Playbook Evolution** — Response effectiveness tracked; playbooks auto-tuned
4. **Environment Baseline** — Normal behavior profiled per asset; drift detection improves over time

---

## Agent Coordination Model

The `brain.py` coordinator manages all six agents through structured pipelines, not ad-hoc dispatching.

### Reactive Pipeline (Incoming Alert)

```
Security Product (e.g., Wazuh alert)
  -> SIEM Adapter (normalize to SecurityEvent)
  -> Event Bus [alert.new]
  -> Triage Agent (classify, score, deduplicate)
  -> Event Bus [alert.triaged, severity=HIGH]
  -> Threat Hunter (enrich with threat intel, correlate, ATT&CK mapping)
  ┌─> Event Bus [threat.confirmed]
  │   -> Incident Responder (select playbook, execute via adapters)
  │   -> Action Validation Layer (confidence check, blast radius check)
  │   -> Firewall Adapter (block IP)
  │   -> Event Bus [action.executed]
  └─> Forensic Analyst (parallel: collect evidence, build timeline)
  -> Compliance Auditor (async: check regulatory implications)
  -> Memory Layer (store incident, update vector embeddings)
  -> OpenClaw (notify analysts via Slack/Teams)
```

### Proactive Pipeline (Scheduled)

```
Scheduler (cron/heartbeat)
  -> Vulnerability Scanner (periodic scan of registered assets)
  -> Threat Hunter (IOC sweep across SIEM + EDR logs)
  -> Compliance Auditor (configuration drift check)
  -> If finding detected: Event Bus [alert.new] -> enters Reactive Pipeline
  -> If clean: log sweep result, update environment baseline
```

### Priority Queue

Alerts are processed through a severity-based priority queue:

| Priority | Severity | Concurrency | Example |
|----------|----------|-------------|---------|
| P0 | CRITICAL | Immediate, preempts other work | Active ransomware, data exfiltration |
| P1 | HIGH | Up to 3 concurrent per agent | Confirmed intrusion, privilege escalation |
| P2 | MEDIUM | Up to 10 concurrent per agent | Suspicious login patterns, policy violations |
| P3 | LOW | Batched processing | Informational alerts, scan results |

**Concurrency limits**: The Incident Responder is limited to 1 active response at a time to prevent conflicting actions (e.g., simultaneous firewall rule changes). Other agents can process multiple alerts concurrently within their limits.

### Task Deduplication

When the same IOC triggers multiple alerts (e.g., 50 firewall blocks for the same IP), the Triage Agent:
1. Groups alerts by shared IOCs and affected assets
2. Creates a single correlated `Alert` with all related `SecurityEvent` entries
3. Routes the correlated alert (not 50 individual alerts) to the next pipeline stage

### Conflict Resolution

When agents produce contradictory recommendations:

1. **Authority hierarchy**: Compliance constraints override Threat Hunter recommendations (e.g., cannot block a regulated partner's IP without legal review)
2. **Corroboration requirement**: Destructive actions require evidence from 2+ independent data sources
3. **Escalation**: When agents disagree and no hierarchy applies, the alert is escalated to human-in-the-loop via OpenClaw with both perspectives presented
4. **Conflict logging**: All disagreements are logged with full reasoning traces for post-incident review

---

## OpenClaw Skill Integration

### Skill-to-Agent Mapping

| OpenClaw Skill | Primary Agent(s) | Trigger | Output |
|---|---|---|---|
| `sentinel-triage` | Triage Agent | New alert event or chat command | Severity score, classification, recommended next agent |
| `sentinel-hunt` | Threat Hunter, Vuln Scanner | Triage escalation or scheduled scan | IOC matches, ATT&CK mapping, enriched context |
| `sentinel-respond` | Incident Responder | Confirmed threat | Executed playbook steps, action results, rollback info |
| `sentinel-report` | Forensic Analyst, Compliance Auditor | Incident closed or on-demand | Incident report, compliance assessment, evidence chain |

### Invocation Flow

```
1. Analyst sends message via Slack: "investigate IP 10.0.0.5"
2. OpenClaw matches message to sentinel-hunt skill
3. Skill calls Sentinel-AI REST API: POST /api/v1/investigations
4. API publishes event to Event Bus [investigation.requested]
5. Brain coordinator dispatches to Threat Hunter agent
6. Agent queries SIEM + EDR adapters, enriches with threat intel
7. Agent returns AgentDecision with findings and confidence score
8. Results returned to OpenClaw via API response
9. OpenClaw formats findings and sends back to Slack channel
10. Analyst verdict (if provided) fed back through learning engine
```

### Feedback Loop

Every skill invocation feeds the self-learning system:
- **Full context logged**: Input, agent reasoning trace, actions taken, outcome -> stored in vector store
- **Threat intel updated**: New IOCs discovered during investigation -> added to threat intel cache
- **Analyst verdicts**: When analysts confirm or override decisions via chat -> fed to learning engine to refine future triage
- **Playbook effectiveness**: Response action success/failure rates -> used to auto-tune playbook selection

---

## Data Flow Scenarios

### Scenario 1: Reactive Alert Processing

```
Wazuh detects brute-force SSH login
  │
  ▼
SIEM Adapter
  │ Normalizes to SecurityEvent
  │ Extracts IOCs (source IP, target host)
  │ Maps to MITRE ATT&CK T1110.001
  ▼
Event Bus [alert.new]
  │
  ▼
Triage Agent
  │ Queries vector memory for similar past events
  │ Checks if source IP appears in threat intel cache
  │ Scores severity: HIGH (confidence: 0.87)
  │ Deduplicates against existing open alerts
  ▼
Event Bus [alert.triaged, severity=HIGH]
  │
  ├──────────────────────────────┐
  ▼                              ▼
Threat Hunter                  Forensic Analyst
  │ Queries EDR for related       │ Pulls auth logs for
  │ activity on target host       │ timeline reconstruction
  │ Checks lateral movement       │ Captures session data
  │ Maps full ATT&CK chain        │
  ▼                              ▼
Event Bus [threat.confirmed]   Evidence package assembled
  │
  ▼
Incident Responder
  │ Selects "brute-force-response" playbook
  │ Proposes: block source IP, force password reset
  ▼
Action Validation Layer
  │ Confidence 0.87 >= 0.75 threshold: PASS
  │ Single IP block: within blast radius limit: PASS
  │ Corroboration: SIEM alert + EDR telemetry: PASS
  ▼
Firewall Adapter → Block IP on Palo Alto
Identity Adapter → Force password reset on Entra ID
  │
  ▼
Event Bus [action.executed]
  │
  ├──> Memory Layer (store incident, update embeddings)
  └──> OpenClaw → Notify analyst via Slack with full report
```

### Scenario 2: Proactive Threat Hunt

```
Scheduler (every 4 hours)
  │
  ▼
Threat Hunter Agent
  │ Loads latest IOC feed from threat intel cache
  │ Queries SIEM Adapter: search logs for IOC matches
  │ Queries EDR Adapter: search endpoint telemetry
  ▼
Memory Layer
  │ Similarity search against known attack patterns
  │ Compare current baseline vs. stored environment profile
  │
  ├── Match found ──> Event Bus [alert.new] ──> Reactive Pipeline
  │
  └── No match ──> Log clean sweep
                    Update environment baseline
                    Report "all clear" to scheduled report
```

---

## Resilience & Error Handling

### Circuit Breaker Pattern

Each adapter connection uses a circuit breaker to prevent cascade failures:

| State | Behavior |
|-------|----------|
| **Closed** (normal) | Requests pass through; failures counted |
| **Open** (tripped) | Requests fail fast; no calls to adapter for cooldown period |
| **Half-Open** (testing) | Single test request allowed; success resets to Closed |

Thresholds: 5 consecutive failures or 50% failure rate in 60-second window triggers Open state. Cooldown: 30 seconds (configurable per adapter).

### Retry Policy

- **Adapter calls**: Exponential backoff, max 3 attempts (1s, 2s, 4s)
- **LLM API calls**: Exponential backoff, max 3 attempts (2s, 4s, 8s)
- **Non-retryable**: Authentication failures (401/403), validation errors (400)

### Dead Letter Queue

Events that fail processing after all retries are moved to a dead letter queue (DLQ) rather than dropped:
- DLQ events are persisted in PostgreSQL
- Platform self-alert triggers when DLQ depth exceeds threshold
- Manual review and replay capability via API: `POST /api/v1/dlq/{event_id}/replay`

### Graceful Degradation

| Component Down | Fallback Behavior |
|----------------|-------------------|
| LLM provider unreachable | Fall back to Sigma rule-based triage (no AI reasoning, but alerts still processed) |
| ChromaDB unavailable | Skip similarity search; process alerts without memory context |
| Single adapter down | Circuit breaker opens; other adapters continue; failed actions queued for retry |
| OpenClaw unreachable | Alerts processed normally; notifications queued for delivery when restored |

### Agent Failure Handling

- **Timeout**: Configurable per agent type (Triage: 30s, Threat Hunter: 120s, Forensic Analyst: 300s)
- **Crash recovery**: Agent tasks are checkpointed; long-running investigations resume from last checkpoint after restart
- **Escalation**: If an agent fails after 3 retries, the alert is flagged `NEEDS_HUMAN_REVIEW` and routed to OpenClaw for analyst attention

---

## Security Architecture

Security is not a deployment afterthought — it is an architectural layer built into the platform.

### Credential Management

| Environment | Strategy |
|-------------|----------|
| **Local development** | `.env` file (gitignored), never committed |
| **Production** | Secrets manager integration (HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault) |
| **Credential scoping** | Each adapter gets minimum-privilege API credentials — read-only where possible, action-scoped where needed |
| **Rotation** | Automated credential rotation on schedule; adapters handle rotation transparently |

### API Authentication & Authorization

The Sentinel-AI FastAPI server enforces:
- **Authentication**: OAuth2/OIDC integration (Entra ID, Okta) or scoped API keys for programmatic access
- **RBAC roles**:
  - `viewer`: Read-only access to alerts, incidents, dashboards
  - `operator`: Can trigger investigations, approve actions
  - `admin`: Full configuration access, adapter management, system settings
- **Network access**: API accessible only from management networks; not exposed to general corporate network

### Prompt Injection Defense

Security log data flows through the LLM — attackers can embed prompt injection payloads in log entries, hostnames, or user-agent strings. Architectural defenses:

1. **Input sanitization layer**: All adapter data passes through a sanitizer before being included in LLM prompts. Known injection patterns are stripped or escaped.
2. **Structured output parsing**: Agents return typed `AgentDecision` objects with validated fields — not freeform text that gets interpreted as instructions.
3. **Action validation layer**: Any action proposed by an agent is validated against a policy allowlist before execution, regardless of LLM output. The LLM cannot invent new action types.
4. **Rate limiting**: No more than N destructive actions per minute (configurable) to prevent an LLM-driven self-DoS.

### Action Safety Controls

| Control | Description |
|---------|-------------|
| **Confidence threshold** | Actions require agent confidence >= 0.75. Below threshold -> human approval required. |
| **Blast radius limit** | No autonomous action can affect more than N assets (default: 5). Broad actions (block subnet, disable OU) require human approval. |
| **Corroboration** | Destructive actions require evidence from 2+ independent data sources (e.g., SIEM alert + EDR detection), not LLM reasoning alone. |
| **Shadow mode** | New deployments run in observation-only mode — recommending actions but not executing — until operators build confidence. |
| **Rollback** | Every automated action has a documented and tested rollback procedure. `ActionResult` includes `rollback_capable` flag and procedure. |

### Immutable Audit Trail

Every autonomous action is recorded in an append-only audit log:
- **What**: Action type, target, parameters
- **Who**: Agent ID or human who authorized
- **Why**: Full reasoning trace from `AgentDecision`
- **Evidence**: Data sources consulted, confidence score, corroborating signals
- **Result**: Success/failure, side effects observed
- **Tamper-evident**: Cryptographic hash chaining (each entry includes hash of previous entry)
- **Retention**: Configurable, aligned with compliance requirements (default: 2 years)

### Network Segmentation

| Container/Service | Internet Access | Internal Network |
|-------------------|----------------|------------------|
| FastAPI server | No | Management VLAN only |
| Agent workers | Outbound only (LLM API) | Internal event bus |
| ChromaDB | No | Internal only |
| PostgreSQL | No | Internal only |
| OpenClaw Gateway | Yes (chat platforms) | Internal API access |
| Adapter containers | Outbound (vendor APIs) | Internal event bus |

**TLS required** for all inter-service communication within the Docker network.

### Deployment Hardening Checklist

1. Run OpenClaw in sandboxed mode — restrict shell and filesystem access
2. Enable MCP proxy guardrails — use AgentGateway for additional prompt injection protection
3. Isolate the vector DB — ChromaDB must not be network-accessible outside the platform
4. Configure shadow mode for initial deployment — validate before enabling autonomous actions
5. Set up credential rotation automation — not just a policy, but an automated process
6. Review blast radius limits — adjust per environment based on asset criticality

---

## Observability

A security platform that cannot monitor itself is a liability. Sentinel-AI includes a dedicated observability stack.

### Metrics (Prometheus)

| Metric | Description |
|--------|-------------|
| `sentinel_alert_throughput` | Alerts ingested per minute, by source adapter |
| `sentinel_agent_latency_seconds` | Processing time per agent, by agent type |
| `sentinel_adapter_error_rate` | Error rate per adapter, tracks circuit breaker state |
| `sentinel_llm_tokens_used` | LLM token consumption by agent, for cost tracking |
| `sentinel_llm_cost_usd` | Estimated LLM API cost per time window |
| `sentinel_queue_depth` | Event bus queue depth, by topic |
| `sentinel_dlq_depth` | Dead letter queue depth (triggers self-alert at threshold) |
| `sentinel_false_positive_rate` | False positive rate over rolling 7-day window (from analyst verdicts) |
| `sentinel_action_success_rate` | Autonomous action success rate, by action type |

### Structured Logging

All logs are JSON-formatted with:
- **Correlation ID**: Traces a single security event from ingestion through triage through response
- **Agent ID**: Which agent produced the log entry
- **Event ID**: Link back to the originating `SecurityEvent`
- **Log levels**: `DEBUG` (agent reasoning steps), `INFO` (actions taken), `WARN` (degraded operation), `ERROR` (failures)

### Distributed Tracing (OpenTelemetry)

OpenTelemetry integration traces the full lifecycle of a security event:
```
Span: adapter.ingest -> event_bus.publish -> triage.process ->
      threat_hunter.enrich -> incident_responder.execute ->
      adapter.action -> memory.store -> openclaw.notify
```

### Platform Self-Alerting

Sentinel-AI monitors itself through a separate alerting channel (not mixed with security alerts):

| Self-Alert | Condition | Channel |
|------------|-----------|---------|
| Adapter disconnected | Circuit breaker opens on any adapter | Ops team Slack/PagerDuty |
| LLM cost spike | Token usage exceeds 2x rolling average | Ops team Slack |
| Queue backup | Event bus depth > 1000 unprocessed | Ops team PagerDuty |
| DLQ growing | Dead letter queue > 50 entries | Ops team Slack |
| Agent timeout rate | > 10% of agent tasks timing out | Ops team Slack |
| Vector store unreachable | ChromaDB health check fails | Ops team PagerDuty |

### Operational Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness check — is the process running |
| `GET /ready` | Readiness check — are all adapters connected and event bus operational |
| `GET /metrics` | Prometheus metrics endpoint |

---

## Testing Strategy

### Test Pyramid

| Layer | Scope | Tools | Run Frequency |
|-------|-------|-------|---------------|
| **Unit** | Individual agents, adapters, models, event bus | pytest, pytest-asyncio, unittest.mock | Every commit |
| **Integration** | End-to-end pipeline (alert -> triage -> response) | pytest, test fixtures, Docker test containers | Every PR |
| **Contract** | Adapter interface compliance | pytest, abstract test classes | Every commit |
| **Resilience** | Failure injection (adapter down, LLM timeout, DB unavailable) | pytest, toxiproxy, custom fault injectors | Weekly / pre-release |
| **Security** | Prompt injection payloads, action validation bypass, auth bypass | pytest, custom security fixtures | Every PR |

### Unit Test Strategy

Each component is tested in isolation with mocked dependencies:
- **Agents**: Mock LLM responses and adapter calls; verify `AgentDecision` output structure, confidence scoring, and MITRE ATT&CK mapping
- **Adapters**: Mock HTTP responses from vendor APIs; verify `SecurityEvent` normalization and `ActionResult` construction
- **Event Bus**: Verify topic-based pub/sub, ordering guarantees, and backpressure behavior
- **Models**: Pydantic validation — reject malformed events, enforce enum constraints, verify serialization round-trips
- **Memory**: Mock ChromaDB client; verify embedding storage, similarity search, and feedback loop integration

### Integration Test Fixtures

Pre-built test scenarios representing realistic security events:
- `brute_force_ssh.json` — Wazuh alert for SSH brute force → full reactive pipeline
- `lateral_movement.json` — EDR detection of lateral movement → multi-agent investigation
- `compliance_drift.json` — Firewall rule change violating policy → compliance audit
- `false_positive_benign.json` — Benign activity that resembles an attack → verify correct classification

### Security Testing

- **Prompt injection corpus**: Test fixtures containing known prompt injection patterns embedded in log fields (`user-agent`, `hostname`, `command` fields) — verify sanitization strips them before LLM processing
- **Action validation bypass**: Attempt to create `AgentDecision` objects with out-of-range confidence scores, invalid action types, or targets on the allowlist — verify the action validation layer rejects them
- **Authentication tests**: Verify unauthorized API requests are rejected; verify RBAC role boundaries

### Test Tooling

```toml
[project.optional-dependencies]
test = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
    "factory-boy>=3.3",       # Test fixture factories
    "respx>=0.21",            # httpx mock for async HTTP
    "freezegun>=1.4",         # Time manipulation for timeout tests
]
```

---

## CI/CD Pipeline

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff          # Lint
      - id: ruff-format   # Format
  - repo: https://github.com/pre-commit/mirrors-mypy
    hooks:
      - id: mypy          # Type checking
  - repo: https://github.com/Yelp/detect-secrets
    hooks:
      - id: detect-secrets # Prevent credential leaks
```

### CI (GitHub Actions)

| Step | Trigger | Purpose |
|------|---------|---------|
| **Lint & Format** | Every push | ruff check, ruff format --check |
| **Type Check** | Every push | mypy --strict on src/ |
| **Unit Tests** | Every push | pytest tests/ -m "not integration" |
| **Integration Tests** | PR to main | pytest tests/ -m integration (with Docker services) |
| **Security Scan** | PR to main | bandit (SAST), pip-audit (dependency vulnerabilities) |
| **Docker Build** | PR to main | Verify `docker compose build` succeeds |
| **Coverage Gate** | PR to main | Fail if coverage drops below 80% |

### CD (Deployment)

- **Staging**: Auto-deploy on merge to `main` — `docker compose up -d` on staging server
- **Production**: Manual promotion via tagged release — Docker images pushed to registry on `v*` tags
- **Rollback**: Previous Docker image tag always available; rollback is `docker compose pull && docker compose up -d` with previous tag

### Branch Protection

- `main` branch: Require passing CI + 1 code review + no direct pushes
- All feature branches: Must be up-to-date with `main` before merge

---

## Data Model Versioning

### Schema Evolution

Data models (`SecurityEvent`, `Alert`, `Incident`, etc.) will evolve as integrations and agents mature. Strategy:

| Store | Versioning Approach |
|-------|-------------------|
| **PostgreSQL** | Alembic migrations — each schema change gets a numbered migration with up/down |
| **ChromaDB** | Versioned collection names (e.g., `alerts_v2`) with migration script to re-embed existing data |
| **Event Bus** | Events carry a `schema_version` field; consumers handle N and N-1 versions |

### Backward Compatibility

- New fields are always **optional with defaults** — old events remain readable
- Removed fields are **deprecated for 2 versions** before deletion
- Breaking changes require a new collection/table + migration script
- All migrations are tested in CI with fixture data from previous versions

---

## Scalability Roadmap

### Phase 1: Single Instance (Current Design)

- Suitable for small-to-medium environments: up to ~1,000 alerts/day
- All agents run in-process within the FastAPI application
- Event bus is in-memory async (Python `asyncio` queues)
- ChromaDB runs as a sidecar container
- PostgreSQL for operational state
- **Limitations**: Vertical scaling only; agent processing is CPU/IO-bound by LLM calls

### Phase 2: Horizontal Scaling

For larger environments (1,000 - 100,000+ alerts/day):

| Component | Phase 1 | Phase 2 |
|-----------|---------|---------|
| Event Bus | In-process async | Redis Streams or NATS JetStream |
| Agent Workers | In-process | Stateless containers, multiple replicas per agent type |
| API Server | Single instance | Load-balanced, multiple replicas |
| ChromaDB | Sidecar container | Externalized cluster (or migrate to Qdrant/Weaviate) |
| PostgreSQL | Single container | Managed database service with replication |

### LLM Cost Management

| Strategy | Description |
|----------|-------------|
| **Tiered models** | Fast/cheap model for triage classification (Haiku-class); capable model for threat hunting reasoning (Sonnet/Opus-class) |
| **Token budgets** | Per-agent, per-time-window token limits; exceeded budget triggers fallback to rule-based processing |
| **Batch processing** | Low-severity alerts batched for triage (up to 10 per LLM call) |
| **Local model fallback** | Ollama integration for air-gapped environments or cost control; reduced capability but zero external API cost |
| **Cost circuit breaker** | If LLM spend exceeds threshold in any hour, all agents fall back to Sigma rule-based processing |

### Vector Store Scaling

ChromaDB is suitable for development and small deployments. Plan for migration:
- **< 100K vectors**: ChromaDB is sufficient
- **100K - 10M vectors**: Migrate to Qdrant or Weaviate for better query performance and horizontal scaling
- **Embedding model**: Choice impacts storage (384-dim vs 1536-dim) and query latency; default to a balanced model (e.g., `all-MiniLM-L6-v2`)

---

## Operational Scenarios & Failure Modes

### Agent Failure

| Scenario | Response |
|----------|----------|
| Agent times out | Task killed after configurable timeout; alert re-queued for retry (max 3 attempts) |
| Agent crashes | Supervisor restarts agent; checkpointed investigations resume from last saved state |
| Repeated failures | Alert flagged `NEEDS_HUMAN_REVIEW`; routed to OpenClaw for analyst attention |
| All agents down | Platform enters degraded mode; Sigma rules process alerts without AI reasoning |

### Adapter Unavailability

| Scenario | Response |
|----------|----------|
| API timeout | Circuit breaker pattern; retry with exponential backoff |
| Adapter fully down | Pending actions queued in PostgreSQL for retry when adapter recovers |
| Alternative available | If firewall adapter is down but WAF adapter is up, attempt block via WAF |
| Extended outage | Self-alert to ops team; incident record reflects failed remediation with pending status |

### LLM Hallucination Safeguards

The most dangerous failure mode — an LLM could fabricate IOCs, misclassify threats, or recommend destructive actions.

| Safeguard | Implementation |
|-----------|----------------|
| **Confidence scoring** | Every `AgentDecision` includes a confidence score; actions below 0.75 require human approval |
| **Blast radius limits** | No autonomous action affects > 5 assets; broader actions require human approval |
| **Corroboration** | Destructive actions need evidence from 2+ independent sources, not just LLM reasoning |
| **Shadow mode** | New deployments observe and recommend only; no autonomous execution until validated |
| **Rollback capability** | Every `ActionResult` includes rollback procedure; rollback can be triggered via API or OpenClaw |
| **Action allowlist** | LLM cannot invent action types; only pre-defined `ActionType` enum values are accepted |

### Alert Storm / Platform DoS

An attacker aware of Sentinel-AI could deliberately generate thousands of alerts to exhaust LLM budgets or overwhelm processing.

| Defense | Implementation |
|---------|----------------|
| **Rate limiting** | Alert ingestion capped at configurable rate per adapter (default: 100/min) |
| **Deduplication at source** | Adapters aggregate identical events before publishing to event bus |
| **Sampling under load** | When queue depth exceeds threshold, low-severity alerts sampled (1-in-N processed) |
| **Cost circuit breaker** | LLM spend exceeding hourly threshold triggers fallback to rule-based processing |
| **Alert storm detection** | Triage Agent detects anomalous alert volume and flags it as a potential meta-attack |

### Data Poisoning of Learning System

If an attacker can influence analyst verdicts or trigger false patterns, they could degrade the self-learning system over time.

| Defense | Implementation |
|---------|----------------|
| **Multi-analyst validation** | High-severity verdict changes require confirmation from 2+ analysts |
| **Anomaly detection on learning data** | Statistical monitoring of verdict distribution; sudden shifts flagged for review |
| **Vector store snapshots** | Periodic snapshots of ChromaDB; rollback to known-good state if poisoning detected |
| **Pattern audit** | Periodic human review of top-weighted learned patterns; exportable for inspection |
| **Confidence decay** | Learned patterns decay in weight over time unless reinforced by new corroborating evidence |

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
# sentinelai
