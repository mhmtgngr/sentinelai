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
┌──────────────────────────────────────────────────────────────────┐
│                    SENTINEL-AI PLATFORM                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │              OPENCLAW GATEWAY (Orchestrator)             │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │     │
│  │  │ WhatsApp │ │ Telegram │ │  Slack   │ │  Discord  │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └───────────┘  │     │
│  └─────────────────────┬───────────────────────────────────┘     │
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────┐     │
│  │              AI AGENT BRAIN (Multi-Agent System)         │     │
│  │                                                          │     │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐     │     │
│  │  │  Triage    │  │  Threat    │  │  Incident      │     │     │
│  │  │  Agent     │  │  Hunter    │  │  Responder     │     │     │
│  │  └────────────┘  └────────────┘  └────────────────┘     │     │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐     │     │
│  │  │ Compliance │  │  Forensic  │  │  Vulnerability │     │     │
│  │  │ Auditor    │  │  Analyst   │  │  Scanner       │     │     │
│  │  └────────────┘  └────────────┘  └────────────────┘     │     │
│  └─────────────────────┬───────────────────────────────────┘     │
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────┐     │
│  │         PRODUCT-AGNOSTIC ADAPTER LAYER                   │     │
│  │                                                          │     │
│  │  ┌─────────┐ ┌──────┐ ┌───────┐ ┌────────┐ ┌────────┐  │     │
│  │  │Firewall │ │ WAF  │ │ SIEM  │ │EntraID │ │  EDR   │  │     │
│  │  │Adapter  │ │Adapt.│ │Adapt. │ │Adapter │ │Adapter │  │     │
│  │  └────┬────┘ └──┬───┘ └──┬────┘ └───┬────┘ └───┬────┘  │     │
│  └───────┼─────────┼────────┼──────────┼──────────┼────────┘     │
│          │         │        │          │          │               │
│  ┌───────▼─────────▼────────▼──────────▼──────────▼────────┐     │
│  │              SECURITY PRODUCTS (Your Stack)              │     │
│  │                                                          │     │
│  │  Palo Alto │ Fortinet │ Wazuh │ Azure AD │ CrowdStrike  │     │
│  │  Cloudflare│ AWS WAF  │ Splunk│ Okta     │ SentinelOne  │     │
│  │  pfSense   │ ModSec   │ ELK   │ Ping     │ Carbon Black │     │
│  └──────────────────────────────────────────────────────────┘     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              MEMORY & LEARNING LAYER                      │    │
│  │                                                           │    │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────────────────┐  │    │
│  │  │  Vector   │  │  Threat   │  │  Self-Learning       │  │    │
│  │  │  Memory   │  │  Intel    │  │  Feedback Engine     │  │    │
│  │  │(ChromaDB) │  │  Cache    │  │  (Continuous Tuning) │  │    │
│  │  └───────────┘  └───────────┘  └──────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
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

## Security Recommendations for Deployment

1. **Run OpenClaw in sandboxed mode** — Restrict shell and filesystem access
2. **Use API key rotation** — All adapter credentials should rotate on schedule
3. **Enable MCP proxy guardrails** — Use AgentGateway or CrowdStrike Falcon AIDR for prompt injection protection
4. **Isolate the vector DB** — ChromaDB should not be network-accessible
5. **Audit all autonomous actions** — Every action logged with full context for review
6. **Human-in-the-loop for critical actions** — Account disabling, firewall rule changes require approval

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
# sentinelai
