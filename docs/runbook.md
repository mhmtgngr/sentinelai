# Operational Runbook

> Procedures for operating and troubleshooting Sentinel-AI.
> See [README.md](../README.md) for architectural overview.

## Common Operations

### Starting the Platform

```bash
# Start all services
docker compose up -d

# Verify health
curl http://localhost:8000/health    # Liveness
curl http://localhost:8000/ready     # All adapters connected
curl http://localhost:8000/metrics   # Prometheus metrics
```

### Stopping the Platform

```bash
# Graceful shutdown (waits for in-flight tasks to complete, up to 30s)
docker compose stop

# Force shutdown (immediate)
docker compose down
```

### Adding a New Adapter

1. Create a new adapter class extending `BaseSecurityAdapter`:
   ```python
   # src/integrations/my_vendor_adapter.py
   from src.integrations.base_adapter import BaseSecurityAdapter

   class MyVendorAdapter(BaseSecurityAdapter):
       product_type = "firewall"
       vendor = "my_vendor"

       async def get_events(self, since: datetime) -> list[SecurityEvent]:
           ...
       async def execute_action(self, action: ActionType, target: str, params: dict) -> ActionResult:
           ...
       async def health_check(self) -> HealthStatus:
           ...
   ```

2. Add configuration to `config/adapters.yaml`:
   ```yaml
   adapters:
     - type: firewall
       vendor: my_vendor
       endpoint: https://fw.example.com/api
       auth:
         type: api_key
         key_env: MY_VENDOR_API_KEY
   ```

3. Add the API key to `.env` or secrets manager
4. Restart the platform or trigger hot-reload via API

### Tuning Agent Confidence Thresholds

Edit `config/agents.yaml`:

```yaml
agents:
  triage:
    confidence_threshold: 0.80  # Increase to reduce false positives (may miss real threats)
```

Guidance:
- **Higher threshold** (0.85-0.95): Fewer autonomous actions, more human review, safer but slower
- **Lower threshold** (0.65-0.75): More autonomous actions, faster response, but more false positives
- **Recommended starting point**: 0.75 for triage, 0.80 for threat hunting, 0.85 for incident response

## Failure Scenarios

### Dead Letter Queue (DLQ) Management

**Viewing DLQ contents:**
```bash
curl http://localhost:8000/api/v1/dlq
```

**Replaying a single event:**
```bash
curl -X POST http://localhost:8000/api/v1/dlq/{event_id}/replay
```

**Replaying all DLQ events (use with caution):**
```bash
curl -X POST http://localhost:8000/api/v1/dlq/replay-all
```

**Purging old DLQ events:**
```bash
curl -X DELETE "http://localhost:8000/api/v1/dlq?older_than=7d"
```

**When to investigate DLQ:**
- DLQ depth > 50 events (triggers self-alert)
- Repeated failures for the same adapter (likely an adapter issue, not event issue)
- Events with `retry_count >= 3` (all retries exhausted)

### Rolling Back an Automated Action

1. Find the action in the incident timeline:
   ```bash
   curl http://localhost:8000/api/v1/incidents/{incident_id}
   ```

2. Check if the action is rollback-capable:
   ```json
   {
     "action_type": "BLOCK_IP",
     "rollback_capable": true,
     "rollback_procedure": "Remove firewall rule #12345"
   }
   ```

3. Execute rollback via API:
   ```bash
   curl -X POST http://localhost:8000/api/v1/actions/{action_id}/rollback
   ```

4. Verify rollback succeeded:
   ```bash
   curl http://localhost:8000/api/v1/actions/{action_id}
   # status should be "ROLLED_BACK"
   ```

### Adapter Connectivity Issues

**Symptoms:**
- Circuit breaker opens (visible in `/metrics` as `sentinel_adapter_error_rate`)
- Actions queued in PostgreSQL with `PENDING` status
- Self-alert: "Adapter disconnected"

**Diagnosis:**
```bash
# Check adapter health
curl http://localhost:8000/api/v1/adapters/health

# Check specific adapter
curl http://localhost:8000/api/v1/adapters/{adapter_id}/health

# View circuit breaker state
curl http://localhost:8000/metrics | grep circuit_breaker
```

**Resolution:**
1. Verify network connectivity to the vendor API
2. Check if credentials have expired or been rotated
3. Check vendor API status page for outages
4. If connectivity is restored, the circuit breaker will auto-recover (half-open -> closed)
5. Replay any queued actions: `POST /api/v1/dlq/replay-all`

### LLM Provider Issues

**Symptoms:**
- Agent timeout rate spikes
- `sentinel_llm_tokens_used` drops to zero
- Self-alert: "LLM cost spike" or all agents timing out

**Degraded mode behavior:**
- Platform automatically falls back to Sigma rule-based processing
- Alerts are still ingested and classified by rules (reduced accuracy)
- Complex investigations are queued until LLM is available

**Resolution:**
1. Check LLM provider status page
2. Verify API key is valid and has sufficient quota
3. Check `sentinel_llm_cost_usd` — may have hit spending limit
4. If using local model fallback (Ollama), verify it's running: `curl http://localhost:11434/api/tags`

### ChromaDB Issues

**Symptoms:**
- Similarity search returns empty results
- `sentinel_chromadb_query_latency` spikes
- Self-alert: "Vector store unreachable"

**Resolution:**
1. Check ChromaDB container: `docker compose logs chromadb`
2. Verify disk space on ChromaDB volume
3. Platform continues in degraded mode (no memory/similarity context)
4. If corruption suspected, restore from latest snapshot:
   ```bash
   docker compose stop chromadb
   # Restore snapshot volume
   docker compose start chromadb
   ```

## Monitoring Alert Response

### Self-Alert Severity Levels

| Alert | Severity | Response Time | Action |
|-------|----------|--------------|--------|
| Adapter disconnected | HIGH | 15 min | Check adapter, verify network |
| LLM cost spike | MEDIUM | 1 hour | Review token usage, check for alert storm |
| Queue backup (>1000) | HIGH | 15 min | Check agent health, scale if needed |
| DLQ growing (>50) | MEDIUM | 1 hour | Investigate root cause, replay if safe |
| Agent timeout rate >10% | HIGH | 15 min | Check LLM latency, review agent timeouts |
| Vector store unreachable | MEDIUM | 30 min | Check ChromaDB, system continues in degraded mode |
| Audit log hash chain break | CRITICAL | Immediate | Potential tampering — investigate immediately |

### Key Dashboards

If using Grafana, recommended dashboard panels:

1. **System Health**: Adapter status (up/down), circuit breaker states, overall throughput
2. **Agent Performance**: Latency p50/p95/p99 per agent, error rates, queue depth
3. **Alert Lifecycle**: Ingested -> Triaged -> Investigated -> Resolved funnel
4. **Cost Tracking**: LLM token usage over time, estimated cost, budget remaining
5. **Accuracy**: False positive rate (rolling 7-day), analyst override rate
