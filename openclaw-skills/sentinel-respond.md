# Sentinel-AI: Incident Response Skill

## Description
Automated incident response with playbook-driven actions. Creates incidents from confirmed threats, executes response playbooks, and manages the full incident lifecycle.

## Trigger
- Threat confirmed by triage or threat hunting
- High-severity alert escalation
- Manual incident creation

## Response Playbooks
- **Block Malicious IP** — Block across all firewalls and WAFs
- **Isolate Compromised Host** — Network containment via EDR
- **Revoke User Sessions** — Identity provider session revocation
- **Collect Forensics** — Automated evidence gathering
- **Notify SOC** — Multi-channel alerting (Slack, email)

## Actions
1. **Create** incident with severity classification
2. **Execute** appropriate playbook based on attack type
3. **Coordinate** actions across multiple adapters
4. **Track** all actions in incident timeline
5. **Escalate** if human approval required for critical actions

## Parameters
- `auto_respond`: Enable automatic response (default: true)
- `require_approval`: Actions requiring human approval (configurable)
- `notification_channels`: Where to send alerts (default: ["slack"])
