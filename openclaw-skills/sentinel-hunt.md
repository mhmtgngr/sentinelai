# Sentinel-AI: Threat Hunting Skill

## Description
Proactive threat hunting using hypothesis-driven investigation. Queries connected security products for indicators of compromise and suspicious patterns that evade traditional detection rules.

## Trigger
- Scheduled heartbeat (configurable interval)
- New threat intelligence received
- Manual hunt request

## Hunting Hypotheses
- **TH001**: Unusual outbound connections (C2 detection)
- **TH002**: Credential dumping indicators (LSASS, SAM)
- **TH003**: Living off the land binaries (LOLBins abuse)
- **TH004**: DNS tunneling (exfiltration detection)
- **TH005**: Lateral movement patterns (PsExec, RDP anomalies)

## Actions
1. **Query** all connected adapters for relevant telemetry
2. **Analyze** data against hunting hypotheses
3. **Correlate** findings with threat intelligence feeds
4. **Report** findings with MITRE ATT&CK mapping
5. **Escalate** confirmed threats to incident response

## Parameters
- `hypothesis_ids`: Specific hypotheses to run (default: all)
- `time_range`: Lookback period in hours (default: 24)
- `target_assets`: Specific hosts/IPs to focus on (default: all)
