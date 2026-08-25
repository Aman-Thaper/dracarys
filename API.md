# DRACARYS — API Reference

Base URL: `http://127.0.0.1:8000`. Interactive docs (OpenAPI/Swagger) at `/docs`.
All responses are JSON; errors use `{ "error": string, "detail": any }`.

## Health
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Service status, version, active planner |

## Targets
| Method | Path | Description |
|---|---|---|
| POST | `/api/targets` | Create a target (rejected if out of scope) |
| GET | `/api/targets` | List targets |
| GET | `/api/targets/{id}` | Get a target |
| POST | `/api/targets/validate` | Scope-check a base URL without creating anything |
| POST | `/api/targets/lab` | Register the bundled lab target (idempotent) |

## Campaigns
| Method | Path | Description |
|---|---|---|
| POST | `/api/campaigns` | Create a campaign for a target |
| GET | `/api/campaigns` | List campaigns |
| GET | `/api/campaigns/{id}` | Get a campaign (state, progress, score) |
| GET | `/api/campaigns/{id}/summary` | Aggregated counts + severity + compromise/fix status |
| POST | `/api/campaigns/{id}/start` | Launch the autonomous loop (background task) |
| POST | `/api/campaigns/{id}/pause` | Request a pause (effective at the next phase boundary) |
| POST | `/api/campaigns/{id}/resume` | Resume a paused campaign where it left off |
| POST | `/api/campaigns/{id}/stop` | Engage the kill switch (→ CANCELLED) |

## Campaign resources (read-only)
| Method | Path | Description |
|---|---|---|
| GET | `/api/campaigns/{id}/observations` | Recon observations |
| GET | `/api/campaigns/{id}/hypotheses` | Planned hypotheses (with planner + priority) |
| GET | `/api/campaigns/{id}/findings` | Confirmed, evidence-backed findings |
| GET | `/api/campaigns/{id}/test-runs` | Every bounded tool execution |
| GET | `/api/campaigns/{id}/evidence` | Evidence records (hashed, redacted) |
| GET | `/api/campaigns/{id}/evidence/{eid}` | One evidence record |
| GET | `/api/campaigns/{id}/attack-paths` | Discovered chains (with canary flag) |
| GET | `/api/campaigns/{id}/graph` | Attack graph (nodes + edges) for visualization |
| GET | `/api/campaigns/{id}/remediations` | Remediations (root cause, patch diff, verify test) |
| GET | `/api/campaigns/{id}/retests` | Retest results (before/after outcomes) |
| GET | `/api/campaigns/{id}/audit` | Campaign audit trail |
| GET | `/api/audit` | Recent audit events across campaigns |

## Example: run a campaign end to end
```bash
B=http://127.0.0.1:8000
TID=$(curl -s $B/api/targets | jq -r '.[0].id')
CID=$(curl -s -X POST $B/api/campaigns -H 'content-type: application/json' \
      -d "{\"target_id\":\"$TID\",\"name\":\"demo\"}" | jq -r '.id')
curl -s -X POST $B/api/campaigns/$CID/start >/dev/null
# poll
curl -s $B/api/campaigns/$CID | jq '.state, .progress.target_compromised'
curl -s $B/api/campaigns/$CID/summary | jq '{findings:.counts.findings, fixes:.fixes_verified}'
curl -s $B/api/campaigns/$CID/attack-paths | jq '.[] | {title, reaches_canary}'
```
