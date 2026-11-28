# Gateway API (quantara-ops, port 8080)

Auth: `POST /login {"username","password"}` -> `{token, session_key, expires_in, role}`. Send `Authorization: Bearer <token>` on every call.
**Writes (POST) are also HMAC-signed**: headers `x-timestamp` (unix s, +-skew), `x-nonce` (unique), `x-signature` =
`hex(HMAC_SHA256(session_key, "\n".join([METHOD, PATH, ts, nonce, hex(SHA256(body))])))`. Reference implementations: `ui/index.html`
(`api()`), `scripts/inject_gw.py`. Roles: viewer(read) technician(read,feedback,inject) owner(read,consent) oem(read,oem) admin(all).
Users can be scoped to vehicles (`vehicles: ["V000"]` or `["*"]`).

| method path | perm | returns |
|---|---|---|
| GET /healthz | none | `{ok, audit}` |
| GET /api/me | read | user, role, vehicle scope, sandbox flag |
| GET /api/overview | read | edge counters, incidents, by_cause, by_reason, by_verdict, commands, dlq, quarantine, rollouts, per_minute[30], vehicles_live |
| GET /api/incidents | read | incidents joined with rca/twin/route: id, vehicle_id, edge_cause, reasons, actions, rca_top, final_cause, recommended_cap, hypotheses[], route |
| GET /api/signals | read | VSS signal names + vehicles currently reporting |
| GET /api/history?vehicle=V000&signals=a,b&minutes=30 | read | `{vehicle, series:{signal:[[ts,value],...]}}` (24 h retention, 1 point / 5 s) |
| GET /api/events?after=ID&topic=cloud.twin | read | raw events (latest 200) |
| GET /api/metrics | read | counters |
| GET /api/pending, /api/proposals, /api/rollouts | read | consent requests, rulebook proposals, rollout status |
| GET /api/audit, /api/audit/verify | audit | hash-chained audit log / verification |
| POST /api/feedback `{incident_id, confirmed_cause}` | feedback | technician feedback -> learning priors |
| POST /api/consent `{request_id, decision}` | consent | owner approves/denies an OTA |
| POST /api/oem/approve `{request_id, approved}` | oem | OEM approval |
| POST /api/rulebook/approve `{event_id, vehicles?}` | rulebook | start staged rollout of a proposed edge rulebook |
| POST /api/rollout/tick `{rollout}` | rollout | advance a staged rollout |
| POST /api/inject `{scenario, vehicles?}` | inject | publish a sandbox scenario (SANDBOX=1 only) |
| WS /ws | read | send `{"token": "..."}` first; then a stream of `{id, topic, vehicle_id, payload}` for every new event |

Scenarios accepted by `/api/inject`: see `docs/SCENARIOS.md`.
