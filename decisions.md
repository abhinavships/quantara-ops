# Decisions (ops + whole platform)

1. **Edge decides first; escalation is a pure, unit-tested function** (`quantara-ingest/edge/policy.py`) so "why did this go to the cloud" is always answerable and is shown in the UI/Grafana.
2. **One image per repo, `ROLE` selects the service.** Separate Condense deployments give independent scaling, failure isolation and versioning without maintaining eight code bases. Total deployed apps: 8 (limit 10).
3. **Topic registry as the data contract** in `quantara-core` (names, partitions, retention). Apps create their topics idempotently at start-up (the broker does not auto-create). Prefix `quantara_` joins directly.
4. **Human inputs on `cloud.ota`**, not `control.inject`: the ingest app treats every `control.inject` record as a scenario injection.
5. **Cloud can only reduce.** Commands are reduce-only with guards on both sides; the cloud proposes rulebook changes but never auto-applies them: an admin approves, then a staged rollout needs per-vehicle owner consent.
6. **Learning loop is conservative.** Priors are Laplace-smoothed counts of technician-confirmed causes; rule proposals need ≥3 twin-confirmed, edge-unattributed cases.
7. **Digital twin = the simulator's own thermal model** run with ≤5 s sub-steps. It validates RCA by fitting an unexplained heat source; if none is needed, flow/pump explains the rise.
8. **Gateway signs writes with a per-session HMAC** (in addition to the JWT) so a leaked bearer token cannot be replayed from a log. Token never goes in a URL; the WebSocket authenticates with its first message.
9. **Store: SQLite default, Postgres via `DATABASE_URL`, optional Redis hot cache.** Condense gives us Kafka only, so the single-pod demo (`ROLE=all`) uses SQLite; Grafana needs Postgres. Splitting sink and gateway requires Postgres.
10. **Audit chain over append-only table**: triggers stop casual edits; the chain catches privileged ones.
11. **Route optimiser is straight-line × 1.3**; no road graph. Good enough to show reachability reasoning; not a navigation product.
12. **Condense specifics learned:** Python 3.12 builder works; variables are a UI table or a JSON editor (Upload JSON → paste); IDE pod restarts lose `~/.ssh`, so repos are public and cloned over HTTPS; "Clone" on a deployment copies its env including the password.
13. **Test corrections (not weakening):** an IDS test that accepted any attack label was tightened; a hysteresis test with `or True` was rewritten; an RCA-prior test asserting "posterior doubles" (impossible from 0.49) was replaced by "+0.3 and becomes top"; a `Store` bug (falsy Redis client ignored) was found by a test and fixed.
