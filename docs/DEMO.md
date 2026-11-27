# Demo script (< 5 minutes). Say up front: everything is simulated.

1. **0:00 Frame (20 s).** "100 simulated EVs, each runs an edge agent. The vehicle decides first; the cloud is for what it can't decide. Nothing here is a real vehicle."
2. **0:20 Fleet tab.** Show edge-resolved vs escalated and bytes saved (counters from ingest). "Resolved issues leave as summaries."
3. **0:50 Breakdown.** Actions → inject `breakdown` on V000. Edge derates locally within seconds; Incidents tab shows it resolved at the edge or escalated with a reason.
4. **1:30 Cloud path.** Open the escalated incident: RCA hypotheses (likelihood × prior), twin verdict (fitted hidden heat or flow-explained), recommended power cap, route to a reachable online station. Mention the signed command (Ed25519, counter, expiry) and that the edge rejected nothing.
5. **2:15 Learning loop.** Send technician feedback on the incident. After 3 twin-confirmed unattributed cases, Actions → "Proposed rulebook changes" appears; approve → staged rollout 5/25/100 % (owner consent required per vehicle).
6. **3:00 Cyber.** Inject `cyber_flood` then `cal_tamper`. Security incident appears; edge isolated CAN / restored golden calibration; telemetry-vs-physics mismatch quarantines a vehicle in `stream-validate`.
7. **3:40 Grid outage.** Inject `grid_outage`: stations offline, route service re-plans.
8. **4:10 Trust.** Audit tab: chain verified, every action by actor. Mention JWT + per-request HMAC + nonce replay protection + role/vehicle scoping.
9. **4:40 Close.** "Simulated: vehicles, physics, stations, approvals. Real: pipeline on Condense, edge logic, signatures, guards, audit." Point to the repos and README.

Backup if live injection stalls: show Grafana (Postgres) or the recorded Incidents list.
