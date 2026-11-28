# Scenarios: inject names and coverage

Edge = deterministic rules (reduce-only). Cloud = `svc/brain.py` (Gemini, validated closed vocabularies, flagged `source: fallback` if the model is unavailable)
on top of Bayesian ranking. Inject via `POST /api/inject {"scenario": "...", "vehicles": ["V000"]}` or `scripts/inject_gw.py <scenario> <vehicle>`.

| Plan item | inject name | Edge (rules) | Cloud (model) | Status |
|---|---|---|---|---|
| Coolant/pump breakdown, BMS temp rise (P0A93) | `breakdown`, `pump_recover` | derate, limp, DTC P0A93 | RCA, twin, route, triage | done |
| Efficiency / degradation | `degradation` | eco advice, consent | RCA, triage | done |
| Grid outage, charging ecosystem | `grid_outage` | notify | fleet route re-plan | partial (single-vehicle route; no fleet-wide SoC optimiser) |
| Contactor stuck P0AA1 | `contactor_stuck` | derate 0.4, limp | triage (recall hint) | done |
| DC/DC fault P0A94 | `dcdc_fail` | derate 0.7 | triage | done |
| BMS comm lost U0111 | `bms_comm_lost` | derate 0.4, limp | triage | done |
| Battery degraded P0A80 | `battery_degraded` | derate 0.7 | triage, warranty hint | done (no fleet warranty forecast) |
| CAN flood/fuzz/spoof/replay | `cyber_flood` `cyber_fuzz` `cyber_spoof` `cyber_replay` | IDS, isolate CAN | RCA, triage | done |
| Calibration tamper | `cal_tamper` | restore golden | triage | done |
| Malicious OBD dongle | `obd_dongle` | isolate OBD | triage, fleet correlation by cause | done (no dongle-model lookup) |
| ECU bus-off / impersonation | `ecu_busoff` | isolate CAN | triage | done |
| TCU remote intrusion | `tcu_intrusion` | isolate TCU | triage | done |
| Rogue charger | `rogue_charger` | stop charge, isolate | triage | done |
| ADAS sensor spoofing | `adas_spoof` | down-weight ADAS | triage | done |
| Link loss | `link_down`, `link_up` | store-and-forward | - | done |
| Reset | `clear` | - | - | done |

## Model-driven situations (no scripted scenario)
`POST /api/situation {"text": "...", "params": {...}}` (or `python scripts/inject_gw.py situation "..." '{"energy_penalty":0.15}'`).
The cloud `fleet` planner (`quantara-services/svc/fleet.py`) gives Gemini the live fleet (SoC, position, incidents + triage), stations and a closed
action vocabulary; it returns a plan which is validated against real vehicle and station ids and published as `cloud.fleet kind=plan`
(`GET /api/plans`) plus driver notifications (`GET /api/notifications`). Recalls, patches and quality alerts are proposals (`needs_approval`).
Examples to try: "A crash closes the highway; traffic is diverted onto a mountain road adding 60 km and 800 m of climb" (params energy_penalty 0.15),
"Coolant pump supply delayed 8 weeks, 3000 vehicles waiting, service bays handle 200 a week; triage by safety", "Forecast battery warranty claims by
region and batch from current P0A80 trends", "Possible malware found on the CAN network of the V0xx cluster: propose patch, recall and notifications",
"Faulty OTA 3.2 caused false battery warnings after reboot; stage the rollout and flag affected cars", "Proactive alerts for cars likely to break down this week".
Only physical effect the simulator applies: `energy_penalty` (fraction of SoC removed from every car). Everything else is the model's job.
The 30-minute scene button: `POST /api/replay/save`, then `GET /api/replays/{id}` (UI plays it back at 7.5x = 4 min).

## Still not covered
Durability/fatigue twin and regional calibration twin have no physics model (the planner can only discuss them); no signed patch artifact is built
(patch_proposal is text for a human); the simulator has no road geometry, so detour effects are the single energy_penalty number.
