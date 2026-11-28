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

## Not built yet (be honest with the UI team)
Highway-closure detour re-routing for many cars; service-centre overload triage queue (parts shortage); warranty/batch forecasting;
durability and regional-calibration twins; malware patch builder + fleet-wide patch rollout (OTA staging exists, patch building does not);
virtual OTA test on twins; targeted recall list; proactive owner alerts as a first-class event; 30-minute scene replay button
(raw data exists: `GET /api/history?vehicle=..&minutes=30`, the replay UI and a "save" event do not).
New scenarios follow one pattern: add a DTC/intrusion rule in `quantara-ingest/edge/dtc.py`, a name in `sim/fleet.py` `DIAG_FAULTS`, a cause in `quantara-services/svc/rca.py` `CAUSES`, a reference line in `svc/brain.py` `DTC_REF`.
