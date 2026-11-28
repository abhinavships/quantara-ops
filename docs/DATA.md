# Data model

## Postgres (or SQLite when DATABASE_URL is unset)
* `events(id, ts, topic, kind, vehicle_id, payload JSONB)` - every non-telemetry event, logical `topic` (e.g. `cloud.twin`).
* `latest(k, ts, payload)` - hot state. `vss:<vehicle>` = newest enriched sample per vehicle, `feeds` = weather + grid + fleet counters.
* `telemetry(ts, vehicle_id, vss JSONB)` - history, 1 row / vehicle / 5 s, kept 24 h. `ts` is epoch seconds (wall clock).
* `audit(seq, ts, actor, action, detail, prev, hash)` - append-only, hash-chained (DB triggers reject UPDATE/DELETE).

## Signals (VSS names, in `latest.payload.vss` and `telemetry.vss`)
Speed; Acceleration.{Longitudinal,Lateral,Vertical}; Chassis.SteeringWheel.Angle; Chassis.Axle.Row{1,2}.Wheel.{Left,Right}.{Speed,Suspension.Travel};
Body.Lights.{Beam.Low.IsOn,Brake.IsActive,Hazard.IsSignaling}; Powertrain.Transmission.CurrentGear; Powertrain.ElectricMotor.{Power,Current};
Powertrain.TractionBattery.{Temperature.Average, StateOfCharge.Current (0..1), Efficiency (km/kWh), Cooling.FlowRate, Cooling.PumpDuty}.
`latest.payload` also has `position [lat,lon]`, `edge {cap, rb, ignored}`, `windows`, `ambient_c`, `grid_outage`, `nearest_station`.

## Event payloads (key fields)
* `cloud.escalations` / `cloud.security`: `{kind, vehicle_id, ts, reasons[], incident{id,cause,confidence,evidence{},actions[],status}, freeze_frame{ring_5min[]}, context}`
* `cloud.rca`: `{incident_id, vehicle_id, edge_cause, hypotheses[{cause,likelihood,prior,posterior}], top, margin, ring[], llm?{cause,confidence,rationale,model}}`
* `cloud.twin`: `{incident_id, final_cause, rca_top, recommended_cap, hidden_heat_confirmed, twin{rmse_*, time_to_derate_s{1.0,0.7,0.4}}, last{}}`
* `cloud.route`: `{incident_id, vehicle_id, reason, cap, ok, range_km, choice{station,distance_km,eta_min}, alternatives[], advice?}`
* `cloud.fleet`: `{kind:"feeds", weather, grid{outage,load,stations[{id,lat,lon,online,ports}]}, edge_counters}` and `{kind:"fleet_incident", cause, vehicles[], suggestion}`
* `cloud.ota`: `rulebook_proposal`, `rollout_status`, `consent_decision`, `feedback`, `rulebook_approve`; `notify.out`: consent requests / refusals; `commands.out`: signed commands.

## Grafana
`grafana/s0_control_room.json` (map + overview), `s1..s4` scenario dashboards, `dashboard.json` (original overview). Provisioning in
`grafana/provisioning`. Queries use the full VSS names and `ts BETWEEN $__unixEpochFrom() AND $__unixEpochTo()` (the time-filter macro breaks on `to_timestamp(ts)`).
