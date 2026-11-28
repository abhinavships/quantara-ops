# Architecture

```
 ingest (sim + EDGE agent, 100 vehicles)              <- the edge decides FIRST, with deterministic rules, even with no network
   |  raw.telemetry (1 Hz VSS-ish signals)  raw.edge (escalations, security, feeds)
   v
 stream-validate  -> valid.telemetry / valid.edge ; bad -> dlq ; suspicious vehicle -> quarantine
   v
 stream-enrich    -> vss.enriched (standard VSS names + windows + position + nearest station) ; escalations -> cloud.*
   v
 CLOUD services (only for what the edge escalates)
   svc-rca   root cause: Bayesian ranking now; optional Gemini second opinion      -> cloud.rca
   svc-twin  physics what-if (thermal model), safe power cap                      -> cloud.twin
   svc-route reachable online charger, reserve margin                             -> cloud.route
   svc-ota   signed commands, consent/OEM approval, staged rollout 5/25/100, rollback -> commands.out, notify.out, cloud.ota
   v
 ops   sink (Kafka -> Postgres/SQLite) + secured gateway (JWT, HMAC-signed writes, replay guard, hash-chained audit) + REST + WebSocket
```

**Edge vs cloud (design rule):** the *edge* is rule-based, deterministic, reduce-only (derate, limp, alert, isolate CAN, restore golden calibration,
ignore a faulty sensor). The *cloud* is where models run: it may only recommend, and every change it pushes is signed, range-guarded,
consent-gated where required, rolled out in stages with rollback, and written to the audit chain.

## Topics
Kafka cluster limit: 10 topics. The code uses 20 *logical* topics (`quantara_core.topics.TOPICS`) mapped onto 7 *physical* ones
(`PHYSICAL`/`LOGICAL`); each message carries `_lt` (its logical name) and consumers filter on it. Always use `quantara_core.bus`; never
read the physical topics raw. All topic and consumer-group names start with `TOPIC_PREFIX` (`quantara_`).

| physical | logical topics carried |
|---|---|
| raw.telemetry | raw.telemetry |
| raw.edge | raw.edge, raw.feeds |
| valid.telemetry | valid.telemetry |
| valid.edge | valid.edge, valid.feeds |
| vss.enriched | vss.enriched |
| cloud.events | dlq, quarantine, cloud.escalations, cloud.security, cloud.fleet, cloud.rca, cloud.twin, cloud.route, cloud.ota, notify.out, audit |
| edge.in | commands.out (cloud -> vehicle), control.inject (sandbox scenarios) |

## Repos
quantara-core (contract: topics, bus, crypto, config) - quantara-ingest (sim + edge) - quantara-stream (validate/enrich) -
quantara-services (rca/twin/route/ota) - quantara-ops (sink, gateway, UI, Grafana, this deploy folder).
