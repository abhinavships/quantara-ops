# Grafana for Quantara (synthetic data only)

Reads the same Neon Postgres the ops app writes to. Tables: `events`, `latest`, `telemetry` (5 s history, 24 h), `audit`.

1. Run Grafana (Docker): 
   ```
   docker run -d -p 3000:3000 \
     -e PG_HOST=<neon-host> -e PG_USER=<user> -e PG_PASSWORD=<password> -e PG_DATABASE=neondb \
     -v $PWD/grafana/provisioning:/etc/grafana/provisioning \
     -v $PWD/grafana/dashboard.json:/var/lib/grafana/dashboards/dashboard.json grafana/grafana
   ```
   (Or Grafana Cloud: add a PostgreSQL data source with uid `quantara-pg`, SSL mode `require`, then import `dashboard.json`.)
2. Open http://localhost:3000, dashboard **Quantara: edge-first fleet protection**. Pick a **Vehicle** at the top.
3. Panels: edge vs cloud, incidents, verdicts, commands, rollouts, DLQ, audit, plus per-vehicle speed, wheel speeds,
   acceleration (incl. speed-bump spikes), suspension travel, steering, battery temp/SoC, lamps and gear.

Credentials stay in your shell / Grafana secrets, never in the repo.

## Scenario dashboards
`s1_breakdown.json` (vehicle + service centre), `s2_ecosystem.json` (OEM/charging ops + driver), `s3_degradation.json` (owner + OEM),
`s4_cyber.json` (OEM security + service centre). Inject with `scripts/inject_gw.py <scenario> [vehicles]` (gateway login, no Kafka creds).
Panels fill when the matching scenario is injected; the "AI second opinion" panels need `GEMINI_API_KEY` on the rca node.
