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
