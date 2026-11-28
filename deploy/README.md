# Run the whole Quantara backend with Docker

Everything is **synthetic** (SANDBOX=1). 12 containers: Kafka (Redpanda), Postgres, `ingest` (100 simulated EVs + edge agents),
`stream-validate`, `stream-enrich`, `svc-rca`, `svc-twin`, `svc-route`, `svc-ota`, `ops` (gateway + sink), optional Grafana.

```bash
pip install quantara-core pyjwt                      # only needed for gen_env.py
PYTHONPATH=. python deploy/gen_env.py                # writes deploy/.env (keys, JWT secret, demo logins) - gitignored
docker compose -f deploy/docker-compose.yml --env-file deploy/.env --profile localkafka up --build
# + Grafana dashboards on :3000:   add  --profile grafana
# build from local sibling checkouts instead of GitHub:  add  -f deploy/docker-compose.local-src.yml
```

* Gateway + reference UI: http://localhost:8080 (`/healthz`, `/api/*`, `/ws`). Demo logins are the commented lines at the bottom of `deploy/.env`.
* Inject a fault (needs the admin or tech login): `OPS_URL=http://localhost:8080 OPS_USER=admin OPS_PASS=... python scripts/inject_gw.py breakdown V000`
* Cloud AI is optional: put `GEMINI_API_KEY` in `deploy/.env`. Without it the cloud uses its built-in Bayesian ranking.
* Using the **Condense** Kafka instead of Redpanda: fill the five `KAFKA_*` values in `deploy/.env`, set `KAFKA_SECURITY_PROTOCOL=SASL_PLAINTEXT`, drop `--profile localkafka`, and create the 7 physical topics (`quantara_{raw.telemetry,raw.edge,valid.telemetry,valid.edge,vss.enriched,cloud.events,edge.in}`).

**Status of this package:** the compose file parses and the env generator is tested (logins verified against the gateway's auth),
but Docker was not available where this was written, so `docker compose up` has not been run end to end. The four app images are the same
Dockerfiles that build on Condense. Expect to fix small things on the first run and tell us.

Security notes: `SIGNING_KEY` is the cloud's private signing key and the compose file gives every container the same `.env` for simplicity
(local dev only). In a real deployment only `svc-ota` gets `SIGNING_KEY`, only `ingest` gets `CLOUD_PUBKEY`, and only `ops` gets `OPS_*`.
