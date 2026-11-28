# Handoff: integrating a UI with the Quantara backend on Condense

Everything runs on **Condense** (Quantara workspace). A UI needs only the gateway URL and a login. No Kafka, no database access.

## 1. What is deployed

| Pipeline node | App (version) | Role |
|---|---|---|
| quantara-ingest | quantara-ingest 0.3.0 | edge simulator + rules (DTC library, security isolation) |
| stream-validate / stream-enrich | quantara-stream | validate, enrich, route |
| svc-rca | quantara-services | cause ranking + per-vehicle model triage |
| svc-twin | quantara-services 0.2.4, `ROLE=twin+fleet` | digital twin + fleet situation planner |
| svc-route / svc-ota | quantara-services | charging routes / staged OTA with consent |
| ops | quantara-ops 0.2.1 | sink + secured HTTPS gateway + audit + DB |

Gateway base URL: the `ops` node's **Ingress Path** (Pipelines -> ops -> Edit). Same URL serves `/ui` (reference page), `/login`, `/api/*`, `/ws`.

## 2. Integrate in 5 steps (UI side)

1. Ask the backend owner for a **gateway login** (roles: viewer, technician, owner, oem, admin). Never ship it in client code.
2. `POST {base}/login {"username","password"}` -> `{token, session_key, role}`. Keep both in memory.
3. Reads: `GET {base}/api/...` with `Authorization: Bearer <token>`.
4. Writes (POST) need the HMAC headers described in `docs/API.md`. Copy `api()` from `ui/index.html` or `scripts/inject_gw.py`.
5. Live updates: open `WS {base}/ws`, send `{"token": "..."}`, then render each `{topic, vehicle_id, payload}`.

Endpoint list: `docs/API.md`. Data shapes: `docs/DATA.md`. Scenarios: `docs/SCENARIOS.md`.

## 3. Screens the plan asks for, and the endpoint behind each

| Screen | Endpoint |
|---|---|
| Fleet overview / event graphs | `GET /api/overview`, `GET /api/history?vehicle=&signals=&minutes=` |
| Incident + ranked causes + highlighted part | `GET /api/incidents` (`hypotheses`, `reasons`, `edge_cause`, DTC in `evidence`) |
| Cluster alert / driver notification | `GET /api/notifications`, `/ws` |
| Fleet plan (stranded cars, recalls, service triage) | `GET /api/plans` (`source` = `llm` or `fallback`, `error` explains why) |
| "Save last 30 min" button | `POST /api/replay/save {vehicle}` then `GET /api/replays/{id}` to play back |
| Owner consent for OTA | `GET /api/pending`, `POST /api/consent` |
| Demo triggers (sandbox only) | `POST /api/inject {scenario, vehicles}`, `POST /api/situation {text, params}` |

Known UI to-do: event graphs were reported as plotted wrongly. Use `/api/history` (`[[ts, value], ...]`, one point per 5 s, oldest first), plot against `ts` seconds, not array index.

## 4. How to redeploy a change (Condense only)

1. Push to the repo's `main` on GitHub (quantara-ingest / -stream / -services / -ops).
2. Applications -> the draft -> Edit Application -> IDE. In the terminal: `git remote set-url origin <repo url> && git fetch origin && git reset --hard origin/main`. (The IDE's first Enter is swallowed; press it twice.)
3. Publish Application -> Update Existing -> pick the app -> new version number -> Publish. Build takes ~7 minutes.
4. Pipelines -> the node -> Edit -> Version dropdown (newest first) -> Save.
5. The draft's env list ("Edit ENVs") must contain every variable the app reads. If it changes, node forms blank their secret fields and someone must re-enter them.

## 5. Secrets and settings (never in git or chat)

Per node form in Condense: `KAFKA_SASL_PASSWORD`, `OPS_USERS` (base64 JSON of users), `OPS_JWT_SECRET`, `DATABASE_URL`, `GEMINI_API_KEY`, `SIGNING_KEY`. Non-secret: `TOPIC_PREFIX=quantara_`, `ROLE`, `PORT=8080`, `SANDBOX=1`. `svc-twin` and `svc-rca` need `GEMINI_API_KEY`. Nodes that do not use `OPS_USERS` still need a dummy value because the shared schema marks it required.

## 6. Current status and what is left

- Verified live: ops 0.2.1 healthy; `/api/inject contactor_stuck` accepted; `/api/situation` reaches the planner and `/api/plans` / `/api/notifications` return.
- **Blocked: live Gemini plans.** The key has no usable quota (retired 2.x models 404, preview models 429, `gemini-flash-latest` 503). Plans come back `source: fallback` with the reason in `error`. Fix: a key with billing/quota, pasted into `svc-twin` and `svc-rca`.
- `svc-rca` is still on services 0.2.0: move to the latest version.
- Check that a situation's `energy_penalty` reaches the simulated cars (the plan snapshot showed no low-battery cars).
- Not built: durability/fatigue twin, regional calibration, signed patch builder, replay player UI, road geometry.
- After the demo: rotate the Gemini key, clear active injections (`inject clear`), keep `SANDBOX=1`.
