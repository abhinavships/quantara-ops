# Security

Scope: synthetic demo; no real vehicles. Controls below are implemented and tested (`tests/test_ops.py`, `quantara-services`, `quantara-ingest`).

## Threat model (summary)
| Threat | Control |
|---|---|
| Forged / altered cloud→vehicle command | Ed25519 signature over {vehicle_id, kind, params, counter, expires, consent, oem}; edge verifies signature, vehicle id, expiry, strictly increasing counter |
| Replayed or stale command | per-vehicle counter + expiry (edge rejects `replayed counter`, `expired`) |
| Dangerous command | guards on both sides: derate ≥ 40 %, reduce-only actions, limits can only decrease, mandatory rules immutable, rulebook version must increase |
| Command without owner/OEM approval | issuer refuses to sign; consent/OEM proofs are bound to the command counter and vehicle |
| Bad rulebook rollout | staged 5/25/100 %, halt on >20 % failure, rollback command to applied vehicles, snapshot rollback on edge |
| Stolen/forged user token | HS256 JWT (15 min), `exp`/`sub`/`jti` required, `alg:none` and wrong-secret tokens rejected |
| Replay of a captured API write | per-session HMAC-SHA256 over method, path, timestamp, nonce, body hash; ±60 s skew; nonce cache (180 s); signature key derived from the token's `jti` so a token alone cannot sign |
| Privilege escalation / IDOR | roles (viewer, technician, owner, oem, admin) and per-vehicle scope enforced server-side on reads, writes, WebSocket |
| Brute force / abuse | login limiter (per IP+user), read and write token buckets, constant-time compare, failed logins audited |
| Audit tampering | append-only table (DB triggers) + SHA-256 hash chain; `/api/audit/verify` detects edit, delete, reorder even with DB superuser |
| Injection of attacks outside the sandbox | `/api/inject` needs `SANDBOX=1`, whitelisted scenarios, scoped vehicles; edge refuses non-`sim` vehicles |
| Secrets in the repo | none; env only; `.gitignore` covers `.env` and `.secrets/` |

## Known limits (honest)
- HMAC session key is derived from the server secret and the token id; a stolen token plus a stolen session key is full session compromise (15 min).
- Nonce cache and rate limiters are in-process: they reset on restart and are per replica. Use one replica or move them to Redis for production.
- JWT secret rotation, token revocation lists, TLS termination and mTLS between apps rely on the platform (Condense) and are not implemented here.
- The CAN IDS is statistical + rule based; slow-and-low attacks below its thresholds are not detected.
- SQLite fallback is per-pod and ephemeral.

Report issues privately to the maintainers of the repository.
