#!/usr/bin/env python3
"""Generate deploy/.env for a local stack: fresh Ed25519 signing keypair, JWT secret and demo users.
Usage: python deploy/gen_env.py [--kafka-local]   (writes deploy/.env, refuses to overwrite)
Passwords are written ONLY to deploy/.env (gitignored) and printed nowhere. Needs: pip install quantara-core pyjwt"""
import base64, json, pathlib, secrets, sys

from quantara_core import crypto
from ops.auth import make_user

out = pathlib.Path(__file__).with_name(".env")
if out.exists(): sys.exit(f"{out} exists; delete it first")
priv, pub = crypto.gen_keypair()
roles = {"admin": ("admin", ["*"]), "tech": ("technician", ["*"]), "owner": ("owner", ["V000"]), "oem": ("oem", ["*"])}
pw = {u: secrets.token_urlsafe(12) for u in roles}
users = {u: make_user(pw[u], r, v) for u, (r, v) in roles.items()}
lines = [
    "TOPIC_PREFIX=quantara_", "SANDBOX=1", "FLEET_SIZE=100",
    "# --- Kafka: local Redpanda by default (docker compose --profile localkafka up). For Condense: set these 5 and drop the profile.",
    "KAFKA_BOOTSTRAP=redpanda:9092", "KAFKA_SECURITY_PROTOCOL=PLAINTEXT", "KAFKA_SASL_MECHANISM=SCRAM-SHA-512",
    "KAFKA_SASL_USERNAME=quantara", "KAFKA_SASL_PASSWORD=",
    "# --- cloud signing key pair (ota signs commands, ingest/edge verifies)",
    f"SIGNING_KEY={priv}", f"CLOUD_PUBKEY={pub}",
    "# --- ops gateway", f"OPS_JWT_SECRET={secrets.token_urlsafe(32)}",
    "OPS_USERS=" + base64.b64encode(json.dumps(users).encode()).decode(),
    "# demo logins (username:password) for the gateway/UI; delete this block in production",
    *[f"# {u}:{pw[u]}" for u in roles],
    "# --- storage", "DATABASE_URL=postgresql://quantara:quantara@postgres:5432/quantara",
    "PG_SSLMODE=disable",
    "# --- cloud AI (optional). Without a key the cloud falls back to its built-in Bayesian ranking.",
    "GEMINI_API_KEY=", "GEMINI_MODEL=gemini-2.5-flash",
]
out.write_text("\n".join(lines) + "\n"); out.chmod(0o600)
print(f"wrote {out} (logins are in the commented block at the bottom)")
