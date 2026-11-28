"""JWT + per-session HMAC request signing + nonce replay cache + rate limits + role/vehicle scoping."""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import OrderedDict

import jwt

ROLES = {"viewer": {"read"}, "technician": {"read", "feedback", "inject", "replay"}, "owner": {"read", "consent", "replay"},
         "oem": {"read", "oem"}, "admin": {"read", "feedback", "inject", "replay", "consent", "oem", "rulebook", "rollout", "audit"}}
SKEW_S, NONCE_TTL_S, JWT_TTL_S = 60, 180, 900


def parse_users(raw):
    """OPS_USERS is JSON, or base64 of that JSON (survives clipboard/quoting damage). Fails with a clear, value-free message."""
    import base64
    raw = (raw or "").strip().strip("'\"")
    for attempt in (lambda: json.loads(raw), lambda: json.loads(base64.b64decode(raw, validate=True))):
        try:
            u = attempt()
            if isinstance(u, dict) and u and all(isinstance(v, dict) and {"salt", "hash", "role"} <= v.keys() for v in u.values()): return u
        except Exception:
            pass
    raise ValueError(f"OPS_USERS is not valid users JSON or base64 of it (received {len(raw)} chars)")


class AuthError(Exception):
    def __init__(self, status, why): self.status, self.why = status, why


def hash_pw(pw, salt=None, iters=200_000):
    salt = salt or secrets.token_hex(8)
    return {"salt": salt, "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iters).hex()}


def make_user(pw, role, vehicles=("*",)): return {**hash_pw(pw), "role": role, "vehicles": list(vehicles)}


class Auth:
    def __init__(self, secret, users, clock=time.time):
        if not secret or len(secret) < 16: raise ValueError("OPS_JWT_SECRET must be >= 16 chars")
        self.secret, self.users, self.clock = secret, users, clock
        self.nonces, self.lock = OrderedDict(), threading.Lock()

    @classmethod
    def from_env(cls):
        return cls(os.environ.get("OPS_JWT_SECRET", "").strip(), parse_users(os.environ.get("OPS_USERS", "")))

    def login(self, user, pw):
        u = self.users.get(user)
        ok = u and hmac.compare_digest(hash_pw(pw, u["salt"])["hash"], u["hash"])
        if not u: hash_pw(pw)                                  # constant-ish time for unknown users
        if not ok: raise AuthError(401, "bad credentials")
        now, jti = int(self.clock()), secrets.token_hex(8)
        tok = jwt.encode({"sub": user, "role": u["role"], "vehicles": u["vehicles"], "jti": jti, "iat": now, "exp": now + JWT_TTL_S},
                         self.secret, algorithm="HS256")
        return {"token": tok, "session_key": self.session_key(jti), "expires_in": JWT_TTL_S, "role": u["role"]}

    def session_key(self, jti): return hmac.new(self.secret.encode(), b"sess|" + jti.encode(), hashlib.sha256).hexdigest()

    def claims(self, token):
        try: return jwt.decode(token, self.secret, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
        except jwt.PyJWTError as e: raise AuthError(401, f"invalid token: {type(e).__name__}")

    @staticmethod
    def signing_string(method, path, ts, nonce, body: bytes):
        return "\n".join([method.upper(), path, str(ts), nonce, hashlib.sha256(body).hexdigest()])

    def verify_signed(self, c, method, path, ts, nonce, sig, body: bytes):
        if not (ts and nonce and sig): raise AuthError(401, "request signature required")
        try: ts = int(ts)
        except ValueError: raise AuthError(401, "bad timestamp")
        now = self.clock()
        if abs(now - ts) > SKEW_S: raise AuthError(401, "stale timestamp")
        want = hmac.new(self.session_key(c["jti"]).encode(), self.signing_string(method, path, ts, nonce, body).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig): raise AuthError(401, "bad signature")
        with self.lock:                                       # only record nonces of *valid* signatures
            for k in [k for k, t in self.nonces.items() if now - t > NONCE_TTL_S]: del self.nonces[k]
            if (c["jti"], nonce) in self.nonces: raise AuthError(401, "replayed nonce")
            self.nonces[(c["jti"], nonce)] = now
            while len(self.nonces) > 100_000: self.nonces.popitem(last=False)

    @staticmethod
    def require(c, perm):
        if perm not in ROLES.get(c["role"], ()): raise AuthError(403, f"role {c['role']} may not {perm}")

    @staticmethod
    def sees(c, vid): return "*" in c["vehicles"] or vid in c["vehicles"]


class RateLimiter:
    def __init__(self, rate, burst, clock=time.monotonic):
        self.rate, self.burst, self.clock, self.b, self.lock = rate, burst, clock, {}, threading.Lock()

    def allow(self, key):
        now = self.clock()
        with self.lock:
            tokens, t = self.b.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - t) * self.rate)
            if tokens < 1: self.b[key] = (tokens, now); return False
            self.b[key] = (tokens - 1, now); return True
