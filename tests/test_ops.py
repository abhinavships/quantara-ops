import hashlib
import hmac
import json
import time
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient

from ops.audit import AuditLog
from ops.auth import Auth, RateLimiter, make_user
from ops.gateway import create_app
from ops.sink import Sink
from ops.store import Store
from quantara_core import config
from quantara_core.bus import MemBus

SECRET = "x" * 32
PW = {"viewer": "pw-view-1", "tech": "pw-tech-1", "owner1": "pw-own-1", "owner2": "pw-own-2", "oem": "pw-oem-1", "admin": "pw-adm-1"}
USERS = {"viewer": make_user(PW["viewer"], "viewer", ["V1"]), "tech": make_user(PW["tech"], "technician", ["*"]),
         "owner1": make_user(PW["owner1"], "owner", ["V1"]), "owner2": make_user(PW["owner2"], "owner", ["V2"]),
         "oem": make_user(PW["oem"], "oem", ["*"]), "admin": make_user(PW["admin"], "admin", ["*"])}


class Env:
    def __init__(self, sandbox=True, **kw):
        self.store, self.bus = Store(), MemBus()
        self.auth = Auth(SECRET, USERS)
        self.app = create_app(self.store, self.bus, self.auth, sandbox=sandbox, **kw)
        self.c = TestClient(self.app)
        self.sink = Sink(self.store, self.bus)
        self.sess = {}

    def feed(self, topic, msg): self.bus.publish(config.topic(topic), msg, key=msg.get("vehicle_id")); self.sink.pump()

    def login(self, user):
        r = self.c.post("/login", json={"username": user, "password": PW[user]})
        assert r.status_code == 200, r.text
        self.sess[user] = r.json(); return r.json()

    def hdr(self, user): return {"authorization": "Bearer " + self.sess[user]["token"]}

    def post(self, user, path, body, ts=None, nonce=None, sig=None, method="POST"):
        raw = json.dumps(body).encode()
        ts = int(time.time()) if ts is None else ts
        nonce = nonce or uuid.uuid4().hex
        s = self.sess[user]
        j = jwt.decode(s["token"], SECRET, algorithms=["HS256"])
        key = hmac.new(SECRET.encode(), b"sess|" + j["jti"].encode(), hashlib.sha256).hexdigest()
        assert key == s["session_key"]
        sig = sig or hmac.new(key.encode(), Auth.signing_string(method, path, ts, nonce, raw).encode(), hashlib.sha256).hexdigest()
        return self.c.request(method, path, content=raw, headers={**self.hdr(user), "x-timestamp": str(ts), "x-nonce": nonce,
                                                                  "x-signature": sig, "content-type": "application/json"})


@pytest.fixture
def env():
    e = Env()
    for u in USERS: e.login(u)
    return e


def esc(vid, iid): return {"kind": "escalation", "vehicle_id": vid, "ts": 10.0, "reasons": ["unattributed"],
                           "incident": {"id": iid, "cause": "unknown", "actions": ["alert"]}}


# ---------- authentication ----------
def test_login_bad_password_401_and_audited():
    e = Env()
    r = e.c.post("/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401 and e.app.state.audit.entries()[-1]["action"] == "login_failed"
    assert e.c.post("/login", json={"username": "ghost", "password": "x"}).status_code == 401


def test_login_rate_limited():
    e = Env(login_rate=(0.0001, 3))
    codes = [e.c.post("/login", json={"username": "admin", "password": "bad"}).status_code for _ in range(6)]
    assert codes[:3] == [401] * 3 and codes[3:] == [429] * 3


def test_reads_need_valid_jwt(env):
    assert env.c.get("/api/me").status_code == 401
    assert env.c.get("/api/me", headers={"authorization": "Bearer junk"}).status_code == 401
    forged = jwt.encode({"sub": "admin", "role": "admin", "vehicles": ["*"], "jti": "a", "exp": time.time() + 99}, "y" * 32, algorithm="HS256")
    assert env.c.get("/api/me", headers={"authorization": "Bearer " + forged}).status_code == 401
    expired = jwt.encode({"sub": "admin", "role": "admin", "vehicles": ["*"], "jti": "a", "exp": time.time() - 5}, SECRET, algorithm="HS256")
    assert env.c.get("/api/me", headers={"authorization": "Bearer " + expired}).status_code == 401
    assert env.c.get("/api/me", headers=env.hdr("admin")).json()["role"] == "admin"


def test_alg_none_token_rejected(env):
    t = jwt.encode({"sub": "admin", "role": "admin", "vehicles": ["*"], "jti": "a", "exp": time.time() + 99}, None, algorithm="none")
    assert env.c.get("/api/me", headers={"authorization": "Bearer " + t}).status_code == 401


# ---------- request signing + replay ----------
def test_unsigned_write_rejected(env):
    r = env.c.post("/api/feedback", json={}, headers=env.hdr("tech"))
    assert r.status_code == 401 and "signature" in r.json()["error"]


def test_bad_signature_stale_and_replay_rejected(env):
    env.feed("cloud.escalations", esc("V1", "V1-1"))
    body = {"incident_id": "V1-1", "confirmed_cause": "pump_fault"}
    assert env.post("tech", "/api/feedback", body, sig="0" * 64).status_code == 401
    assert env.post("tech", "/api/feedback", body, ts=int(time.time()) - 600).status_code == 401
    n = uuid.uuid4().hex
    assert env.post("tech", "/api/feedback", body, nonce=n).status_code == 200
    r = env.post("tech", "/api/feedback", body, nonce=n)
    assert r.status_code == 401 and "replayed" in r.json()["error"]


def test_signature_binds_body_and_path(env):
    env.feed("cloud.escalations", esc("V1", "V1-1"))
    raw = json.dumps({"incident_id": "V1-1", "confirmed_cause": "a"}).encode()
    ts, n = int(time.time()), "n1"
    s = env.sess["tech"]; jti = jwt.decode(s["token"], SECRET, algorithms=["HS256"])["jti"]
    sig = hmac.new(s["session_key"].encode(), Auth.signing_string("POST", "/api/feedback", ts, n, raw).encode(), hashlib.sha256).hexdigest()
    tampered = json.dumps({"incident_id": "V1-1", "confirmed_cause": "b"}).encode()
    r = env.c.post("/api/feedback", content=tampered, headers={**env.hdr("tech"), "x-timestamp": str(ts), "x-nonce": n, "x-signature": sig})
    assert r.status_code == 401


def test_signature_from_other_session_rejected(env):
    env.feed("cloud.escalations", esc("V1", "V1-1"))
    other = env.login("admin")                               # second session for another user
    sig_key = other["session_key"]
    raw = json.dumps({"incident_id": "V1-1", "confirmed_cause": "x"}).encode(); ts, n = int(time.time()), "n2"
    sig = hmac.new(sig_key.encode(), Auth.signing_string("POST", "/api/feedback", ts, n, raw).encode(), hashlib.sha256).hexdigest()
    r = env.c.post("/api/feedback", content=raw, headers={**env.hdr("tech"), "x-timestamp": str(ts), "x-nonce": n, "x-signature": sig})
    assert r.status_code == 401


# ---------- roles and vehicle scope ----------
def test_role_enforced(env):
    env.feed("cloud.escalations", esc("V1", "V1-1"))
    assert env.post("viewer", "/api/feedback", {"incident_id": "V1-1", "confirmed_cause": "x"}).status_code == 403
    assert env.post("owner1", "/api/inject", {"scenario": "clear"}).status_code == 403
    assert env.post("oem", "/api/rulebook/approve", {"event_id": 1}).status_code == 403
    assert env.c.get("/api/audit", headers=env.hdr("tech")).status_code == 403


def test_vehicle_scope_filters_reads(env):
    env.feed("cloud.escalations", esc("V1", "V1-1")); env.feed("cloud.escalations", esc("V2", "V2-1"))
    ids = lambda u: {i["id"] for i in env.c.get("/api/incidents", headers=env.hdr(u)).json()}
    assert ids("viewer") == {"V1-1"} and ids("admin") == {"V1-1", "V2-1"}
    ev = env.c.get("/api/events", headers=env.hdr("viewer")).json()
    assert all(x["vehicle_id"] in ("V1", None) for x in ev)


def test_owner_cannot_consent_for_other_vehicle(env):
    env.feed("notify.out", {"kind": "notice", "vehicle_id": "V2", "request_id": "req-V2-1", "text": "eco?", "channel": "driver"})
    r = env.post("owner1", "/api/consent", {"request_id": "req-V2-1", "decision": "approved"})
    assert r.status_code == 403
    assert not [m for _, m in env.bus.log.get(config.topic("cloud.ota"), [])]
    assert env.post("owner2", "/api/consent", {"request_id": "req-V2-1", "decision": "approved"}).status_code == 200


def test_unknown_incident_404(env):
    assert env.post("tech", "/api/feedback", {"incident_id": "nope", "confirmed_cause": "x"}).status_code == 404


# ---------- actions reach the bus, audited first ----------
def test_feedback_consent_oem_rulebook_flow(env):
    env.feed("cloud.escalations", esc("V1", "V1-1"))
    env.feed("notify.out", {"kind": "notice", "vehicle_id": "V1", "request_id": "req-V1-1", "text": "eco?"})
    env.feed("cloud.ota", {"kind": "rulebook_proposal", "cause": "cell_heating", "cases": 3, "rationale": "r", "status": "pending_approval",
                           "rulebook": {"version": 2, "limits": {}, "rules": []}})
    assert env.post("tech", "/api/feedback", {"incident_id": "V1-1", "confirmed_cause": "cell_heating"}).status_code == 200
    assert [p["request_id"] for p in env.c.get("/api/pending", headers=env.hdr("owner1")).json()] == ["req-V1-1"]
    assert env.post("owner1", "/api/consent", {"request_id": "req-V1-1", "decision": "approved"}).status_code == 200
    env.sink.pump()
    assert env.c.get("/api/pending", headers=env.hdr("owner1")).json() == []              # decided
    assert env.post("oem", "/api/oem/approve", {"request_id": "r", "approved": True}).status_code == 200
    pid = env.c.get("/api/proposals", headers=env.hdr("admin")).json()[0]["event_id"]
    assert env.post("admin", "/api/rulebook/approve", {"event_id": pid}).status_code == 200
    kinds = [m["kind"] for _, m in env.bus.log[config.topic("cloud.ota")] if m.get("by")]
    assert kinds == ["feedback", "consent_decision", "oem_approval", "rulebook_approve"]
    acts = [a["action"] for a in env.app.state.audit.entries()]
    assert {"feedback", "consent", "oem_approval", "rulebook_approve"} <= set(acts)
    assert env.bus.log[config.topic("cloud.ota")][-1][1]["rulebook"]["version"] == 2


def test_inject_whitelist_scope_and_sandbox(env):
    assert env.post("tech", "/api/inject", {"scenario": "rm -rf"}).status_code == 400
    assert env.post("tech", "/api/inject", {"scenario": "breakdown", "vehicles": ["V1"]}).status_code == 200
    assert env.bus.log[config.topic("control.inject")][0][1] == {"scenario": "breakdown", "vehicles": ["V1"]}
    prod = Env(sandbox=False); prod.login("tech")
    assert prod.post("tech", "/api/inject", {"scenario": "breakdown"}).status_code == 403


def test_write_rate_limit():
    e = Env(write_rate=(0.0001, 2)); e.login("tech"); e.feed("cloud.escalations", esc("V1", "V1-1"))
    codes = [e.post("tech", "/api/feedback", {"incident_id": "V1-1", "confirmed_cause": "x"}).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


# ---------- audit chain ----------
def test_audit_chain_verifies_and_detects_tamper():
    s = Store(); a = AuditLog(s)
    for i in range(5): a.append("u", "act", {"i": i})
    assert a.verify() == {"ok": True, "entries": 5, "head": a.verify()["head"]}
    with pytest.raises(Exception, match="append-only"): s.exec("UPDATE audit SET actor='evil' WHERE seq=2")
    with pytest.raises(Exception, match="append-only"): s.exec("DELETE FROM audit WHERE seq=3")
    s.exec("DROP TRIGGER audit_no_update")                                   # attacker with DB superuser
    s.exec("UPDATE audit SET detail='{}' WHERE seq=3")
    assert a.verify()["ok"] is False and a.verify()["broken_at"] == 3


def test_audit_detects_deleted_and_reordered_entries():
    s = Store(); a = AuditLog(s)
    for i in range(4): a.append("u", "act", {"i": i})
    s.exec("DROP TRIGGER audit_no_delete"); s.exec("DELETE FROM audit WHERE seq=2")
    assert a.verify()["ok"] is False


def test_audit_endpoint_admin_only_and_mirrors_to_topic(env):
    env.post("tech", "/api/inject", {"scenario": "clear"})
    assert env.c.get("/api/audit/verify", headers=env.hdr("admin")).json()["ok"] is True
    assert any(m["action"] == "inject" for _, m in env.bus.log[config.topic("audit")])


# ---------- sink ----------
def test_sink_survives_garbage_and_keeps_latest_vss():
    e = Env()
    e.bus.publish(config.topic("cloud.rca"), {"_undecodable": True})
    e.bus.publish(config.topic("cloud.rca"), "not-a-dict")
    e.bus.publish(config.topic("vss.enriched"), {"vehicle_id": "V1", "ts": 1, "vss": {"a": 1}})
    e.bus.publish(config.topic("vss.enriched"), {"vehicle_id": "V1", "ts": 2, "vss": {"a": 2}})
    e.feed("cloud.fleet", {"kind": "feeds", "ts": 5, "edge_counters": {"edge_resolved": 9, "escalated": 1, "resolved_ratio": 0.9}})
    assert e.sink.bad == 2 and e.store.get_latest("vss:V1")["vss"]["a"] == 2
    e.login("viewer")
    assert e.c.get("/api/metrics", headers=e.hdr("viewer")).json()["edge"]["resolved_ratio"] == 0.9


def test_redis_hot_cache_used_when_configured():
    class R(dict):
        def set(self, k, v, ex=None): self[k] = v
        def get(self, k): return super().get(k)
    r = R(); s = Store(redis=r); s.set_latest("feeds", {"x": 1})
    assert s.get_latest("feeds") == {"x": 1} and "quantara:feeds" in r


# ---------- websocket ----------
def test_websocket_streams_only_scoped_events(env):
    with env.c.websocket_connect("/ws") as ws:
        ws.send_json({"token": env.sess["viewer"]["token"]})
        time.sleep(0.2)
        env.feed("cloud.escalations", esc("V2", "V2-1"))
        env.feed("cloud.escalations", esc("V1", "V1-1"))
        m = ws.receive_json()
        assert m["vehicle_id"] == "V1" and m["payload"]["incident"]["id"] == "V1-1"


def test_websocket_rejects_bad_token(env):
    with env.c.websocket_connect("/ws") as ws:
        ws.send_json({"token": "bad"})
        with pytest.raises(Exception): ws.receive_json()


# ---------- misc ----------
def test_rate_limiter_refills():
    t = [0.0]; r = RateLimiter(1, 2, clock=lambda: t[0])
    assert [r.allow("k") for _ in range(3)] == [True, True, False]
    t[0] += 1.5; assert r.allow("k") and not r.allow("k")


def test_weak_secret_refused():
    with pytest.raises(ValueError): Auth("short", {})


def test_ui_served_and_no_docs(env):
    assert "Quantara" in env.c.get("/").text and env.c.get("/docs").status_code == 404
