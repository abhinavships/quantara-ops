"""Gateway: the only way humans touch the platform. Every write is authenticated (JWT), signed (per-session HMAC),
replay-protected (nonce), rate limited, role- and vehicle-scoped, and audited BEFORE it is published."""
import asyncio
import json
import os
import pathlib
import time

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from quantara_core import config

from .audit import AuditLog
from .auth import Auth, AuthError, RateLimiter

SCENARIOS = ("breakdown", "grid_outage", "degradation", "cyber_flood", "cyber_fuzz", "cyber_spoof", "cyber_replay",
             "cal_tamper", "telemetry_mismatch", "pump_recover", "clear", "link_down", "link_up")
UI = pathlib.Path(__file__).resolve().parent.parent / "ui" / "index.html"


def create_app(store, bus, auth: Auth, sandbox=None, clock=time.time, read_rate=(20, 40), write_rate=(2, 6), login_rate=(0.2, 5)):
    app = FastAPI(title="Quantara ops gateway", docs_url=None, redoc_url=None, openapi_url=None)
    audit = AuditLog(store, publish=lambda e: bus.publish(config.topic("audit"), e, key="audit"))
    rl_r, rl_w, rl_l = RateLimiter(*read_rate), RateLimiter(*write_rate), RateLimiter(*login_rate)
    sandbox = (os.environ.get("SANDBOX") == "1") if sandbox is None else sandbox
    app.state.audit, app.state.store, app.state.auth = audit, store, auth

    @app.exception_handler(AuthError)
    async def _auth_err(_, e): return JSONResponse({"error": e.why}, status_code=e.status)

    async def guard(request: Request, perm: str, write=False):
        h = request.headers.get("authorization", "")
        if not h.startswith("Bearer "): raise AuthError(401, "missing bearer token")
        c = auth.claims(h[7:])
        if not (rl_w if write else rl_r).allow(c["sub"]): raise AuthError(429, "rate limited")
        if write:
            auth.verify_signed(c, request.method, request.url.path, request.headers.get("x-timestamp"),
                               request.headers.get("x-nonce"), request.headers.get("x-signature"), await request.body())
        auth.require(c, perm)
        return c

    def pub(topic, msg, key=None): bus.publish(config.topic(topic), msg, key=key)

    def scoped(c): return c["vehicles"]

    # ---------------- public ----------------
    @app.get("/healthz")
    async def healthz(): return {"ok": True, "audit": audit.verify()["ok"]}

    @app.get("/")
    async def ui(): return FileResponse(UI)

    @app.post("/login")
    async def login(request: Request):
        b = await request.json()
        user = str(b.get("username", ""))[:64]
        if not rl_l.allow(f"{request.client.host if request.client else '?'}|{user}"):
            audit.append(user or "?", "login_rate_limited", {}); raise AuthError(429, "too many attempts")
        try:
            r = auth.login(user, str(b.get("password", "")))
        except AuthError:
            audit.append(user or "?", "login_failed", {}); raise
        audit.append(user, "login", {"role": r["role"]})
        return r

    # ---------------- reads ----------------
    @app.get("/api/me")
    async def me(request: Request):
        c = await guard(request, "read"); return {"user": c["sub"], "role": c["role"], "vehicles": c["vehicles"], "sandbox": sandbox}

    @app.get("/api/incidents")
    async def incidents(request: Request):
        c = await guard(request, "read")
        esc = store.events(["cloud.escalations", "cloud.security"], vehicles=scoped(c), limit=100)
        by = {}
        for e in store.events(["cloud.rca", "cloud.twin", "cloud.route"], vehicles=scoped(c), limit=400):
            by.setdefault(e["payload"].get("incident_id"), {})[e["topic"].split(".")[1]] = e["payload"]
        out = []
        for e in esc:
            p, inc = e["payload"], e["payload"].get("incident", {})
            x = by.get(inc.get("id"), {})
            out.append({"event_id": e["id"], "id": inc.get("id"), "vehicle_id": p.get("vehicle_id"), "ts": p.get("ts"),
                        "security": p.get("kind") == "security", "edge_cause": inc.get("cause"), "reasons": p.get("reasons"),
                        "actions": inc.get("actions"), "rca_top": (x.get("rca") or {}).get("top"),
                        "final_cause": (x.get("twin") or {}).get("final_cause"), "recommended_cap": (x.get("twin") or {}).get("recommended_cap"),
                        "hypotheses": (x.get("rca") or {}).get("hypotheses"), "route": (x.get("route") or {}).get("choice")})
        return out[::-1]

    @app.get("/api/pending")
    async def pending(request: Request):
        c = await guard(request, "read")
        asked = {e["payload"]["request_id"]: e["payload"] for e in store.events(["notify.out"], vehicles=scoped(c), limit=300)
                 if e["payload"].get("request_id")}
        done = {e["payload"].get("request_id") for e in store.events(["cloud.ota"], limit=500)
                if e["payload"].get("kind") == "consent_decision"}
        return [v for k, v in asked.items() if k not in done]

    @app.get("/api/proposals")
    async def proposals(request: Request):
        await guard(request, "read")
        return [{"event_id": e["id"], **{k: e["payload"].get(k) for k in ("cause", "cases", "rationale", "status")},
                 "version": e["payload"]["rulebook"]["version"]}
                for e in store.events(["cloud.ota"], kind="rulebook_proposal", limit=50)]

    @app.get("/api/rollouts")
    async def rollouts(request: Request):
        await guard(request, "read")
        latest = {}
        for e in store.events(["cloud.ota"], kind="rollout_status", limit=200): latest[e["payload"]["id"]] = e["payload"]
        return list(latest.values())

    @app.get("/api/metrics")
    async def metrics(request: Request):
        await guard(request, "read")
        f = store.get_latest("feeds") or {}
        cnt = lambda t: len(store.events([t], limit=10_000))
        return {"edge": f.get("edge_counters"), "incidents": cnt("cloud.escalations") + cnt("cloud.security"),
                "commands": cnt("commands.out"), "dlq": cnt("dlq"), "quarantine": cnt("quarantine"), "ts": f.get("ts")}

    @app.get("/api/events")
    async def events(request: Request, after: int = 0, topic: str = ""):
        c = await guard(request, "read")
        return store.events([topic] if topic else None, after=after, vehicles=scoped(c), limit=200)

    @app.get("/api/audit")
    async def audit_list(request: Request):
        await guard(request, "audit"); return audit.entries(200)

    @app.get("/api/audit/verify")
    async def audit_verify(request: Request):
        await guard(request, "audit"); return audit.verify()

    # ---------------- writes (signed) ----------------
    async def body(request): 
        try: return json.loads((await request.body()) or b"{}")
        except ValueError: raise AuthError(400, "invalid JSON")

    def vehicle_of(event_filter_topic, key, val, c):
        for e in store.events([event_filter_topic], limit=1000):
            p = e["payload"]
            if (p.get("incident", {}).get("id") if key == "incident" else p.get(key)) == val:
                if not auth.sees(c, p.get("vehicle_id")): raise AuthError(403, "vehicle out of scope")
                return p.get("vehicle_id")
        raise AuthError(404, "not found")

    @app.post("/api/feedback")
    async def feedback(request: Request):
        c = await guard(request, "feedback", write=True); b = await body(request)
        vid = vehicle_of("cloud.escalations", "incident", b.get("incident_id"), c)
        cause = str(b.get("confirmed_cause", ""))[:64]
        if not cause: raise AuthError(400, "confirmed_cause required")
        audit.append(c["sub"], "feedback", {"incident_id": b["incident_id"], "cause": cause, "vehicle": vid})
        pub("cloud.ota", {"kind": "feedback", "incident_id": b["incident_id"], "confirmed_cause": cause, "by": c["sub"], "ts": clock()})
        return {"ok": True}

    @app.post("/api/consent")
    async def consent(request: Request):
        c = await guard(request, "consent", write=True); b = await body(request)
        vid = vehicle_of("notify.out", "request_id", b.get("request_id"), c)
        d = "approved" if b.get("decision") == "approved" else "denied"
        audit.append(c["sub"], "consent", {"request_id": b["request_id"], "decision": d, "vehicle": vid})
        pub("cloud.ota", {"kind": "consent_decision", "request_id": b["request_id"], "decision": d, "by": c["sub"], "ts": clock()})
        return {"ok": True, "decision": d}

    @app.post("/api/oem/approve")
    async def oem(request: Request):
        c = await guard(request, "oem", write=True); b = await body(request)
        ok = bool(b.get("approved"))
        audit.append(c["sub"], "oem_approval", {"request_id": b.get("request_id"), "approved": ok})
        pub("cloud.ota", {"kind": "oem_approval", "request_id": b.get("request_id"), "approved": ok, "by": c["sub"], "ts": clock()})
        return {"ok": True}

    @app.post("/api/rulebook/approve")
    async def rb_approve(request: Request):
        c = await guard(request, "rulebook", write=True); b = await body(request)
        e = store.event(b.get("event_id"))
        if not e or e["payload"].get("kind") != "rulebook_proposal": raise AuthError(404, "no such proposal")
        audit.append(c["sub"], "rulebook_approve", {"event_id": e["id"], "version": e["payload"]["rulebook"]["version"]})
        pub("cloud.ota", {"kind": "rulebook_approve", "rulebook": e["payload"]["rulebook"], "vehicles": b.get("vehicles"), "by": c["sub"], "ts": clock()})
        return {"ok": True}

    @app.post("/api/rollout/tick")
    async def rollout_tick(request: Request):
        c = await guard(request, "rollout", write=True); b = await body(request)
        audit.append(c["sub"], "rollout_tick", {"rollout": b.get("rollout")})
        pub("cloud.ota", {"kind": "rollout_tick", "rollout": b.get("rollout"), "by": c["sub"], "ts": clock()})
        return {"ok": True}

    @app.post("/api/inject")
    async def inject(request: Request):
        c = await guard(request, "inject", write=True); b = await body(request)
        if not sandbox: raise AuthError(403, "injection disabled outside SANDBOX=1")
        if b.get("scenario") not in SCENARIOS: raise AuthError(400, "unknown scenario")
        vs = [v for v in (b.get("vehicles") or []) if isinstance(v, str) and auth.sees(c, v)]
        if b.get("vehicles") and not vs: raise AuthError(403, "vehicle out of scope")
        audit.append(c["sub"], "inject", {"scenario": b["scenario"], "vehicles": vs})
        pub("control.inject", {"scenario": b["scenario"], "vehicles": vs or None})
        return {"ok": True}

    # ---------------- websocket ----------------
    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        await sock.accept()
        try:
            c = auth.claims((await asyncio.wait_for(sock.receive_json(), 10)).get("token", ""))
            auth.require(c, "read")
        except (AuthError, asyncio.TimeoutError, ValueError):
            await sock.close(code=4401); return
        cursor = (store.q("SELECT coalesce(max(id),0) AS i FROM events")[0]["i"])
        try:
            while True:
                for e in store.events(None, after=cursor, vehicles=scoped(c), limit=100):
                    cursor = max(cursor, e["id"])
                    await sock.send_json({"id": e["id"], "topic": e["topic"], "vehicle_id": e["vehicle_id"], "payload": e["payload"]})
                await asyncio.sleep(0.3)
        except (WebSocketDisconnect, RuntimeError):
            return

    return app
