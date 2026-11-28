"""Gateway: the only way humans touch the platform. Every write is authenticated (JWT), signed (per-session HMAC),
replay-protected (nonce), rate limited, role- and vehicle-scoped, and audited BEFORE it is published."""
import asyncio
import json
import os
import pathlib
import re
import time

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from quantara_core import config

from .audit import AuditLog
from .auth import Auth, AuthError, RateLimiter

SCENARIOS = ("breakdown", "grid_outage", "degradation", "cyber_flood", "cyber_fuzz", "cyber_spoof", "cyber_replay",
             "cal_tamper", "telemetry_mismatch", "pump_recover", "clear", "link_down", "link_up",
             "contactor_stuck", "dcdc_fail", "bms_comm_lost", "battery_degraded", "obd_dongle", "ecu_busoff", "tcu_intrusion",
             "rogue_charger", "adas_spoof")
PARAM_LIMITS = {"energy_penalty": (0.0, 0.5), "detour_km": (0.0, 500.0), "climb_m": (0.0, 5000.0), "ambient_c": (-40.0, 60.0)}


def clean_params(p):
    """Situation params reach every simulated car, so only known keys are accepted and numbers are clamped to sane ranges."""
    out = {}
    for k, v in p.items():
        if k == "closed_stations":
            if not isinstance(v, list): raise AuthError(400, "closed_stations must be a list")
            out[k] = [str(x)[:32] for x in v[:20]]
        elif k in PARAM_LIMITS:
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v: raise AuthError(400, f"{k} must be a number")
            lo, hi = PARAM_LIMITS[k]; out[k] = min(hi, max(lo, float(v)))
        else: raise AuthError(400, f"unknown param {k}")
    return out


UI = pathlib.Path(__file__).resolve().parent.parent / "ui" / "index.html"


class PrefixStrip:
    """Condense serves the app under /<uuid>/; strip that segment so routes and request signatures are prefix-free."""
    _re = re.compile(r"^/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)")

    def __init__(self, app): self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            m = self._re.match(scope["path"])
            if m:
                scope = {**scope, "path": scope["path"][m.end():] or "/"}
                if scope.get("raw_path"): scope["raw_path"] = scope["path"].encode()
        await self.app(scope, receive, send)


def create_app(store, bus, auth: Auth, sandbox=None, clock=time.time, read_rate=(20, 40), write_rate=(2, 6), login_rate=(0.2, 5)):
    app = FastAPI(title="Quantara ops gateway", docs_url=None, redoc_url=None, openapi_url=None)
    audit = AuditLog(store, publish=lambda e: bus.publish(config.topic("audit"), e, key="audit"))
    rl_r, rl_w, rl_l = RateLimiter(*read_rate), RateLimiter(*write_rate), RateLimiter(*login_rate)
    sandbox = (os.environ.get("SANDBOX") == "1") if sandbox is None else sandbox
    app.state.audit, app.state.store, app.state.auth = audit, store, auth
    app.add_middleware(PrefixStrip)

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

    @app.get("/api/history")
    async def history(request: Request, vehicle: str, signals: str = "", minutes: int = 30):
        """Time series for one vehicle: ?vehicle=V000&signals=Vehicle.Speed,Vehicle.Acceleration.Vertical&minutes=30"""
        c = await guard(request, "read")
        if "*" not in scoped(c) and vehicle not in scoped(c): raise AuthError(403, "vehicle not in scope")
        names = {x for x in signals.split(",") if x} or None
        return {"vehicle": vehicle, "series": store.history(vehicle, names, clock() - max(1, min(minutes, 1440)) * 60)}

    @app.get("/api/signals")
    async def signal_names(request: Request):
        """VSS signal names currently reported, per the latest sample of any in-scope vehicle."""
        c = await guard(request, "read")
        rows = store.q("SELECT k FROM latest WHERE k LIKE ?", ("vss:%",))
        vs = [r["k"][4:] for r in rows if "*" in scoped(c) or r["k"][4:] in scoped(c)]
        names = sorted({k for v in vs for k in ((store.get_latest(f"vss:{v}") or {}).get("vss") or {})})
        return {"vehicles": sorted(vs), "signals": names}

    @app.get("/api/overview")
    async def overview(request: Request):
        """Aggregates for the dashboard (same panels as grafana/dashboard.json). Scoped to the caller's vehicles."""
        c = await guard(request, "read")
        ev = lambda t, **k: store.events(t, vehicles=scoped(c), limit=5000, **k)
        hist = lambda xs: dict(sorted(((str(k), xs.count(k)) for k in set(xs)), key=lambda kv: -kv[1]))
        esc = ev(["cloud.escalations", "cloud.security"])
        twin = ev(["cloud.twin"])
        latest = {}
        for e in ev(["cloud.ota"], kind="rollout_status"): latest[e["payload"]["id"]] = e["payload"]
        now = clock(); buckets = [0] * 30                       # incidents per minute, last 30 min
        for e in esc:
            age = int((now - (e["ts"] or 0)) // 60)
            if 0 <= age < 30: buckets[29 - age] += 1
        feeds = store.get_latest("feeds") or {}
        return {"edge": feeds.get("edge_counters"), "ts": feeds.get("ts"), "incidents": len(esc),
                "security": sum(1 for e in esc if e["topic"] == "cloud.security"),
                "by_cause": hist([(e["payload"].get("incident") or {}).get("cause") or "unknown" for e in esc]),
                "by_reason": hist([r for e in esc for r in (e["payload"].get("reasons") or [])]),
                "by_verdict": hist([e["payload"].get("final_cause") or "unknown" for e in twin]),
                "commands": len(ev(["commands.out"])), "dlq": len(ev(["dlq"])), "quarantine": len(ev(["quarantine"])),
                "rollouts": {"applied": sum(r.get("applied", 0) for r in latest.values()),
                             "failed": sum(r.get("failed", 0) for r in latest.values()), "count": len(latest)},
                "per_minute": buckets, "vehicles_live": len(store.q("SELECT k FROM latest WHERE k LIKE ?", ("vss:%",)))}

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

    @app.post("/api/situation")
    async def situation(request: Request):
        """Free-text world event for the cloud model to plan: {"text": "...", "params": {"energy_penalty": 0.15, ...}}."""
        c = await guard(request, "inject", write=True); b = await body(request)
        if not sandbox: raise AuthError(403, "injection disabled outside SANDBOX=1")
        text = str(b.get("text", "")).strip()[:600]
        if len(text) < 5: raise AuthError(400, "text required")
        params = clean_params(b["params"]) if isinstance(b.get("params"), dict) else {}
        sid = f"sit-{int(clock())}"
        audit.append(c["sub"], "situation", {"id": sid, "text": text})
        pub("control.inject", {"scenario": "situation", "id": sid, "text": text, "params": params, "ts": clock()})
        return {"ok": True, "id": sid}

    @app.get("/api/plans")
    async def plans(request: Request):
        """Cloud-model plans for situations (newest last): summary, risk, validated actions, source llm|fallback."""
        await guard(request, "read")
        return [{"event_id": e["id"], **e["payload"]} for e in store.events(["cloud.fleet"], kind="plan", limit=30)]

    @app.get("/api/notifications")
    async def notifications(request: Request):
        c = await guard(request, "read")
        return [e["payload"] for e in store.events(["notify.out"], kind="notification", vehicles=scoped(c), limit=100)]

    @app.post("/api/replay/save")
    async def replay_save(request: Request):
        """The 'store last 30 min' button: freeze a vehicle's last 30 min of signals + its incidents as a replayable scene."""
        c = await guard(request, "replay", write=True); b = await body(request)
        vid = str(b.get("vehicle", ""))
        if not vid or not auth.sees(c, vid): raise AuthError(403, "vehicle not in scope")
        now = clock()
        series = store.history(vid, None, now - 1800)
        if not series: raise AuthError(404, "no recent data for that vehicle")
        inc = [{"ts": e["ts"], "topic": e["topic"], "payload": e["payload"]}
               for e in store.events(["cloud.escalations", "cloud.security", "cloud.twin", "cloud.rca"], vehicles=[vid], limit=200)
               if (e["ts"] or 0) >= now - 1800]
        audit.append(c["sub"], "replay_save", {"vehicle": vid})
        eid = store.add_event("replay", {"kind": "replay", "vehicle_id": vid, "ts": now, "note": str(b.get("note", ""))[:200],
                                         "from": now - 1800, "to": now, "series": series, "events": inc})
        return {"ok": True, "replay_id": eid}

    @app.get("/api/replays")
    async def replays(request: Request):
        c = await guard(request, "read")
        return [{"replay_id": e["id"], "vehicle_id": e["vehicle_id"], "ts": e["ts"], "note": e["payload"].get("note"),
                 "signals": len(e["payload"].get("series", {})), "events": len(e["payload"].get("events", []))}
                for e in store.events(["replay"], vehicles=scoped(c), limit=50)]

    @app.get("/api/replays/{replay_id}")
    async def replay_get(request: Request, replay_id: int):
        """Full scene; the UI plays it back (4 min of wall clock for 30 min of data is a UI speed-up of 7.5x)."""
        c = await guard(request, "read")
        e = store.event(replay_id)
        if not e or e["topic"] != "replay" or not auth.sees(c, e["vehicle_id"]): raise AuthError(404, "not found")
        return {"replay_id": e["id"], **e["payload"]}

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
