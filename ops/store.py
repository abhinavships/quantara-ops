"""Persistence. SQLite by default (single-pod demo); Postgres when DATABASE_URL is set; optional Redis hot cache.
Audit table is append-only: DB triggers reject UPDATE/DELETE."""
import json
import sqlite3
import threading
import time

SQLITE = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, topic TEXT, kind TEXT, vehicle_id TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS ev_v ON events(vehicle_id, id);
CREATE TABLE IF NOT EXISTS latest(k TEXT PRIMARY KEY, ts REAL, payload TEXT);
CREATE TABLE IF NOT EXISTS telemetry(ts REAL, vehicle_id TEXT, vss TEXT);
CREATE INDEX IF NOT EXISTS tel_v ON telemetry(vehicle_id, ts);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, detail TEXT, prev TEXT, hash TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
"""
PG = """
CREATE TABLE IF NOT EXISTS events(id BIGSERIAL PRIMARY KEY, ts DOUBLE PRECISION, topic TEXT, kind TEXT, vehicle_id TEXT, payload JSONB);
CREATE INDEX IF NOT EXISTS ev_v ON events(vehicle_id, id);
CREATE TABLE IF NOT EXISTS latest(k TEXT PRIMARY KEY, ts DOUBLE PRECISION, payload JSONB);
CREATE TABLE IF NOT EXISTS telemetry(ts DOUBLE PRECISION, vehicle_id TEXT, vss JSONB);
CREATE INDEX IF NOT EXISTS tel_v ON telemetry(vehicle_id, ts);
CREATE TABLE IF NOT EXISTS audit(seq BIGINT PRIMARY KEY, ts DOUBLE PRECISION, actor TEXT, action TEXT, detail TEXT, prev TEXT, hash TEXT);
CREATE OR REPLACE FUNCTION audit_guard() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit is append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_ro ON audit;
CREATE TRIGGER audit_ro BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_guard();
"""


class Store:
    def __init__(self, dsn=None, redis=None):
        self.lock, self.redis, self.pg = threading.RLock(), redis, bool(dsn and dsn.startswith("postgres"))
        self._last_hist, self._hist_n = {}, 0
        if self.pg:
            import psycopg
            self.c = psycopg.connect(dsn, autocommit=True)
            with self.lock:
                self.c.execute("SELECT pg_advisory_lock(727001)")      # pods starting together must not race the DDL
                try:
                    for stmt in PG.split(";\n"):
                        if stmt.strip(): self.c.execute(stmt)
                finally:
                    self.c.execute("SELECT pg_advisory_unlock(727001)")
        else:
            self.c = sqlite3.connect(dsn or ":memory:", check_same_thread=False, isolation_level=None)
            self.c.row_factory = sqlite3.Row
            self.c.executescript(SQLITE)

    def _sql(self, s): return s.replace("?", "%s") if self.pg else s

    def exec(self, sql, p=()):
        with self.lock:
            cur = self.c.execute(self._sql(sql), p)
            return cur

    def q(self, sql, p=()):
        with self.lock:
            cur = self.c.execute(self._sql(sql), p)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _j(self, r):
        p = r["payload"]; r = dict(r)
        r["payload"] = p if isinstance(p, dict) else json.loads(p)
        return r

    # ----- events -----
    def add_event(self, topic, msg):
        vid = msg.get("vehicle_id") if isinstance(msg, dict) else None
        kind = msg.get("kind") if isinstance(msg, dict) else None
        ts = msg.get("ts") if isinstance(msg, dict) and isinstance(msg.get("ts"), (int, float)) else time.time()
        if topic == "vss.enriched":                       # high-rate: latest per vehicle + a downsampled history
            self.set_latest(f"vss:{vid}", msg); self._hist(vid, ts if abs(ts - time.time()) < 86400 else time.time(), msg.get("vss")); return None
        self.exec("INSERT INTO events(ts,topic,kind,vehicle_id,payload) VALUES(?,?,?,?,?)",
                  (ts, topic, kind, vid, json.dumps(msg)))
        if kind == "feeds" or (topic == "cloud.fleet" and kind == "feeds"): self.set_latest("feeds", msg)
        return self.q("SELECT max(id) AS i FROM events")[0]["i"]

    HIST_EVERY_S, HIST_KEEP_S = 5.0, 24 * 3600      # one row per vehicle per 5 s, kept 24 h

    def _hist(self, vid, ts, vss):
        if not vid or not isinstance(vss, dict) or not vss: return
        if ts - self._last_hist.get(vid, 0) < self.HIST_EVERY_S: return
        self._last_hist[vid] = ts; self._hist_n += 1
        self.exec("INSERT INTO telemetry(ts,vehicle_id,vss) VALUES(?,?,?)", (ts, vid, json.dumps(vss)))
        if self._hist_n % 2000 == 0: self.exec("DELETE FROM telemetry WHERE ts<?", (time.time() - self.HIST_KEEP_S,))

    def history(self, vehicle, names=None, since=0.0, limit=5000):
        """{signal: [[ts, value], ...]} oldest first for one vehicle."""
        rows = self.q("SELECT ts, vss FROM telemetry WHERE vehicle_id=? AND ts>? ORDER BY ts DESC LIMIT ?", (vehicle, since, limit))
        out = {}
        for r in reversed(rows):
            v = r["vss"] if isinstance(r["vss"], dict) else json.loads(r["vss"])
            for k, x in v.items():
                if names is None or k in names: out.setdefault(k, []).append([r["ts"], x])
        return out

    def events(self, topics=None, after=0, vehicles=None, limit=200, kind=None):
        sql, p = "SELECT * FROM events WHERE id>?", [after]
        if topics: sql += " AND topic IN (%s)" % ",".join("?" * len(topics)); p += list(topics)
        if kind: sql += " AND kind=?"; p.append(kind)
        if vehicles is not None and "*" not in vehicles:
            if not vehicles: return []
            sql += " AND (vehicle_id IN (%s) OR vehicle_id IS NULL)" % ",".join("?" * len(vehicles)); p += list(vehicles)
        sql += " ORDER BY id DESC LIMIT ?"; p.append(limit)
        return [self._j(r) for r in reversed(self.q(sql, p))]

    def event(self, eid): 
        r = self.q("SELECT * FROM events WHERE id=?", (eid,))
        return self._j(r[0]) if r else None

    # ----- hot state (Redis if configured, else table) -----
    def set_latest(self, k, msg):
        if self.redis is not None: self.redis.set(f"quantara:{k}", json.dumps(msg), ex=3600)
        if self.pg: self.exec("INSERT INTO latest VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET ts=excluded.ts,payload=excluded.payload", (k, time.time(), json.dumps(msg)))
        else: self.exec("INSERT OR REPLACE INTO latest VALUES(?,?,?)", (k, time.time(), json.dumps(msg)))

    def get_latest(self, k):
        if self.redis is not None:
            v = self.redis.get(f"quantara:{k}")
            if v: return json.loads(v)
        r = self.q("SELECT payload FROM latest WHERE k=?", (k,))
        if not r: return None
        p = r[0]["payload"]; return p if isinstance(p, dict) else json.loads(p)
