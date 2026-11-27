"""Hash-chained, append-only audit log. hash = sha256(prev | canonical(entry)). Any edit, deletion or reorder
breaks verify(). The DB also rejects UPDATE/DELETE; the chain detects tampering done with direct DB access."""
import hashlib
import json
import threading
import time

GENESIS = "0" * 64


def _h(prev, e): return hashlib.sha256((prev + json.dumps(e, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class AuditLog:
    def __init__(self, store, publish=None):
        self.s, self.publish, self.lock = store, publish, threading.Lock()

    def append(self, actor, action, detail=None):
        with self.lock:
            last = self.s.q("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1")
            seq, prev = (last[0]["seq"] + 1, last[0]["hash"]) if last else (1, GENESIS)
            e = {"seq": seq, "ts": round(time.time(), 3), "actor": actor, "action": action,
                 "detail": json.dumps(detail or {}, sort_keys=True)}
            e["prev"], e["hash"] = prev, _h(prev, e)
            self.s.exec("INSERT INTO audit VALUES(?,?,?,?,?,?,?)", (e["seq"], e["ts"], actor, action, e["detail"], prev, e["hash"]))
        if self.publish:
            try: self.publish(e)
            except Exception: pass                     # the DB is the record; the topic is a mirror
        return e

    def entries(self, limit=100): return list(reversed(self.s.q("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))))

    def verify(self):
        prev, n = GENESIS, 0
        for r in self.s.q("SELECT * FROM audit ORDER BY seq"):
            n += 1
            e = {k: r[k] for k in ("seq", "ts", "actor", "action", "detail")}
            if r["seq"] != n or r["prev"] != prev or r["hash"] != _h(prev, e):
                return {"ok": False, "broken_at": r["seq"], "entries": n}
            prev = r["hash"]
        return {"ok": True, "entries": n, "head": prev}
