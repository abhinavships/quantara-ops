"""Cron job: run the synthetic ingest simulator and write its VSS history + latest state into a Postgres DB.
Usage: DATABASE_URL=... INGEST_PATH=../quantara-ingest STREAM_PATH=../quantara-stream python scripts/sim_to_db.py
Each run back-fills from the newest stored row (max 1 h) to now at 1 Hz, stores one row per vehicle per 5 s.
Synthetic data only (sim=True vehicles)."""
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, ".."), os.path.abspath(os.environ.get("INGEST_PATH", os.path.join(here, "../../quantara-ingest"))),
                os.path.abspath(os.environ.get("STREAM_PATH", os.path.join(here, "../../quantara-stream")))]
from ops.store import Store
from sim.vehicle import Vehicle
from stream.enrich import VSS

N, EVERY = int(os.environ.get("FLEET", "10")), 5

def main():
    s = Store(os.environ["DATABASE_URL"])
    now = time.time()
    last = s.q("SELECT max(ts) AS m FROM telemetry")[0]["m"] or 0
    start = max(last + EVERY, now - 3600)
    rows, latest = [], {}
    for i in range(N):
        vid = f"SIM-{i:03d}"
        v = Vehicle(vid, seed=int(start) + i, lat=12.97 + i * 0.01, lon=77.59 + i * 0.01)
        v.demand = 0.3 + 0.07 * (i % 6)
        t = min(start, now - EVERY)                       # always simulate >=1 step so latest refreshes
        while t <= now:
            sig = v.step(1.0)
            vss = {VSS[k]: x for k, x in sig.items() if k in VSS}
            if t >= start and int(t - start) % EVERY == 0: rows.append((t, vid, json.dumps(vss)))
            t += 1.0
        latest[vid] = {"kind": "vss", "vehicle_id": vid, "ts": now, "vss": vss}
    if rows:
      with s.lock, s.c.cursor() as cur:
        cur.executemany("INSERT INTO telemetry(ts,vehicle_id,vss) VALUES(%s,%s,%s)", rows)
    for vid, m in latest.items(): s.set_latest(f"vss:{vid}", m)
    s.exec("DELETE FROM telemetry WHERE ts<?", (now - 24 * 3600,))
    print(f"{time.strftime('%F %T')} wrote {len(rows)} rows for {N} vehicles")

if __name__ == "__main__": main()
