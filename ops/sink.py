"""Sink: consumes platform topics and persists them (Postgres/SQLite; Redis hot state). Bad messages never crash it."""
import logging
import time

from quantara_core import config

log = logging.getLogger("sink")
TOPICS = ["cloud.escalations", "cloud.security", "cloud.rca", "cloud.twin", "cloud.route", "cloud.ota", "cloud.fleet",
          "notify.out", "commands.out", "quarantine", "dlq", "vss.enriched"]


class Sink:
    def __init__(self, store, bus, group="ops-sink"):
        self.s, self.bus, self.group, self.n, self.bad = store, bus, config.group(group), 0, 0

    def pump(self, max_n=500, timeout=0.2):
        got = 0
        for t, _, m in self.bus.poll(self.group, [config.topic(x) for x in TOPICS], max_n=max_n, timeout=timeout):
            short = t[len(config.topic("")):]
            try:
                if not isinstance(m, dict) or m.get("_undecodable"): raise ValueError("undecodable")
                self.s.add_event(short, m); self.n += 1; got += 1
            except Exception as e:
                self.bad += 1; log.warning("skipped message on %s: %s", short, e)
        return got

    def run(self):
        while True:
            try:
                if not self.pump(): time.sleep(0.1)
            except Exception:
                log.exception("sink loop error (continuing)"); time.sleep(1)
