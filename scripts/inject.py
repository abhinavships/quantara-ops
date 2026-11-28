#!/usr/bin/env python3
"""Publish a sandbox fault scenario straight to Kafka (topic control.inject). No UI, no gateway.
Usage: python scripts/inject.py breakdown V000 V001      (vehicles optional = whole fleet)
       python scripts/inject.py --list
Needs KAFKA_* and TOPIC_PREFIX in ./.env (gitignored) or the environment. Refuses unless SANDBOX=1."""
import os
import pathlib
import sys

SCENARIOS = ("breakdown", "grid_outage", "degradation", "cyber_flood", "cyber_fuzz", "cyber_spoof", "cyber_replay",
             "cal_tamper", "telemetry_mismatch", "pump_recover", "clear", "link_down", "link_up")


def load_env(path):
    if path.exists():
        for ln in path.read_text().splitlines():
            if "=" in ln and not ln.lstrip().startswith("#"):
                k, v = ln.split("=", 1); os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def inject(bus, scenario, vehicles=None):
    from quantara_core import config
    if os.environ.get("SANDBOX") != "1": raise SystemExit("refusing: SANDBOX=1 required")
    if scenario not in SCENARIOS: raise SystemExit(f"unknown scenario {scenario!r}; one of: {', '.join(SCENARIOS)}")
    bus.publish(config.topic("control.inject"), {"scenario": scenario, "vehicles": vehicles or None})
    bus.flush()


if __name__ == "__main__":
    load_env(pathlib.Path(__file__).resolve().parent.parent / ".env")
    os.environ.setdefault("TOPIC_PREFIX", "quantara_"); os.environ.setdefault("SANDBOX", "1")
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help", "--list"): print(__doc__); print("scenarios:", ", ".join(SCENARIOS)); sys.exit(0)
    from quantara_core.bus import get_bus
    inject(get_bus(), a[0], a[1:])
    print("injected", a[0], a[1:] or "(whole fleet)")
