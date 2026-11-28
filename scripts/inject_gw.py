#!/usr/bin/env python3
"""Inject a sandbox scenario through the ops gateway (login + signed POST). No Kafka credentials needed.
Usage: OPS_URL=https://.../<ingress> OPS_USER=admin OPS_PASS=... python scripts/inject_gw.py breakdown V000 V001
Free-text situation for the cloud model:  python scripts/inject_gw.py situation "highway closed, +60 km, +800 m climb" '{"energy_penalty":0.15}'
Scenarios: breakdown grid_outage degradation cyber_flood cyber_fuzz cyber_spoof cyber_replay cal_tamper clear ..."""
import hashlib, hmac, json, os, sys, time, urllib.request, uuid

url, a = os.environ["OPS_URL"].rstrip("/"), sys.argv[1:]
if not a: sys.exit(__doc__)


def call(path, body, h=None):
    r = urllib.request.Request(url + path, json.dumps(body).encode(), {"content-type": "application/json", **(h or {})})
    return json.load(urllib.request.urlopen(r, timeout=30))


s = call("/login", {"username": os.environ["OPS_USER"], "password": os.environ["OPS_PASS"]})
sit = a[0] == "situation"
path = "/api/situation" if sit else "/api/inject"
body = json.dumps({"text": a[1], "params": json.loads(a[2]) if len(a) > 2 else {}} if sit else {"scenario": a[0], "vehicles": a[1:]}).encode()
ts, nonce = str(int(time.time())), uuid.uuid4().hex
sig = hmac.new(s["session_key"].encode(), "\n".join(["POST", path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode(), hashlib.sha256).hexdigest()
r = urllib.request.Request(url + path, body, {"content-type": "application/json", "authorization": "Bearer " + s["token"],
                           "x-timestamp": ts, "x-nonce": nonce, "x-signature": sig})
print(json.load(urllib.request.urlopen(r, timeout=30)), a[0], a[1:] or "(default vehicle)")
