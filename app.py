"""Condense output-connector entrypoint. ROLE=all (default: sink thread + gateway), sink, or gateway.
Split sink/gateway only makes sense with a shared Postgres (DATABASE_URL); SQLite is per-pod."""
import logging
import os
import sys
import threading

import uvicorn

from quantara_core import config, topics
from quantara_core.bus import get_bus
from ops.auth import Auth
from ops.gateway import create_app
from ops.sink import Sink
from ops.store import Store

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ops")


def main():
    role = os.environ.get("ROLE", "all")
    redis = None
    if os.environ.get("REDIS_URL"):
        import redis as _r
        redis = _r.from_url(os.environ["REDIS_URL"])
    store, bus = Store(os.environ.get("DATABASE_URL"), redis), get_bus()
    log.info("topics: %s", {k: v for k, v in topics.ensure_topics().items() if v != "exists"} or "all exist")
    log.info("role=%s store=%s redis=%s", role, "postgres" if store.pg else "sqlite", bool(redis))
    if role in ("all", "sink"):
        threading.Thread(target=Sink(store, bus).run, daemon=True).start()
    if role in ("all", "gateway"):
        uvicorn.run(create_app(store, bus, Auth.from_env()), host="0.0.0.0", port=int(os.environ.get("portNumber") or os.environ.get("PORT") or 8080), log_level="info")
    else:
        threading.Event().wait()


def _diagnose(err):
    """If startup fails, keep the port alive and show why (Condense logs are not always visible). Never prints env values."""
    import http.server
    import traceback
    txt = "ops failed to start:\n" + "".join(traceback.format_exception(type(err), err, err.__traceback__))
    log.error(txt)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500); self.send_header("content-type", "text/plain"); self.end_headers(); self.wfile.write(txt.encode())
    http.server.HTTPServer(("0.0.0.0", int(os.environ.get("portNumber") or os.environ.get("PORT") or 8080)), H).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _diagnose(e)
