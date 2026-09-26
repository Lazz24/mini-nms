"""JSON API plus dashboard for the network engine, one origin (stdlib http.server).

Serves GET / (dashboard/index.html and any other file under dashboard/) alongside the
/api/* routes. Reads the port from $PORT (default 8080) and binds to 0.0.0.0 so a host
like Render can route to it. There is no authentication: it is a demo of simulated data.
The NetworkModel is built once at startup. Live (simulated) monitor state is created
once and kept in memory so faults injected via POST /api/inject persist across requests
until cleared; every GET /api/status or /api/alerts reads that current state, and
POST /api/troubleshoot diagnoses against it (so injected faults affect diagnoses).
"""

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import unquote

from engine import monitor
from engine.audit import run_audit
from engine.model import NetworkModel
from engine.troubleshoot import diagnose

HOST = "0.0.0.0"  # all interfaces: required on Render; also serves localhost
PORT = int(os.environ.get("PORT", 8080))  # Render sets PORT
DASHBOARD_DIR = (Path(__file__).resolve().parent / "dashboard").resolve()
MAX_BODY_BYTES = 1_000_000

MODEL = NetworkModel()
LIVE_STATE = monitor.poll(MODEL)
STATE_LOCK = Lock()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _public_state(state):
    """The state snapshot without internal bookkeeping (keys starting with '_')."""
    return {k: v for k, v in state.items() if not k.startswith("_")}


# -- Route handlers -----------------------------------------------------------


def get_health(_body):
    return {"status": "ok", "devices": len(MODEL.devices)}


def get_topology(_body):
    devices = []
    for hostname, dev in sorted(MODEL.devices.items()):
        interfaces = [
            {k: i[k] for k in ("name", "description", "ip", "mask", "network", "vlan", "shutdown", "switchport")}
            for key, i in sorted(MODEL.interfaces.items())
            if i["device"] == hostname
        ]
        devices.append({"hostname": hostname, "role": dev["role"], "interfaces": interfaces})
    return {"devices": devices, "links": MODEL.links, "conflicts": MODEL.conflicts}


def get_status(_body):
    with STATE_LOCK:
        return _public_state(LIVE_STATE)


def get_alerts(_body):
    with STATE_LOCK:
        return monitor.get_alerts(LIVE_STATE)


def get_audit(_body):
    return run_audit(MODEL)


def post_troubleshoot(body):
    if not isinstance(body, dict):
        raise ApiError(400, "body must be a JSON object describing the symptom")
    # Diagnose against the same live state /api/inject mutates, so injected faults count.
    with STATE_LOCK:
        return diagnose(MODEL, body, live_state=LIVE_STATE)


def _device_pair(target):
    if isinstance(target, str):
        target = [t.strip() for t in target.replace(":", ",").replace("-", ",").split(",")]
    if not (isinstance(target, list) and len(target) == 2 and all(isinstance(t, str) and t for t in target)):
        raise ApiError(400, "link_flap target must be two device names, e.g. [\"r1\", \"sw1\"] or \"r1,sw1\"")
    return target


def post_inject(body):
    if not isinstance(body, dict) or "fault" not in body:
        raise ApiError(400, 'body must be a JSON object like {"fault": "interface_down", "target": "r1:GigabitEthernet0/0"}')
    fault, target = body["fault"], body.get("target")
    if fault != "clear" and not target:
        raise ApiError(400, f"fault '{fault}' requires a 'target'")

    with STATE_LOCK:
        try:
            if fault == "interface_down":
                monitor.inject_interface_down(LIVE_STATE, target)
            elif fault == "link_flap":
                monitor.inject_link_flap(LIVE_STATE, _device_pair(target))
            elif fault == "high_util":
                pct = body.get("pct", 95)
                if isinstance(pct, bool) or not isinstance(pct, (int, float)) or not 0 <= pct <= 100:
                    raise ApiError(400, "'pct' must be a number between 0 and 100")
                monitor.inject_high_util(LIVE_STATE, target, pct)
            elif fault == "clear":
                monitor.clear_faults(LIVE_STATE)
            else:
                raise ApiError(400, f"unknown fault '{fault}'; use interface_down, link_flap, high_util or clear")
        except KeyError as exc:
            raise ApiError(400, str(exc.args[0])) from exc
        return {"faults": list(LIVE_STATE["faults"]), "alerts": monitor.get_alerts(LIVE_STATE)}


ROUTES = {
    ("GET", "/api/health"): get_health,
    ("GET", "/api/topology"): get_topology,
    ("GET", "/api/status"): get_status,
    ("GET", "/api/alerts"): get_alerts,
    ("GET", "/api/audit"): get_audit,
    ("POST", "/api/troubleshoot"): post_troubleshoot,
    ("POST", "/api/inject"): post_inject,
}


# -- HTTP plumbing ------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        data = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "invalid Content-Length") from None
        if length <= 0:
            raise ApiError(400, "request body is empty; expected a JSON object")
        if length > MAX_BODY_BYTES:
            raise ApiError(400, "request body too large")
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, f"malformed JSON body: {exc}") from exc

    def _static_file(self, path):
        """The file under dashboard/ for a request path, or None. Never escapes the folder."""
        relative = "index.html" if path in ("/", "/index.html") else unquote(path).lstrip("/")
        try:
            target = (DASHBOARD_DIR / relative).resolve()
        except (OSError, ValueError):
            return None
        if target.is_file() and target.is_relative_to(DASHBOARD_DIR):
            return target
        return None

    def _send_static(self, target):
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method):
        try:
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if method == "GET" and not path.startswith("/api"):
                target = self._static_file(path)
                if target is None:
                    raise ApiError(404, f"no such page: {path}")
                self._send_static(target)
                return
            route = ROUTES.get((method, path))
            if route is None:
                known = {p for (_, p) in ROUTES}
                if path in known:
                    raise ApiError(405, f"{method} not allowed on {path}")
                raise ApiError(404, f"no such endpoint: {path}")
            body = self._read_json() if method == "POST" else None
            self._send(200, route(body))
        except ApiError as exc:
            self._send(exc.status, {"error": str(exc)})
        except Exception as exc:  # keep the server alive on any handler bug
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Network engine on http://localhost:{PORT} (listening on {HOST}:{PORT})")
    print(f"  GET   /            dashboard ({DASHBOARD_DIR.name}/index.html)")
    for (method, path) in ROUTES:
        print(f"  {method:<5} {path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.server_close()
