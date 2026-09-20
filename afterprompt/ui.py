"""The local UI (--ui): a loopback server the browser talks to while a scan runs, and after it.

The browser never sees the machine; this process does. The page is a view onto it, and the API is a short
allowlist of read-only endpoints plus two small writes (checklist ticks and the page's heartbeat). No endpoint
takes a path, runs anything, or returns an unmasked secret: everything it serves was already masked for
findings.json.

Defences (U1, U2), each checked on every request:
- bound to 127.0.0.1 only, on an ephemeral port (never 0.0.0.0: no firewall prompt, no LAN exposure);
- a 256-bit capability token, required as "Authorization: Bearer" on every /api/ call. It reaches the page in the
  URL fragment, which browsers never send to a server; the page moves it into memory and removes it from the
  address bar. Loopback is not a trust boundary (any local user or process can connect), so the token is;
- the Host header must name this server (defeats DNS rebinding, where evil.example resolves to 127.0.0.1);
- cross-site requests are refused by Origin and Sec-Fetch-Site, and no CORS header is ever sent;
- the page is served with CSP default-src 'self' and bundles everything, so it provably loads nothing external.
"""
import hmac
import json
import os
import queue
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from afterprompt import settings
from afterprompt.util import read_json, write_json

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ui")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"), "/tokens.css": ("tokens.css", "text/css; charset=utf-8"),
          # Reference data the page needs and must not fetch from the internet: vendor marks (Simple Icons, CC0)
          # and the rotation guidance keyed by vendor.
          "/vendors.json": ("vendors.json", "application/json; charset=utf-8"),
          "/rotation.json": ("rotation.json", "application/json; charset=utf-8")}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 4096
HEARTBEAT_GRACE = 45.0     # seconds without a heartbeat before a finished scan's server stops
IDLE_LIMIT = 30 * 60.0     # seconds a finished scan's server stays up with no page at all


class State:
    """What the page can see: progress, console lines, the finished findings, the checklist."""

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.lock = threading.Lock()
        self.stages = []
        self.current = None
        self.done = set()
        self.summaries = {}
        self.progress = {}
        self.lines = []
        self.finished = False
        self.findings_path = None
        self.checklist_path = os.path.join(base_dir, "checklist.json")
        self.subscribers = []
        self.last_beat = None
        self.started = time.monotonic()

    def _publish(self, event):
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except queue.Full:
                pass

    def set_stages(self, stages, descriptions):
        with self.lock:
            self.stages = [{"name": s, "label": descriptions.get(s, s)} for s in stages]
        self._publish({"type": "stages"})

    def stage(self, name, done=False, summary=None):
        with self.lock:
            if done:
                self.done.add(name)
                if summary:
                    self.summaries[name] = summary
                self.progress.pop(name, None)
            else:
                self.current = name
        self._publish({"type": "stage", "name": name, "done": done})

    def progress_update(self, stage, done, total=None, note=None):
        """One phase's live count. total None means the total is not knowable, and the view says so."""
        with self.lock:
            self.progress[stage] = {"done": done, "total": total, "note": note}
        self._publish({"type": "progress", "stage": stage, "done": done, "total": total, "note": note})

    def say(self, line):
        with self.lock:
            self.lines.append(line)
            del self.lines[:-2000]
        self._publish({"type": "line", "text": line})

    def finish(self, findings_path):
        with self.lock:
            self.finished = True
            self.findings_path = findings_path
        self._publish({"type": "finished"})

    def snapshot(self):
        with self.lock:
            return {"stages": [dict(s, done=s["name"] in self.done, current=s["name"] == self.current,
                                    summary=self.summaries.get(s["name"]))
                               for s in self.stages],
                    "progress": dict(self.progress),
                    "finished": self.finished, "lines": self.lines[-400:]}

    def checklist(self):
        data = read_json(self.checklist_path, {}) or {}
        return {k: bool(v) for k, v in data.items() if isinstance(k, str)} if isinstance(data, dict) else {}

    def tick(self, value_hash, done):
        with self.lock:
            data = self.checklist()
            data[value_hash] = bool(done)
            write_json(self.checklist_path, data)
            return data


def allowed_host(host, port):
    return host in (f"127.0.0.1:{port}", f"localhost:{port}")


def request_problem(headers, port, token, api):
    """Why a request must be refused (status, reason), or None. Pure, so every rule is tested on its own."""
    if not allowed_host(headers.get("Host", ""), port):
        return 403, "unexpected Host header"
    origin = headers.get("Origin")
    if origin is not None and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
        return 403, "cross-origin request"
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        return 403, "cross-site request"
    if api:
        auth = headers.get("Authorization", "")
        given = auth[7:] if auth.startswith("Bearer ") else ""
        if not given or not hmac.compare_digest(given.encode(), token.encode()):
            return 401, "missing or wrong token"
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "afterprompt-ui"
    sys_version = ""

    def log_message(self, fmt, *args):   # never print request lines (they are local, but noisy)
        pass

    # ---- responses
    def _headers(self, status, ctype, length=None, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        if length is not None:
            self.send_header("Content-Length", str(length))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self._headers(status, ctype, len(data))
        if self.command != "HEAD":
            self.wfile.write(data)

    def _check(self, api):
        problem = request_problem(self.headers, self.server.server_port, self.server.token, api)
        if problem:
            self._send(problem[0], {"error": problem[1]})
            return False
        return True

    # ---- verbs
    def do_GET(self):
        path = urlsplit(self.path).path
        if path in STATIC:
            if not self._check(api=False):
                return
            name, ctype = STATIC[path]
            with open(os.path.join(HERE, name), "rb") as fh:
                self._send(200, fh.read(), ctype)
            return
        if not path.startswith("/api/"):
            self._check(api=False) and self._send(404, {"error": "not found"})
            return
        if not self._check(api=True):
            return
        st = self.server.state
        if path == "/api/status":
            self._send(200, st.snapshot())
        elif path == "/api/findings":
            data = read_json(st.findings_path, None) if st.findings_path else None
            if data is None:
                self._send(404, {"error": "no findings yet"})
            else:
                self._send(200, {"findings": data, "checklist": st.checklist()})
        elif path == "/api/settings":
            self._send(200, settings.describe(st.base_dir))
        elif path == "/api/events":
            self._events()
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        # Read the body before deciding anything. A refusal that leaves bytes unread makes Windows reset the
        # connection, and the caller then sees a dropped socket instead of the 401 or 403 it should have got.
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        body_bytes = self.rfile.read(n) if 0 < n <= MAX_BODY else b""
        if 0 < n > MAX_BODY:
            self.rfile.read(min(n, 1024 ** 2))
        if not self._check(api=True):
            return
        if n < 0 or n > MAX_BODY:
            self._send(413, {"error": "body too large"})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._send(415, {"error": "expected application/json"})
            return
        try:
            body = json.loads(body_bytes or b"{}")
        except ValueError:
            self._send(400, {"error": "bad json"})
            return
        st = self.server.state
        if path == "/api/heartbeat":
            st.last_beat = time.monotonic()
            self._send(200, {"ok": True})
        elif path == "/api/settings":
            key = body.get("key") if isinstance(body, dict) else None
            values = settings.set_value(st.base_dir, key, body.get("value")) if isinstance(key, str) else None
            if values is None:
                self._send(400, {"error": "unknown setting or value out of range"})
            else:
                self._send(200, {"values": values})
        elif path == "/api/checklist":
            h = body.get("hash") if isinstance(body, dict) else None
            if not (isinstance(h, str) and 8 <= len(h) <= 64 and all(c in "0123456789abcdef" for c in h)):
                self._send(400, {"error": "hash must be a value hash"})
                return
            self._send(200, {"checklist": st.tick(h, bool(body.get("done")))})
        else:
            self._send(404, {"error": "not found"})

    def do_OPTIONS(self):
        # No CORS, ever: a preflight gets a plain refusal and no Access-Control-* header.
        self._send(405, {"error": "method not allowed"})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS

    def _events(self):
        """Server-sent events over a fetch() stream (the page sends the token as a header, which EventSource
        cannot), one JSON event per line, with a keep-alive comment every 15 s."""
        q = queue.Queue(maxsize=5000)
        st = self.server.state
        st.subscribers.append(q)
        try:
            self._headers(200, "text/event-stream; charset=utf-8")
            self.wfile.write(f"data: {json.dumps({'type': 'hello', **st.snapshot()})}\n\n".encode())
            self.wfile.flush()
            while not self.server.stopping.is_set():
                try:
                    ev = q.get(timeout=15)
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            if q in st.subscribers:
                st.subscribers.remove(q)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state, token=None, port=0):
        super().__init__(("127.0.0.1", port), Handler)
        self.state = state
        self.token = token or secrets.token_urlsafe(32)      # 256 bits
        self.stopping = threading.Event()
        self.thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}/#token={self.token}"

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stopping.set()
        self.shutdown()
        self.server_close()


def should_stop(state, now=None, grace=None, idle=None):
    """After the scan: stop when the page has gone quiet, or when no page ever came and the idle limit passed."""
    grace = HEARTBEAT_GRACE if grace is None else grace
    idle = IDLE_LIMIT if idle is None else idle
    if not state.finished:
        return False
    now = time.monotonic() if now is None else now
    if state.last_beat is not None:
        return now - state.last_beat > grace
    return now - state.started > idle


def wait_until_done(server, poll=1.0, grace=None, idle=None):
    """Keep serving a finished scan until the page is closed (heartbeat stops), the idle limit passes, or Ctrl-C."""
    try:
        while not should_stop(server.state, grace=grace, idle=idle):
            time.sleep(poll)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
