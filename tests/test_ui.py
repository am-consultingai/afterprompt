"""U1/U2/U3/U5/U6: the loopback UI. Every defence is asserted on its own, including DNS rebinding."""
import http.client
import io
import json
import os
import re
import threading
import time
from unittest import mock

from afterprompt import cli, ui
from afterprompt.util import write_json
from tests.helpers import Fixture, TempDirTest, requires_rg

PORT = 50505
TOKEN = "t" * 43


class RuleTests(TempDirTest):
    """request_problem() is pure, so each rule is checked in isolation."""

    def problem(self, api=True, **h):
        headers = {"Host": f"127.0.0.1:{PORT}", "Authorization": f"Bearer {TOKEN}"}
        headers.update({k.replace("_", "-"): v for k, v in h.items() if v is not None})
        for k in [k for k, v in h.items() if v is None]:
            headers.pop(k.replace("_", "-"), None)
        return ui.request_problem(headers, PORT, TOKEN, api)

    def test_good_requests(self):  # U-UI-1
        self.assertIsNone(self.problem())
        self.assertIsNone(self.problem(Host=f"localhost:{PORT}"))
        self.assertIsNone(self.problem(Origin=f"http://127.0.0.1:{PORT}", Sec_Fetch_Site="same-origin"))
        self.assertIsNone(self.problem(Sec_Fetch_Site="none"))                  # typed into the address bar
        self.assertIsNone(self.problem(api=False, Authorization=None))           # the static page needs no key

    def test_dns_rebinding_is_refused(self):  # U-UI-2
        """evil.example resolves to 127.0.0.1: the browser then sends Host: evil.example:port."""
        for host in (f"evil.example:{PORT}", f"127.0.0.1:{PORT + 1}", "127.0.0.1", f"localhost.evil.example:{PORT}",
                     f"[::1]:{PORT}", None):
            with self.subTest(host=host):
                self.assertEqual(self.problem(Host=host), (403, "unexpected Host header"))

    def test_cross_site_is_refused(self):  # U-UI-3
        for origin in ("http://evil.example", "null", f"https://127.0.0.1:{PORT}", f"http://127.0.0.1:{PORT + 1}"):
            with self.subTest(origin=origin):
                self.assertEqual(self.problem(Origin=origin)[0], 403)
        for site in ("cross-site", "same-site"):
            with self.subTest(site=site):
                self.assertEqual(self.problem(Sec_Fetch_Site=site)[0], 403)

    def test_token(self):  # U-UI-4
        self.assertEqual(self.problem(Authorization=None), (401, "missing or wrong token"))
        self.assertEqual(self.problem(Authorization="Bearer " + "x" * 43)[0], 401)
        self.assertEqual(self.problem(Authorization=TOKEN)[0], 401)              # scheme required
        self.assertEqual(self.problem(Authorization="Bearer ")[0], 401)


class LiveServerTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.state = ui.State(os.path.join(self.tmp, "checklist.json"))
        self.server = ui.Server(self.state).start()
        self.port = self.server.server_port
        self.addCleanup(self.server.stop)

    def req(self, method, path, body=None, headers=None, token=True, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["Authorization"] = f"Bearer {self.server.token}"
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.putrequest(method, path, skip_host=True)
        for k, v in h.items():
            c.putheader(k, v)
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else (body or b"")
        data = data.encode() if isinstance(data, str) else data
        if body is not None:
            c.putheader("Content-Length", str(len(data)))
        c.endheaders(data if body is not None else None)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_bound_to_loopback_with_a_long_key(self):  # U-UI-5
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertGreaterEqual(len(self.server.token), 43)                      # 32 random bytes
        self.assertIn(f"127.0.0.1:{self.port}/#token=", self.server.url)         # fragment: never sent to a server

    def test_page_headers_and_no_cors_ever(self):  # U-UI-6
        status, h, body = self.req("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        for method, path in (("GET", "/"), ("GET", "/api/status"), ("OPTIONS", "/api/status"),
                             ("POST", "/api/heartbeat")):
            _, h, _ = self.req(method, path, body={} if method == "POST" else None,
                               headers={"Origin": f"http://127.0.0.1:{self.port}"})
            self.assertFalse([k for k in h if k.lower().startswith("access-control")], (method, path))
        self.assertEqual(self.req("OPTIONS", "/api/status")[0], 405)

    def test_api_needs_the_key_and_the_right_host(self):  # U-UI-7
        self.assertEqual(self.req("GET", "/api/status", token=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/status", host=f"evil.example:{self.port}")[0], 403)
        self.assertEqual(self.req("GET", "/", token=False, host=f"evil.example:{self.port}")[0], 403)
        self.assertEqual(self.req("GET", "/api/status", headers={"Origin": "http://evil.example"})[0], 403)
        status, _, body = self.req("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["finished"], False)

    def test_no_file_can_be_reached(self):  # U-UI-8
        for path in ("/../../etc/passwd", "/app.js/../ui.py", "/%2e%2e/ui.py", "/assets/ui/index.html",
                     "/api/../ui.py", "//etc/passwd", "/index.html", "/api/file?path=/etc/passwd"):
            with self.subTest(path=path):
                self.assertEqual(self.req("GET", path)[0], 404)

    def test_findings_are_the_masked_ones(self):  # U-UI-9
        self.assertEqual(self.req("GET", "/api/findings")[0], 404)
        fp = os.path.join(self.tmp, "findings.json")
        write_json(fp, {"rotate": [{"hash": "abc123def4567890", "masked": "sk-ant…Ab12"}], "review": []})
        self.state.finish(fp)
        status, _, body = self.req("GET", "/api/findings")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["findings"]["rotate"][0]["masked"], "sk-ant…Ab12")

    def test_checklist(self):  # U-UI-10
        ok = {"hash": "abc123def4567890", "done": True}
        self.assertEqual(self.req("POST", "/api/checklist", body=ok)[0], 200)
        with open(os.path.join(self.tmp, "checklist.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), {"abc123def4567890": True})
        self.assertEqual(self.req("POST", "/api/checklist", body={"hash": "../../etc", "done": True})[0], 400)
        self.assertEqual(self.req("POST", "/api/checklist", body={"hash": "ABC123DEF4567890"})[0], 400)
        self.assertEqual(self.req("POST", "/api/checklist", body="x" * 5000)[0], 413)
        self.assertEqual(self.req("POST", "/api/checklist", body=ok, headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.req("POST", "/api/checklist", body=b"{nope")[0], 400)
        self.assertEqual(self.req("POST", "/api/checklist", body=ok, token=False)[0], 401)

    def test_heartbeat(self):  # U-UI-11
        self.assertIsNone(self.state.last_beat)
        self.assertEqual(self.req("POST", "/api/heartbeat", body={})[0], 200)
        self.assertIsNotNone(self.state.last_beat)

    def test_live_events(self):  # U-UI-12
        self.state.set_stages(["discover", "report"], {"discover": "Finding AI tool data"})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/api/events", headers={"Authorization": f"Bearer {self.server.token}"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/event-stream"))
        hello = json.loads(r.fp.readline().decode()[len("data: "):])
        r.fp.readline()
        self.assertEqual(hello["type"], "hello")
        self.assertEqual(hello["stages"][0]["label"], "Finding AI tool data")
        self.state.say("[1/9] Finding AI tool data …")
        ev = json.loads(r.fp.readline().decode()[len("data: "):])
        self.assertEqual(ev, {"type": "line", "text": "[1/9] Finding AI tool data …"})
        c.close()


class PageTests(TempDirTest):
    def test_page_loads_nothing_external_and_never_injects_html(self):  # U-UI-13
        for name in ("index.html", "app.js", "app.css"):
            with open(os.path.join(ui.HERE, name), encoding="utf-8") as fh:
                text = fh.read()
            with self.subTest(file=name):
                self.assertFalse(re.search(r"(?:src|href)\s*=\s*[\"']https?:", text))
                self.assertNotIn("@import", text)
                self.assertNotIn("//cdn", text)
        with open(os.path.join(ui.HERE, "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "localStorage"):
            self.assertNotIn(banned, js)
        self.assertIn("history.replaceState", js)          # the key leaves the address bar at once
        self.assertIn('credentials: "omit"', js)


class LifecycleTests(TempDirTest):
    def test_should_stop(self):  # U-UI-14
        st = ui.State(os.path.join(self.tmp, "c.json"))
        now = st.started
        self.assertFalse(ui.should_stop(st, now + 10 ** 6))                 # never while the scan runs
        st.finished = True
        self.assertFalse(ui.should_stop(st, now + 10, grace=45, idle=1800))
        self.assertTrue(ui.should_stop(st, now + 1801, grace=45, idle=1800))  # nobody ever opened it
        st.last_beat = now + 100
        self.assertFalse(ui.should_stop(st, now + 140, grace=45, idle=1800))
        self.assertTrue(ui.should_stop(st, now + 146, grace=45, idle=1800))   # the tab was closed

    def test_wait_stops_the_server(self):  # U-UI-15
        st = ui.State(os.path.join(self.tmp, "c.json"))
        server = ui.Server(st).start()
        st.finished = True
        st.last_beat = time.monotonic()
        ui.wait_until_done(server, poll=0.05, grace=0.2)
        with self.assertRaises(OSError):
            http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=1).request("GET", "/")


@requires_rg
class CliTests(TempDirTest):
    def test_scan_with_the_browser_view(self):  # U-UI-16
        fx = Fixture(self.tmp, "linux")
        out = io.StringIO()
        seen = {}

        def browser():
            for _ in range(600):
                m = re.search(r"Browser view: (http://127\.0\.0\.1:(\d+)/#token=([\w-]+))", out.getvalue())
                if m:
                    break
                time.sleep(0.05)
            port, token = int(m.group(2)), m.group(3)
            h = {"Authorization": f"Bearer {token}"}
            for _ in range(600):                     # poll status until the scan finishes, like the page does
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", "/api/status", headers=h)
                st = json.loads(c.getresponse().read())
                c.close()
                if st["finished"]:
                    break
                time.sleep(0.1)
            seen["stages"] = st["stages"]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/api/findings", headers=h)
            seen["findings"] = json.loads(c.getresponse().read())["findings"]
            c.close()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/heartbeat", body=b"{}", headers=dict(h, **{"Content-Type": "application/json"}))
            c.getresponse().read()
            c.close()
            seen["token"] = token
        t = threading.Thread(target=browser, daemon=True)
        t.start()
        import contextlib
        with mock.patch.dict(os.environ, fx.env()), mock.patch.object(ui, "HEARTBEAT_GRACE", 0.5), \
                contextlib.redirect_stdout(out):
            code = cli.main(["--ui"])
        t.join(10)
        self.assertEqual(code, cli.EXIT_ROTATE)
        self.assertTrue(all(s["done"] for s in seen["stages"]))
        self.assertEqual(len(seen["findings"]["rotate"]), 4)
        for v in fx.s.values():
            self.assertNotIn(v, json.dumps(seen["findings"]))
        run = os.path.join(fx.base, "runs", os.listdir(os.path.join(fx.base, "runs"))[0])
        with open(os.path.join(run, "run.log"), encoding="utf-8") as fh:
            self.assertNotIn(seen["token"], fh.read())                      # the key is never written down
