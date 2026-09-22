"""U1/U2/U3/U5/U6: the loopback UI. Every defence is asserted on its own, including DNS rebinding."""
import http.client
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from afterprompt import cli, ui
from afterprompt.util import write_json
from tests.helpers import Fixture, TempDirTest, requires_rg, write

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
        self.state = ui.State(self.tmp)
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
        # A refusal still reads the body first: otherwise the connection is reset and the caller never sees why.
        self.assertEqual(self.req("POST", "/api/checklist", body=ok, token=False)[0], 401)
        self.assertEqual(self.req("POST", "/api/checklist", body="x" * 5000, token=False)[0], 401)
        self.assertEqual(self.req("POST", "/api/checklist", body=ok, host="evil.example:1")[0], 403)

    def test_start_is_the_only_endpoint_that_makes_work_happen(self):  # U-UI-46
        """It is behind the same key as everything else, and pressing it twice starts one scan."""
        self.assertFalse(self.state.scan_started)
        self.assertEqual(self.req("POST", "/api/start", body={}, token=False)[0], 401)
        self.assertFalse(self.state.scan_started)           # a refused press reads nothing
        code, _, body = self.req("POST", "/api/start", body={})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"started": True, "first": True})
        self.assertTrue(self.state.scan_started)
        self.assertTrue(self.state.wait_for_start(0.01))
        self.assertEqual(json.loads(self.req("POST", "/api/start", body={})[2])["first"], False)
        self.assertTrue(json.loads(self.req("GET", "/api/status")[2])["started"])

    def test_heartbeat(self):  # U-UI-11
        self.assertIsNone(self.state.last_beat)
        self.assertEqual(self.req("POST", "/api/heartbeat", body={})[0], 200)
        self.assertIsNotNone(self.state.last_beat)

    def test_progress_and_summaries(self):  # U-UI-27
        """A phase that can count says how far it is; one that cannot says so, and never invents a total."""
        self.state.set_stages(["manifest", "expand"], {"manifest": "Listing files", "expand": "Decoding"})
        self.state.progress_update("expand", 306, 1510)
        self.state.progress_update("manifest", 4200, None, "files found")
        body = json.loads(self.req("GET", "/api/status")[2])
        self.assertEqual(body["progress"]["expand"], {"done": 306, "total": 1510, "note": None})
        self.assertEqual(body["progress"]["manifest"], {"done": 4200, "total": None, "note": "files found"})
        self.state.stage("expand", done=True, summary="7.5 GB decoded")
        body = json.loads(self.req("GET", "/api/status")[2])
        self.assertEqual([s["summary"] for s in body["stages"] if s["name"] == "expand"], ["7.5 GB decoded"])
        self.assertNotIn("expand", body["progress"])          # a finished phase drops its bar

    def test_reference_data_is_served_locally(self):  # U-UI-28
        for path in ("/vendors.json", "/rotation.json"):
            with self.subTest(path=path):
                status, headers, body = self.req("GET", path, token=False)
                self.assertEqual(status, 200)
                self.assertTrue(headers["Content-Type"].startswith("application/json"))
                self.assertIn("schema" if "rotation" in path else "icons", json.loads(body))

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
    """The page itself, and the design rules that decay without a test (AM Consulting frontend UI guidelines)."""

    def read(self, name):
        with open(os.path.join(ui.HERE, name), encoding="utf-8") as fh:
            return fh.read()

    def read_module(self, name):
        with open(os.path.join(os.path.dirname(os.path.abspath(ui.__file__)), name), encoding="utf-8") as fh:
            return fh.read()

    def js_without_comments(self):
        js = re.sub(r"/\*.*?\*/", "", self.read("app.js"), flags=re.S)
        return re.sub(r"(?m)^\s*//.*$", "", js)

    def test_page_loads_nothing_external_and_never_injects_html(self):  # U-UI-13
        for name in ("index.html", "app.js", "app.css", "tokens.css"):
            text = self.read(name)
            with self.subTest(file=name):
                self.assertFalse(re.search(r"(?:src|href)\s*=\s*[\"']https?:", text))
                self.assertNotIn("@import", text)
                self.assertNotIn("//cdn", text)
        js = self.read("app.js")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(banned, js)
        self.assertIn("history.replaceState", js)          # the key leaves the address bar at once
        self.assertIn('credentials: "omit"', js)
        # Nothing from the scan, and nothing else, is kept in the browser: even the theme lives in the
        # scanner's settings file, so the page holds no state of its own.
        for store in ("localStorage", "sessionStorage", "indexedDB", "document.cookie"):
            self.assertNotIn(store, js)

    def test_every_colour_comes_from_a_token(self):  # U-UI-17
        """Three shades of grey invented per component is what unfinished looks like: app.css names no colour."""
        css = self.read("app.css")
        self.assertFalse(re.findall(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", css), "raw colour in app.css")
        self.assertIn("var(--", css)
        tokens = self.read("tokens.css")
        for required in ("--base:", "--ink:", "--accent:", "color-mix(in oklab"):
            self.assertIn(required, tokens)
        # Dark mode is a redefinition of the inputs, not a second palette.
        self.assertIn('@media (prefers-color-scheme: dark)', tokens)
        self.assertIn(':root:not([data-theme="light"])', tokens)
        self.assertIn(':root[data-theme="dark"]', tokens)

    def test_directions_are_logical(self):  # U-UI-18
        """One physical property is all it takes to break every right-to-left screen."""
        for name in ("app.css", "tokens.css"):
            css = re.sub(r"/\*.*?\*/", "", self.read(name), flags=re.S)
            with self.subTest(file=name):
                self.assertFalse(re.findall(r"(?m)^\s*(?:padding|margin|border)-(?:left|right)\s*:", css))
                self.assertFalse(re.findall(r"text-align\s*:\s*(?:left|right)", css))
                self.assertFalse(re.findall(r"(?m)^\s*(?:left|right)\s*:", css))
                self.assertFalse(re.findall(r"float\s*:", css))

    def test_shadows_are_current(self):  # U-UI-19
        """The 2010s shadow (12-25% black, positive spread, one layer) is the biggest dated tell."""
        css = self.read("tokens.css")
        found = 0
        for line in css.splitlines():
            if not line.strip().startswith("--shadow"):
                continue
            px = r"(-?\d+)(?:px)?"
            for layer in re.findall(rf"{px}\s+{px}\s+{px}\s+{px}\s+rgb\([^/]*/\s*(\d+)%", line):
                found += 1
                spread, alpha = int(layer[3]), int(layer[4])
                self.assertLess(spread, 0, line)           # negative spread: the shadow sits under the element
                self.assertLessEqual(alpha, 7, line)
        self.assertGreaterEqual(found, 4)

    def test_type_and_shape_rules(self):  # U-UI-20
        css = self.read("app.css") + self.read("tokens.css")
        self.assertNotIn("text-transform: uppercase", css)   # uppercase micro-labels are extinct (and RTL-hostile)
        self.assertIn("--weight-label", css)
        # Radius is stratified by element size, not one value everywhere.
        radii = {k: int(v) for k, v in re.findall(r"--radius-(\w+):\s*(\d+)px", css)}
        self.assertEqual(sorted(radii), ["card", "control", "panel", "row"])
        self.assertLess(radii["control"], radii["card"])
        self.assertLess(radii["card"], radii["panel"])
        self.assertLessEqual(radii["control"], 6)
        # Tracking is a Latin device, so it is scoped rather than applied from body.
        self.assertIn(":dir(ltr) body", self.read("app.css"))
        self.assertIn("--measure", css)

    def test_icons_are_16px_at_stroke_1_5(self):  # U-UI-21
        js = self.read("app.js")
        self.assertIn('viewBox: "0 0 16 16"', js)
        self.assertIn('"stroke-width": "1.5"', js)
        # The only 24-box art is the marks — a vendor's and an environment's — which are filled glyphs, not
        # strokes, and are drawn in a fixed cell rather than scaled from a 24px stroke icon.
        self.assertEqual(js.count('"0 0 24 24"'), 2)
        self.assertIn('fill: "currentColor"', js)
        css = self.read("app.css")
        self.assertIn("place-items: center; inline-size: 16px; block-size: 16px", css)
        self.assertIn(".mark svg { inline-size: 13px; block-size: 13px; }", css)

    def test_no_user_visible_string_is_inline(self):  # U-UI-22
        """Every sentence lives in the TEXT catalogue, so there is one place to translate and to proofread."""
        js = self.js_without_comments()
        body = js[js.index("const TEXT = {"):]
        after = body[body.index("\n  };") + 1:]
        literals = re.findall(r'"((?:[^"\\\n]|\\.)*)"', after) + re.findall(r"'((?:[^'\\\n]|\\.)*)'", after)
        inline = [t for t in literals if len(t) >= 14
                  if " " in t and not t.startswith(("http", "/api/", "data:", "0 0 ", "M", "application/"))
                  and t != "noreferrer noopener"      # an attribute value, not a sentence
                  and "px" not in t and not t.startswith("afterprompt.")]
        self.assertEqual(inline, [], "move these into TEXT")

    def test_accessibility_floor(self):  # U-UI-23
        html, js, css = self.read("index.html"), self.read("app.js"), self.read("app.css")
        self.assertIn('role="status"', html)                       # progress is announced without the user acting
        self.assertIn('setAttribute("aria-live", "polite")', js)
        self.assertIn('setAttribute("role", "listbox")', js)
        self.assertIn('setAttribute("aria-activedescendant"', js)
        self.assertIn('aria-selected', js)
        self.assertIn('setAttribute("aria-expanded"', js)           # collapsible groups say whether they are open
        self.assertIn('setAttribute("role", "progressbar")', js)    # and a bar reports its value
        self.assertIn("label.htmlFor", js)                         # clicking a label focuses its control
        self.assertIn(":focus-visible", css)
        # Selection and focus must look different: a persistent fill, and a ring only while the list has focus.
        self.assertIn('.row[aria-selected="true"]', css)
        self.assertIn(".list:focus-visible .row[aria-selected=\"true\"]", css)
        self.assertIn("prefers-reduced-motion", css)
        self.assertIn('"aria-hidden": "true"', js)                 # decorative icons are not announced

    def test_progress_is_honest(self):  # U-UI-29
        js = self.js_without_comments()
        self.assertIn("if (p.total) {", js)                   # a bar only when a total is knowable
        self.assertIn("TEXT.totalUnknown", js)                # and it says so when it is not
        self.assertNotIn("estimate", js.lower())
        self.assertIn('setAttribute("role", "progressbar")', js)

    def test_screens_and_deep_links(self):  # U-UI-30
        js = self.js_without_comments()
        self.assertIn('["scan", "findings", "settings", "about"].includes(wantedScreen)', js)
        self.assertNotIn("machines", js.lower().split("const text")[0])   # no screen of its own any more
        self.assertIn('params.get("screen")', js)
        self.assertIn('show("findings")', js)                 # the result is shown when the scan finishes

    def test_marks_identify_never_endorse(self):  # U-UI-31
        js = self.js_without_comments()
        self.assertIn("const isVendor =", js)                 # a kind of secret is not drawn as a brand
        self.assertIn('fill: "currentColor"', js)             # one ink colour, never the brand's palette
        self.assertNotIn("brand", js.lower())
        self.assertIn("trademarks:", js)                      # and the page says whose marks these are

    def test_it_fits_a_phone(self):  # U-UI-33
        """Measured at 390px: the bar's name, tabs and state overflowed, and the page scrolled sideways."""
        css = self.read("app.css")
        narrow = css[css.index("@media (max-width: 560px)"):]
        narrow = narrow[:narrow.index("}\n}") + 3]
        self.assertIn(".bar { block-size: auto; flex-wrap: wrap;", narrow)
        self.assertIn(".tabs { order: 3; flex-basis: 100%; }", narrow)   # the tabs take their own row
        # Panes stack before that, so the list and the card are never side by side on a phone.
        self.assertIn("@media (max-width: 900px) { .panes { grid-template-columns: minmax(0, 1fr);", css)

    def test_the_card_answers_for_this_credential_not_just_this_vendor(self):  # U-UI-32
        js = self.js_without_comments()
        # A vendor can issue several kinds of credential, and the page must not give a cookie key-rotation steps.
        self.assertIn("function vendorGuide(vendor, kind)", js)
        self.assertIn("base.kinds && base.kinds[kind]", js)
        self.assertIn('kind === "session_cookie" ? TEXT.endsSession', js)
        # GitHub's fine-grained tokens live on their own page: the per-format link beats the vendor-wide console.
        links = js[js.index("const links = el("):js.index("if (links.children.length)")]
        self.assertLess(links.index("f.revoke.url"), links.index("guide.console.url"))

    def test_nothing_is_read_until_the_page_asks(self):  # U-UI-45
        """The link opening a browser must not be what makes a machine-wide read of every credential begin."""
        st = ui.State(self.tmp)
        self.assertFalse(st.scan_started)
        self.assertFalse(st.snapshot()["started"])
        self.assertFalse(st.wait_for_start(0.01))          # nobody asked: the wait does not pass
        self.assertTrue(st.request_start())                # the press
        self.assertTrue(st.wait_for_start(0.01))
        self.assertTrue(st.snapshot()["started"])
        self.assertFalse(st.request_start())               # pressing twice starts one scan

    def test_a_signal_must_not_be_mistaken_for_a_press(self):  # U-UI-49
        """Event.wait() returns early for reasons that are not a press; the flag is the gate, not the wait.

        This shipped wrong once: killing the wrapper shell released the wait, and a full scan of the machine
        began that nobody had asked for."""
        cli_src = self.read_module("cli.py")
        gate = cli_src[cli_src.index("Waiting for Start scan"):cli_src.index("t0 = time.monotonic()")]
        self.assertIn("while not view.state.scan_started:", gate)
        self.assertIn("view.state.wait_for_start(0.5)", gate)

    def test_a_step_says_what_it_found(self):  # U-UI-50
        """A count is a number to believe or not; the names behind it can be checked."""
        st = ui.State(self.tmp)
        st.set_stages(["environments"], {"environments": "Looking for environments"})
        st.detail("environments", [{"label": "Docker containers", "note": "api-1, worker-1", "tone": "ok"},
                                   {"label": "", "note": "dropped: no label"}])
        rows = st.snapshot()["details"]["environments"]
        self.assertEqual([r["label"] for r in rows], ["Docker containers"])
        st.detail("environments", [])                       # nothing to say leaves what was there
        self.assertEqual(len(st.snapshot()["details"]["environments"]), 1)

    def test_the_scan_screen_groups_and_opens_its_steps(self):  # U-UI-51
        js = self.js_without_comments()
        # Four pieces of work, and every step named in exactly one of them.
        self.assertIn('const GROUPS = [["find"', js)
        groups = js[js.index("const GROUPS = ["):js.index("const GROUP_LABEL")]
        for stage in cli.DESCRIPTIONS:
            self.assertIn(f'"{stage}"', groups, f"{stage} belongs to no group on the scan screen")
        # A step with something to show opens; one without stays a line rather than a dead control.
        self.assertIn("const head2 = el(rows ? \"button\" : \"div\", null, \"phase-head\");", js)
        self.assertIn("state.openStep[s.name] === undefined ? !!s.current : state.openStep[s.name]", js)
        self.assertIn('state.details[ev.stage] = ev.rows || [];', js)
        for key in ("groupFind:", "groupRead:", "groupSearch:", "groupFinish:", "stepOpen:", "stepClose:"):
            self.assertIn(key, self.read("app.js"))

    def test_the_page_offers_the_button_and_the_cli_waits(self):  # U-UI-47
        js = self.js_without_comments()
        # The scan screen is a control before it is a view.
        self.assertIn("if (!state.started && !state.findings) return box.append(renderReady(wrap));", js)
        self.assertIn('post("/api/start", {})', js)
        for key in ("scanReady:", "scanReadySub:", "scanStart:", "scanStarting:", "scanStartFailed:"):
            self.assertIn(key, self.read("app.js"))
        # A page that reconnects mid-scan, or opens a finished one, does not offer to start it again.
        self.assertIn("state.started = !!s.started || !!s.finished;", js)
        self.assertIn("state.started = !!ev.started || !!ev.finished;", js)
        # The scanner waits for the press, and says so rather than looking hung.
        cli_src = self.read_module("cli.py")
        self.assertIn("view.state.wait_for_start(", cli_src)
        self.assertIn("Waiting for Start scan in the browser view.", cli_src)
        self.assertLess(cli_src.index("view.state.wait_for_start("), cli_src.index("for k, name in enumerate"))

    def test_the_list_is_ordered_by_what_it_opens(self):  # U-UI-41
        """The browser view and the report must not disagree about what to do first."""
        from afterprompt import impact
        js = self.js_without_comments()
        # The bands, in the scanner's order, with the scanner's words. A rename in impact.py fails here.
        self.assertIn('const IMPACT = ["money", "data", "access", "service"];', js)
        self.assertEqual(list(impact.RANKS), ["money", "data", "access", "service"])
        for band in impact.RANKS:
            self.assertIn(impact.LABELS[band], js, f"{band}: label is not the one impact.py uses")
            self.assertIn(impact.NOTES[band], js, f"{band}: note is not the one impact.py uses")
        # Grouping by band orders by the band, not by how much there is in it.
        self.assertIn("rank = key === \"review\" ? IMPACT.length : IMPACT.indexOf(key);", js)
        self.assertIn("a.rank !== null ? a.rank - b.rank : 0", js)
        # A finding from an older scan has no band; it sorts last rather than loudest.
        self.assertIn("IMPACT.includes(f.impact) ? f.impact : null", js)

    def test_repeats_fold_but_never_the_ones_to_rotate(self):  # U-UI-42
        """One file holding thirty of a kind used to fill the list and push everything else off it."""
        js = self.js_without_comments()
        self.assertIn("const FOLD_FROM = 3;", js)
        # The key is what the row shows: its kind and the one place it names.
        self.assertIn('section === "review" && place', js)
        self.assertIn("f.label", js[js.index("function foldKey"):js.index("function fold(")])
        # Below the threshold nothing is hidden, and a folded row opens.
        self.assertIn("row.members.length >= FOLD_FROM", js)
        self.assertIn("state.unfolded[row.key]", js)
        # Keyboard navigation only ever visits rows that are on screen.
        rows = js[js.index("function visibleRows()"):js.index("function renderFindings")]
        self.assertIn("state.unfolded[row.key]", rows)

    def test_the_first_three_are_named(self):  # U-UI-43
        js = self.js_without_comments()
        self.assertIn("const lead = (state.findings ? state.findings.rotate : []).slice(0, 3);", js)
        self.assertIn("state.findings.rotate.length > 3", js)      # a short list needs no lead
        for key in ("startHere:", "startHereWhy:"):
            self.assertIn(key, self.read("app.js"))

    def test_the_bands_are_drawn_from_tokens(self):  # U-UI-44
        css = self.read("app.css")
        band = css[css.index(".band {"):css.index(".row.fold")]
        for rule in (".band.money { background: var(--danger); }",
                     ".band.data { background: var(--warning); }",
                     ".band.access { background: var(--accent); }",
                     ".band.service { background: var(--text-tertiary); }"):
            self.assertIn(rule, band)

    def test_keyboard_contract(self):  # U-UI-24
        js = self.js_without_comments()
        for key in ('"ArrowDown"', '"ArrowUp"', '"j"', '"k"', '"Home"', '"End"', '"Enter"', '"Escape"'):
            self.assertIn(key, js, key)
        self.assertIn('$("list").focus()', js)
        for key in ('"ArrowRight"', '"ArrowLeft"', '" "'):         # collapse, expand, and tick without the mouse
            self.assertIn(key, js, key)
        self.assertIn("scrollIntoView", js)

    def test_selection_survives_live_updates(self):  # U-UI-25
        js = self.js_without_comments()
        self.assertIn("const before = state.selected;", js)
        self.assertIn("if (!all.includes(before)) state.selected = all[0] || null;", js)

    def test_states_are_distinguished(self):  # U-UI-26
        """Nothing yet, nothing found and it broke are three different sentences, each saying what happens next."""
        js = self.read("app.js")
        for key in ("scanRunningSub:", "nothingYet:", "nothing:", "connectionLost:", "refusedText:",
                    "tickFailed:", "needKey:", "settingsFailed:"):
            self.assertIn(key, js)
        self.assertNotIn("JSON.stringify(err", js)                 # never a raw exception in the interface


class LifecycleTests(TempDirTest):
    def test_should_stop(self):  # U-UI-14
        st = ui.State(self.tmp)
        now = st.started
        self.assertFalse(ui.should_stop(st, now + 10 ** 6))                 # never while the scan runs
        st.finished = True
        self.assertFalse(ui.should_stop(st, now + 10, grace=45, idle=1800))
        self.assertTrue(ui.should_stop(st, now + 1801, grace=45, idle=1800))  # nobody ever opened it
        st.last_beat = now + 100
        self.assertFalse(ui.should_stop(st, now + 140, grace=45, idle=1800))
        self.assertTrue(ui.should_stop(st, now + 146, grace=45, idle=1800))   # the tab was closed

    def test_wait_stops_the_server(self):  # U-UI-15
        st = ui.State(self.tmp)
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
            # Nothing happens until the page asks: the scanner is sitting on the Start screen.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/api/status", headers=h)
            self.assertFalse(json.loads(c.getresponse().read())["started"])
            c.close()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", "/api/start", body="{}",
                      headers=dict(h, **{"Content-Type": "application/json"}))
            self.assertEqual(c.getresponse().status, 200)
            c.close()
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


class LogoAndAboutTests(TempDirTest):
    """The application's own mark, the icons generated from it, and who the page says built it."""

    def setUp(self):
        super().setUp()
        self.state = ui.State(self.tmp)
        self.server = ui.Server(self.state).start()
        self.addCleanup(self.server.stop)

    def get(self, path, token=True):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Authorization": f"Bearer {self.server.token}"} if token else {}
        c.request("GET", path, None, headers)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_the_logo_pack_is_complete(self):  # U-UI-34
        logo = os.path.join(os.path.dirname(os.path.abspath(ui.__file__)), "assets", "logo")
        for name in ("afterprompt-mark.svg", "afterprompt-icon.svg", "afterprompt-icon-mono.svg",
                     "afterprompt-icon-maskable.svg", "favicon.ico", "apple-touch-icon.png", "README.md"):
            with self.subTest(name=name):
                self.assertTrue(os.path.exists(os.path.join(logo, name)), name)
        for size in (16, 32, 48, 64, 96, 128, 180, 192, 256, 512, 1024):
            with self.subTest(size=size):
                self.assertTrue(os.path.exists(os.path.join(logo, f"afterprompt-icon-{size}.png")))
        # The SVGs are the masters: the mark inherits the text colour, the badge carries the accent.
        with open(os.path.join(logo, "afterprompt-mark.svg"), encoding="utf-8") as fh:
            self.assertIn("currentColor", fh.read())
        with open(os.path.join(logo, "afterprompt-icon.svg"), encoding="utf-8") as fh:
            self.assertIn("#1f5fd0", fh.read())

    def test_the_favicon_holds_three_sizes(self):  # U-UI-35
        """Read straight out of the ICO directory: the suite depends on the standard library only."""
        logo = os.path.join(os.path.dirname(os.path.abspath(ui.__file__)), "assets", "logo")
        with open(os.path.join(logo, "favicon.ico"), "rb") as fh:
            blob = fh.read()
        reserved, kind, count = struct.unpack_from("<HHH", blob, 0)
        self.assertEqual((reserved, kind), (0, 1))
        sizes = sorted((blob[6 + i * 16] or 256, blob[7 + i * 16] or 256) for i in range(count))
        self.assertEqual(sizes, [(16, 16), (32, 32), (48, 48)])

    @unittest.skipUnless(shutil.which("google-chrome") or shutil.which("chromium"), "needs a browser to rasterise")
    def test_the_generated_icons_match_the_masters(self):  # U-UI-39
        """A mark edited in the SVG but not re-rendered would ship two different logos."""
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest("needs Pillow to compare the renders")
        tool = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(ui.__file__))), "tools",
                            "make_logo_pack.py")
        r = subprocess.run([sys.executable, tool, "--check"], capture_output=True, text=True, timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_page_serves_its_icons_and_nothing_else_from_that_folder(self):  # U-UI-36
        for path, ctype in (("/favicon.ico", "image/x-icon"), ("/logo/afterprompt-mark.svg", "image/svg+xml"),
                            ("/logo/afterprompt-icon.svg", "image/svg+xml"),
                            ("/logo/am-logo.png", "image/png"), ("/logo/am-logo-white.png", "image/png")):
            with self.subTest(path=path):
                status, headers, body = self.get(path, token=False)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], ctype)
                self.assertTrue(body)
        for path in ("/logo/README.md", "/logo/../ui.py", "/logo/am/am-logo-600.png", "/logo/"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)

    def test_about_states_what_it_can_count(self):  # U-UI-37
        from afterprompt import __version__, patterns
        status, _, body = self.get("/api/about")
        self.assertEqual(status, 200)
        about = json.loads(body)
        self.assertEqual(about["version"], __version__)
        self.assertEqual(about["patterns"], len(patterns.PATTERNS))
        self.assertGreaterEqual(about["tools"], 20)
        self.assertEqual(about["licence"], "FSL-1.1-ALv2")
        self.assertEqual(about["vendor"]["name"], "AM Consulting")
        self.assertTrue(about["vendor"]["url"].startswith("https://"))
        self.assertEqual(self.get("/api/about", token=False)[0], 401)

    def test_the_page_carries_the_mark_and_credits_am(self):  # U-UI-38
        here = os.path.join(os.path.dirname(os.path.abspath(ui.__file__)), "assets", "ui")
        with open(os.path.join(here, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn('rel="icon" href="/favicon.ico"', html)
        self.assertIn('rel="apple-touch-icon"', html)
        self.assertIn('viewBox="0 0 64 40"', html)       # the mark is inline, so it follows the theme
        with open(os.path.join(here, "app.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("aboutPoweredBy", js)
        self.assertIn("/logo/am-logo.png", js)
        self.assertIn("/logo/am-logo-white.png", js)     # the white mark for the dark background


class StatusApiTests(TempDirTest):
    """The endpoints behind the status control and the watchdog."""

    def setUp(self):
        super().setUp()
        self.state = ui.State(self.tmp)
        self.state.home = self.tmp
        self.server = ui.Server(self.state).start()
        self.addCleanup(self.server.stop)
        self.addCleanup(self.state.stop_watchdog)

    def req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Authorization": f"Bearer {self.server.token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        c.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        r = c.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        c.close()
        return out

    def test_a_status_is_set_and_comes_back_with_the_findings(self):  # U-UI-40
        h = "a1b2c3d4e5f60718"
        write_json(os.path.join(self.tmp, "findings.json"), {"rotate": [{"hash": h, "masked": "sk…1"}], "review": []})
        self.state.finish(os.path.join(self.tmp, "findings.json"))
        status, body = self.req("POST", "/api/status", {"hash": h, "status": "rotating"})
        self.assertEqual(status, 200)
        self.assertEqual(body["row"]["status"], "rotating")
        self.assertEqual(self.req("GET", "/api/findings")[1]["statuses"][h]["status"], "rotating")

    def test_a_status_the_product_does_not_have_is_refused(self):  # U-UI-41
        for bad in ({"hash": "a" * 16, "status": "solved"}, {"hash": "../etc", "status": "rotated"},
                    {"status": "rotated"}, {"hash": "a" * 16}):
            with self.subTest(body=bad):
                self.assertEqual(self.req("POST", "/api/status", bad)[0], 400)

    def test_a_recheck_reports_what_is_still_on_disk(self):  # U-UI-42
        from tests.samples import SecretFactory
        from afterprompt.util import sha16
        from afterprompt.vendor import value_part
        key = SecretFactory(31).sample("anthropic_key")
        write(os.path.join(self.tmp, "history.jsonl"), 'pasted %s here\n' % key)
        h = sha16(value_part("anthropic_key", key.encode()))
        finding = {"hash": h, "match_hashes": [sha16(key.encode())], "patterns": ["anthropic_key"],
                   "masked": "sk-ant…x", "locations": [{"display": "~/history.jsonl", "side": "linux",
                                                        "decoded": False}], "still_on_disk": []}
        write_json(os.path.join(self.tmp, "findings.json"), {"rotate": [finding], "review": []})
        self.state.finish(os.path.join(self.tmp, "findings.json"))
        status, body = self.req("POST", "/api/recheck", {"hash": h})
        self.assertEqual(status, 200)
        self.assertEqual(body["seen"][h]["state"], "present")
        # Clean the file the way someone would, and the answer changes.
        write(os.path.join(self.tmp, "history.jsonl"), "pasted [removed] here\n")
        self.assertEqual(self.req("POST", "/api/recheck", {"hash": h})[1]["seen"][h]["state"], "gone")
        self.assertEqual(self.req("GET", "/api/findings")[1]["statuses"][h]["seen"]["state"], "gone")

    def test_the_page_is_told_when_the_watchdog_changes_its_mind(self):  # U-UI-43
        """A status the person set and a fact the watchdog observed are published as separate events."""
        events = []
        q = __import__("queue").Queue(maxsize=100)
        self.state.subscribers.append(q)
        self.state.set_status("b" * 16, "rotated")
        while not q.empty():
            events.append(q.get_nowait())
        self.assertEqual(events[0]["type"], "status")
        self.assertEqual(events[0]["row"]["status"], "rotated")
