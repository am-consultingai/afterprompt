"""Saved defaults for the next scan (settings.json), the settings API, and the data behind the credential cards."""
import json
import os
import re
import unittest
from unittest import mock

from afterprompt import cli, config, patterns, settings, ui
from tests.helpers import TempDirTest, write

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(ui.__file__)), "assets", "ui")


class FieldTests(TempDirTest):
    def test_defaults_are_the_shipped_behaviour(self):  # U-SET-1
        self.assertEqual(settings.load(self.tmp), settings.DEFAULTS)
        self.assertEqual(settings.DEFAULTS["mode"], "quick")
        self.assertIs(settings.DEFAULTS["workers"], None)          # automatic
        self.assertIs(settings.DEFAULTS["keep_work"], False)       # decoded plaintext is not kept by default

    def test_every_field_explains_itself(self):  # U-SET-2
        for f in settings.FIELDS:
            with self.subTest(field=f.key):
                self.assertTrue(f.label and f.help.endswith(".") and len(f.help) > 25)
                self.assertIn(f.scope, ("scan", "view"))
                self.assertIn(f.kind, ("bool", "choice", "number", "number_or_auto"))
                if f.kind == "choice":
                    self.assertTrue(f.choices and any(f.default == v for v, _ in f.choices))
                if f.kind in ("number", "number_or_auto"):
                    self.assertTrue(f.minimum is not None and f.maximum > f.minimum)

    def test_values_are_checked_before_they_are_saved(self):  # U-SET-3
        self.assertIsNotNone(settings.set_value(self.tmp, "mode", "deep"))
        self.assertEqual(settings.load(self.tmp)["mode"], "deep")
        for key, bad in (("mode", "sideways"), ("max_disk_gb", 0), ("max_disk_gb", 10 ** 9), ("max_disk_gb", "lots"),
                         ("workers", 999), ("keep_work", "yes"), ("nonexistent", 1), ("group_by", "colour")):
            with self.subTest(key=key, value=bad):
                self.assertIsNone(settings.set_value(self.tmp, key, bad))
        self.assertEqual(settings.load(self.tmp)["mode"], "deep")   # a refused change leaves the file alone

    def test_automatic_is_a_value(self):  # U-SET-4
        self.assertIsNotNone(settings.set_value(self.tmp, "workers", 4))
        self.assertEqual(settings.load(self.tmp)["workers"], 4)
        self.assertIsNotNone(settings.set_value(self.tmp, "workers", "auto"))
        self.assertIsNone(settings.load(self.tmp)["workers"])

    def test_a_broken_file_degrades_to_defaults(self):  # U-SET-5
        write(settings.path(self.tmp), "{ not json")
        self.assertEqual(settings.load(self.tmp), settings.DEFAULTS)
        write(settings.path(self.tmp), json.dumps({"values": {"mode": "deep", "max_disk_gb": "huge",
                                                              "evil": {"$ref": "/etc/passwd"}}}))
        loaded = settings.load(self.tmp)
        self.assertEqual(loaded["mode"], "deep")                    # the good value survives
        self.assertEqual(loaded["max_disk_gb"], settings.DEFAULTS["max_disk_gb"])
        self.assertNotIn("evil", loaded)


class ConfigMergeTests(TempDirTest):
    def cfg(self, argv, env=None):
        args = cli.parser().parse_args(argv)
        with mock.patch.dict(os.environ, dict(env or {}, AFTERPROMPT_DIR=self.tmp)):
            return config.from_args(args, os.path.join(self.tmp, "run"))

    def test_saved_settings_become_the_defaults(self):  # U-SET-6
        settings.save(self.tmp, dict(settings.DEFAULTS, mode="deep", max_disk_gb=25, keep_work=True, sarif=True,
                                     no_wsl=True, workers=3))
        cfg = self.cfg([])
        self.assertEqual(cfg.mode, "deep")
        self.assertEqual(cfg.max_disk_bytes, 25 * config.GIB)
        self.assertTrue(cfg.keep_work and cfg.sarif and cfg.no_wsl)
        self.assertEqual(cfg.workers, 3)

    def test_a_flag_still_wins(self):  # U-SET-7
        """Including a flag whose value happens to equal the shipped default: --quick is a choice, not
        silence."""
        settings.save(self.tmp, dict(settings.DEFAULTS, mode="deep", max_disk_gb=25))
        cfg = self.cfg(["--max-disk", "3", "--quick"])
        self.assertEqual(cfg.max_disk_bytes, 3 * config.GIB)
        self.assertEqual(cfg.mode, "quick")

    def test_a_settings_file_from_an_older_version_still_loads(self):  # U-SET-21
        """It will still carry "theme", which no longer exists: an unknown key must not break the scan."""
        settings.save(self.tmp, dict(settings.DEFAULTS, mode="deep"))
        path = os.path.join(self.tmp, "settings.json")
        with open(path, encoding="utf-8") as fh:
            saved = json.load(fh)
        saved["theme"] = "am"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(saved, fh)
        self.assertEqual(settings.load(self.tmp)["mode"], "deep")
        self.assertNotIn("theme", settings.load(self.tmp))
        self.assertEqual(self.cfg([]).mode, "deep")

    def test_a_worker_ignores_them(self):  # U-SET-8
        """The host passes a worker the run's options explicitly; the distro's own saved settings must not apply."""
        settings.save(self.tmp, dict(settings.DEFAULTS, mode="deep", keep_work=True))
        cfg = self.cfg(["--worker", "--windows-home", "none"])
        self.assertEqual(cfg.mode, "quick")
        self.assertFalse(cfg.keep_work)


class SettingsApiTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.state = ui.State(self.tmp)
        self.server = ui.Server(self.state).start()
        self.addCleanup(self.server.stop)

    def req(self, method, path, body=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Authorization": f"Bearer {self.server.token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        c.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        r = c.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        c.close()
        return out

    def test_fields_values_and_defaults(self):  # U-SET-9
        status, body = self.req("GET", "/api/settings")
        self.assertEqual(status, 200)
        self.assertEqual({f["key"] for f in body["fields"]}, set(settings.DEFAULTS))
        self.assertEqual(body["values"], settings.DEFAULTS)
        self.assertEqual(body["defaults"], settings.DEFAULTS)
        self.assertTrue(body["path"].endswith("settings.json"))

    def test_instant_apply_and_refusal(self):  # U-SET-10
        status, body = self.req("POST", "/api/settings", {"key": "mode", "value": "deep"})
        self.assertEqual(status, 200)
        self.assertEqual(body["values"]["mode"], "deep")
        self.assertEqual(settings.load(self.tmp)["mode"], "deep")
        for bad in ({"key": "mode", "value": "sideways"}, {"key": "../etc", "value": 1}, {"value": 1},
                    {"key": "workers", "value": 10 ** 6}):
            with self.subTest(body=bad):
                self.assertEqual(self.req("POST", "/api/settings", bad)[0], 400)
        self.assertEqual(settings.load(self.tmp)["mode"], "deep")


class ReferenceDataTests(unittest.TestCase):
    """The vendor marks and the rotation guidance the cards are built from."""

    def load(self, name):
        with open(os.path.join(UI_DIR, name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_every_pattern_vendor_can_be_shown(self):  # U-SET-11
        v = self.load("vendors.json")
        self.assertEqual(v["patterns"], patterns.VENDORS)
        for vendor in set(patterns.VENDORS.values()):
            with self.subTest(vendor=vendor):
                # Either a mark we may redistribute, or a monogram: never a brand's mark they asked us to drop.
                self.assertTrue(vendor in v["icons"] or vendor in v["monogram_only"])
        for vendor, art in v["icons"].items():
            self.assertTrue(art["path"].startswith(("M", "m")), vendor)
        self.assertIn("Simple Icons", v["about"] + v["source"])

    def test_rotation_guidance_is_sourced(self):  # U-SET-12
        r = self.load("rotation.json")
        vendors = set(patterns.VENDORS.values())
        for name, g in r["vendors"].items():
            with self.subTest(vendor=name):
                self.assertIn(name, vendors, "guidance for a vendor no pattern maps to")
                self.assertTrue(g["steps"] and all(s.strip().endswith(".") for s in g["steps"]))
                self.assertIn(g["confidence"], ("verified", "partly verified"))
                self.assertTrue(g["source"].startswith("https://"))
                # What the vendor's procedure costs you: an overlap window, or callers breaking on revocation.
                self.assertIn(g["downtime"], ("overlap", "immediate"))
                for link in ("console", "audit"):
                    if link in g:
                        self.assertTrue(g[link]["url"].startswith("https://"), link)
                        self.assertTrue(g[link]["where"])

    def test_the_vendors_that_matter_most_are_covered(self):  # U-SET-19
        """The credentials people actually leak: guidance, not just a revoke link."""
        r = self.load("rotation.json")
        for vendor in ("Anthropic", "OpenAI", "AWS", "GitHub", "Google", "Google Cloud", "Azure", "GitLab",
                       "Hugging Face", "npm", "Docker Hub"):
            with self.subTest(vendor=vendor):
                self.assertIn(vendor, r["vendors"])

    def test_a_vendor_can_answer_per_finding_kind(self):  # U-SET-20
        """Google issues API keys and sets session cookies; a cookie must not be told to rotate a key."""
        r = self.load("rotation.json")
        kinds = set(r["generic"])
        cookie = r["vendors"]["Google"]["kinds"]["session_cookie"]
        self.assertTrue(any("sign out" in s.lower() for s in cookie["steps"]))
        self.assertFalse(any("Rotate key" in s for s in cookie["steps"]))
        for name, g in r["vendors"].items():
            for kind, special in (g.get("kinds") or {}).items():
                with self.subTest(vendor=name, kind=kind):
                    self.assertIn(kind, kinds, "a finding kind the view never asks for")
                    self.assertTrue(special["steps"] and all(s.strip().endswith(".") for s in special["steps"]))
                    self.assertIn(special.get("downtime", g["downtime"]), ("overlap", "immediate"))

    def test_every_finding_kind_has_generic_steps(self):  # U-SET-13
        r = self.load("rotation.json")
        for kind in ("live_credential", "pattern", "configuration", "session_cookie", "private_key",
                     "connection_string", "prompt", "entropy"):
            with self.subTest(kind=kind):
                g = r["generic"][kind]
                self.assertTrue(g["headline"] and g["steps"])
        # A connection string leaks the address as well as the password, and rotating cannot take that back.
        conn = " ".join(r["generic"]["connection_string"]["steps"] + [r["generic"]["connection_string"]["headline"]])
        self.assertIn("host", conn)
        # A passphrase is no defence once the key's plain text has been pasted into a transcript.
        self.assertIn("passphrase", r["generic"]["private_key"]["headline"])
        # A weak match with a confident vendor procedure attached has to say "confirm this is yours" first.
        for kind in ("entropy", "prompt"):
            self.assertTrue(r["generic"][kind]["confirm_first"].strip().endswith("."), kind)
        # Ending the session is the fix for a cookie; a password change on its own may not be.
        self.assertTrue(any("password" in s for s in r["generic"]["session_cookie"]["steps"]))
        self.assertTrue(any("invalidates the cookie" in s for s in r["generic"]["session_cookie"]["steps"]))
        # The two things that hold whatever the credential is.
        self.assertTrue(any("already sent to the model vendor" in u for u in r["universal"]))
        self.assertTrue(any("Revoke first" in u for u in r["universal"]))

    def test_no_secret_shaped_text_in_the_data(self):  # U-SET-14
        for name in ("rotation.json", "vendors.json"):
            with open(os.path.join(UI_DIR, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertFalse(re.search(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})", text), name)


class ProgressTests(TempDirTest):
    """Stages that can count publish it; the view is the only listener, and there is none by default."""

    def test_no_sink_no_cost(self):  # U-SET-15
        from afterprompt import progress
        progress.set_sink(None)
        progress.emit("manifest", 10, None, "files")          # must not raise with nobody listening

    def test_sink_receives_and_survives_a_bad_listener(self):  # U-SET-16
        from afterprompt import progress
        seen = []
        progress.set_sink(lambda *a: seen.append(a))
        self.addCleanup(progress.set_sink, None)
        progress.emit("vendor_raw", 12, 140, "16 matches so far")
        self.assertEqual(seen, [("vendor_raw", 12, 140, "16 matches so far")])
        progress.set_sink(lambda *a: 1 / 0)                   # a broken view must never break a scan
        progress.emit("vendor_raw", 13, 140, None)

    def test_pool_reports_each_item(self):  # U-SET-17
        from afterprompt import pool, progress
        from tests.helpers import make_cfg
        seen = []
        progress.set_sink(lambda *a: seen.append(a))
        self.addCleanup(progress.set_sink, None)
        cfg = make_cfg(self.tmp, "linux", workers=1)
        items = [(i, os.path.join(self.tmp, f"o{i}")) for i in range(3)]
        pool.run_pool(_touch, items, "decode", lambda it: os.path.exists(it[1]), lambda it, why: None, cfg)
        self.assertEqual([(s, d, t) for s, d, t, _ in seen], [("decode", 1, 3), ("decode", 2, 3), ("decode", 3, 3)])

    def test_the_pool_label_maps_to_its_stage(self):  # U-SET-18
        """The decode pool publishes as "decode"; the stage the user sees is "expand"."""
        self.assertEqual(cli.PROGRESS_STAGE["decode"], "expand")
        self.assertIn("expand", cli.DESCRIPTIONS)


def _touch(item):
    with open(item[1], "w", encoding="utf-8") as fh:
        fh.write("x")
