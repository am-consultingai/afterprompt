"""M5: a credential stored in one environment and leaked in another is found, in both directions. The values
travel over worker pipes only: never argv, never a file, and a resumed run collects them again."""
import base64
import io
import json
import os
import sys
from unittest import mock

from afterprompt import cli, known
from afterprompt.util import mask, sha16
from tests.helpers import Fixture, TempDirTest, jsonl, make_cfg, requires_rg, run_dirs, write
from tests.samples import SecretFactory


class ExchangeTests(TempDirTest):
    def test_round_trip_names_the_environment(self):  # U-X-1
        v = b"AKIA" + b"Q" * 16
        items = known.export_values({v: [("/home/me/.aws/credentials", "aws_access_key_id", False)]}, "/home/me")
        self.assertEqual(items[0]["e"][0][0], "~/.aws/credentials")
        back = known.import_values(items, "Ubuntu")
        self.assertEqual(back, {v: [("[Ubuntu] ~/.aws/credentials", "aws_access_key_id", False)]})

    def test_hostile_input_is_dropped(self):  # U-X-2
        good = {"v": base64.b64encode(b"x" * 20).decode(), "e": [["s", "k", False]]}
        items = [{"v": "!!not base64!!", "e": [["s", "k", False]]}, {"v": base64.b64encode(b"short").decode(),
                 "e": [["s", "k", 0]]}, {"e": []}, "string", {"v": good["v"], "e": "nope"},
                 {"v": base64.b64encode(b"y" * 9000).decode(), "e": [["s", "k", False]]}, good]
        self.assertEqual(list(known.import_values(items, "X")), [b"x" * 20])
        self.assertEqual(known.import_values(None, "X"), {})

    @requires_rg
    def test_known_search_uses_foreign_values(self):  # U-X-3
        home = os.path.join(self.tmp, "home")
        f = SecretFactory(8)
        foreign_key = f.sample("github_token")
        data = os.path.join(self.tmp, "data")
        write(os.path.join(data, "s.jsonl"), f"remote set with {foreign_key}\n")
        cfg = make_cfg(self.tmp, "linux", home)
        srcs = {"platform": "linux", "windows_home": None, "project_dirs": []}
        foreign = {foreign_key.encode(): [("[Box] ~/.config/gh/hosts.yml", "oauth_token", False)]}
        stats = known.run(cfg, srcs, [data], foreign=foreign)
        self.assertEqual(stats["foreign_values"], 1)
        with open(cfg.w("known.jsonl"), encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh]
        self.assertEqual({r["vh"] for r in rows}, {sha16(foreign_key)})
        with open(cfg.w("live_index.json"), encoding="utf-8") as fh:
            idx = json.load(fh)
        self.assertEqual(idx[sha16(foreign_key)]["stores"][0]["store"], "[Box] ~/.config/gh/hosts.yml")
        self.assertNotIn(foreign_key, json.dumps(idx))


@requires_rg
class ValuesOnlyWorkerTests(TempDirTest):
    def test_values_only_keeps_nothing(self):  # U-X-4
        fx = Fixture(self.tmp, "linux")
        out = io.StringIO()
        with mock.patch.dict(os.environ, fx.env()), mock.patch("sys.stdout", out):
            code = cli.main(["--worker", "--values-only", "--windows-home", "none"])
        self.assertEqual(code, 0)
        msgs = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual([m["type"] for m in msgs], ["result"])
        vals = known.import_values(msgs[0]["values"], "Box")
        self.assertIn(fx.s["F1"].encode(), vals)                      # the key in the fixture's .env
        worker_base = os.path.join(fx.base, "worker")
        self.assertEqual([d for d in os.listdir(worker_base) if d != "bin"], [])   # no run folder, no temp left

    def test_worker_imports_values_from_stdin_not_argv(self):  # U-X-5
        fx = Fixture(self.tmp, "linux", clean=True)
        f = SecretFactory(77)
        host_key = f.sample("stripe_secret_key")
        jsonl(os.path.join(fx.home, ".claude", "projects", "p", "x.jsonl"),
              [{"type": "user", "message": {"content": f"charge with {host_key}"}}])
        payload = json.dumps({"from": "Windows", "values": known.export_values(
            {host_key.encode(): [("C:\\Users\\me\\app\\.env", "STRIPE_KEY", False)]})}) + "\n"
        out = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(payload.encode()))
        with mock.patch.dict(os.environ, fx.env()), mock.patch("sys.stdout", out), mock.patch("sys.stdin", stdin):
            code = cli.main(["--worker", "--import-values", "--windows-home", "none"])
        self.assertEqual(code, cli.EXIT_ROTATE)
        result = [json.loads(l) for l in out.getvalue().splitlines()][-1]
        r = {x["masked"]: x for x in result["findings"]["rotate"]}[mask(host_key)]
        self.assertEqual(r["category"], "live_credential")
        self.assertEqual(r["still_on_disk"], [{"store": "[Windows] C:\\Users\\me\\app\\.env", "key": "STRIPE_KEY"}])
        run = os.path.join(fx.base, "worker", "runs", os.listdir(os.path.join(fx.base, "worker", "runs"))[0])
        for dp, _, fns in os.walk(run):
            for fn in fns:
                with open(os.path.join(dp, fn), "rb") as fh:
                    self.assertNotIn(host_key.encode(), fh.read(), fn)


@requires_rg
class BothDirectionsTests(TempDirTest):
    """Host and Box each store a key the other leaked into its AI history."""

    def setUp(self):
        super().setUp()
        self.host = Fixture(os.path.join(self.tmp, "host"), "linux", clean=True)
        self.box = Fixture(os.path.join(self.tmp, "box"), "linux", clean=True)
        f = SecretFactory(55)
        self.host_key, self.box_key = f.sample("github_token"), f.sample("huggingface_token")
        write(os.path.join(self.host.home, ".config", "gh", "hosts.yml"), f"github.com:\n  oauth_token: {self.host_key}\n")
        write(os.path.join(self.box.home, ".config", "gh", "hosts.yml"), f"huggingface.co:\n  oauth_token: {self.box_key}\n")
        jsonl(os.path.join(self.host.home, ".claude", "projects", "h", "s.jsonl"),
              [{"type": "user", "message": {"content": f"HF_TOKEN={self.box_key} please"}}])
        jsonl(os.path.join(self.box.home, ".claude", "projects", "b", "s.jsonl"),
              [{"type": "user", "message": {"content": f"GH_TOKEN={self.host_key} please"}}])

    def scan(self, **env):
        p = self.host.run(env=self.host.env(AFTERPROMPT_TEST_ENVS=f"Box={self.box.home}", **env))
        return p.returncode, p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")

    def check(self):
        d = self.host.findings()
        rotate = {r["masked"]: r for r in d["rotate"]}
        box_leak = rotate[mask(self.box_key)]               # stored in Box, leaked on the host
        self.assertEqual(box_leak["category"], "live_credential")
        self.assertEqual(box_leak["sides"], ["linux"])
        stores = [s["store"].replace("\\", "/") for s in box_leak["still_on_disk"]]   # "~\\" on Windows hosts
        self.assertIn("[Box] ~/.config/gh/hosts.yml", stores)
        host_leak = rotate[mask(self.host_key)]             # stored on the host, leaked in Box
        self.assertEqual(host_leak["category"], "live_credential")
        self.assertEqual(host_leak["sides"], ["env:Box"])
        self.assertTrue(any(s["store"].replace("\\", "/").endswith("~/.config/gh/hosts.yml")
                            for s in host_leak["still_on_disk"]))
        run = os.path.join(self.host.base, "runs", run_dirs(self.host.base)[-1])
        for dp, _, fns in os.walk(run):
            for fn in fns:
                with open(os.path.join(dp, fn), "rb") as fh:
                    data = fh.read()
                for v in (self.host_key, self.box_key):
                    self.assertNotIn(v.encode(), data, os.path.join(dp, fn))

    def test_found_in_both_directions(self):  # I-X-1
        code, out = self.scan()
        self.assertEqual(code, 10, out)
        self.check()
        for v in (self.host_key, self.box_key):
            self.assertNotIn(v, out)

    def test_still_found_after_a_resume(self):  # I-X-2
        code, out = self.scan(AFTERPROMPT_STOP_AFTER="environments")
        self.assertEqual(code, 130, out)
        code, out = self.scan()
        self.assertEqual(code, 10, out)
        self.assertIn("already done", out)
        self.check()
