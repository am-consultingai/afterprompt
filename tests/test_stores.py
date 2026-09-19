import json
import os
import stat
import time
from unittest import mock

from afterprompt import known, stores
from afterprompt.util import sha16
from tests.helpers import TempDirTest, jwt, make_cfg, no_resource_warnings, requires_rg, write, requires_posix
from tests.samples import SecretFactory


class StoresTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.f = SecretFactory(11)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)

    def collect(self, platform="linux", win=None, project_dirs=(), **kw):
        cfg = make_cfg(self.tmp, platform, self.home, windows_home=win, **kw)
        srcs = {"platform": platform, "windows_home": win, "project_dirs": list(project_dirs)}
        values, stats = stores.collect(cfg, srcs)
        return {v.decode(): e for v, e in values.items()}, stats, cfg

    def s(self, n=24):
        return self.f.chars("a", n)

    def test_aws(self):  # U-STO-1
        sec, tok = self.s(40), self.s(120)
        write(os.path.join(self.home, ".aws", "credentials"),
              f"[default]\naws_access_key_id = AKIA{self.f.chars('U', 16)}\naws_secret_access_key = {sec}\n"
              f"aws_session_token={tok}\nregion = eu-west-1\n")
        vals, _, _ = self.collect()
        self.assertIn(sec, vals)
        self.assertIn(tok, vals)
        self.assertFalse(any(v.startswith("AKIA") for v in vals))

    def test_netrc(self):  # U-STO-2
        a, b, c = self.s(), self.s(), self.s()
        write(os.path.join(self.home, ".netrc"), f"machine a.com\n  login me\n  password {a}\n"
                                                 f"machine b.com login me password {b}\n")
        write(os.path.join(self.home, "_netrc"), f"machine c.com login me password {c}\n")
        vals, _, _ = self.collect()
        for v in (a, b, c):
            self.assertIn(v, vals)

    def test_npmrc(self):  # U-STO-3
        t = self.f.chars("u", 36)
        write(os.path.join(self.home, ".npmrc"), f"//registry.npmjs.org/:_authToken={t}\nsave-exact=true\n")
        vals, _, _ = self.collect()
        self.assertIn(t, vals)

    def test_pypirc(self):  # U-STO-4
        t = self.s(30)
        write(os.path.join(self.home, ".pypirc"), f"[pypi]\nusername = __token__\npassword = {t}\n")
        self.assertIn(t, self.collect()[0])

    def test_git_credentials(self):  # U-STO-5
        url = f"https://me:{self.s(20)}@github.com"
        write(os.path.join(self.home, ".git-credentials"), url + "\n")
        self.assertIn(url, self.collect()[0])

    def test_pgpass(self):  # U-STO-6
        pw = self.s(18)
        write(os.path.join(self.home, ".pgpass"), f"db.host.com:5432:app:me:{pw}\n")
        self.assertIn(pw, self.collect()[0])

    def test_kube(self):  # U-STO-7
        tok, key = self.s(60), self.f.chars("b", 200)
        write(os.path.join(self.home, ".kube", "config"),
              f"users:\n- name: me\n  user:\n    token: {tok}\n    client-key-data: {key}\n")
        vals = self.collect()[0]
        self.assertIn(tok, vals)
        self.assertIn(key, vals)

    def test_gh_hosts(self):  # U-STO-8
        tok = "gho_" + self.s(36)
        write(os.path.join(self.home, ".config", "gh", "hosts.yml"), f"github.com:\n    oauth_token: {tok}\n    user: me\n")
        self.assertIn(tok, self.collect()[0])

    def test_docker_bom(self):  # U-STO-9
        auth = self.f.chars("b", 40)
        write(os.path.join(self.home, ".docker", "config.json"),
              "﻿" + json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": auth}}}))
        self.assertIn(auth, self.collect()[0])

    def test_gcloud(self):  # U-STO-10
        rt, cs = "1//0" + self.f.chars("u", 60), "GOCSPX-" + self.f.chars("u", 28)
        cid = f"{self.f.chars('d', 12)}-{self.f.chars('l', 32)}.apps.googleusercontent.com"
        write(os.path.join(self.home, ".config", "gcloud", "application_default_credentials.json"),
              json.dumps({"client_id": cid, "client_secret": cs, "refresh_token": rt, "type": "authorized_user"}))
        vals = self.collect()[0]
        self.assertIn(rt, vals)
        self.assertIn(cs, vals)
        self.assertNotIn(cid, vals)

    def test_msal_cache(self):  # U-STO-11
        secret = self.s(40)
        uid = "123e4567-e89b-12d3-a456-426614174000"
        write(os.path.join(self.home, ".azure", "msal_token_cache.json"),
              json.dumps({"RefreshToken": {"x": {"secret": secret, "home_account_id": uid}}}))
        vals = self.collect()[0]
        self.assertIn(secret, vals)
        self.assertNotIn(uid, vals)

    def test_env_files(self):  # U-STO-12
        a, b, c = self.s(), self.s(), self.s()
        proj = os.path.join(self.home, "code", "app")
        write(os.path.join(proj, ".env"), f"# c\nexport API_KEY=\"{a}\"\nSECRET_TOKEN='{b}'\nPORT=3000\n")
        write(os.path.join(proj, ".env.example"), f"API_KEY={c}\n")
        write(os.path.join(proj, ".env.sample"), f"API_KEY={c}\n")
        vals, stats, _ = self.collect(project_dirs=[proj])
        self.assertIn(a, vals)
        self.assertIn(b, vals)
        self.assertNotIn(c, vals)

    def test_ssh(self):  # U-STO-13
        body = self.f.chars("b", 400)
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(body[i:i + 70] for i in range(0, 400, 70)) + \
              "\n-----END OPENSSH PRIVATE KEY-----\n"
        write(os.path.join(self.home, ".ssh", "id_ed25519"), pem)
        write(os.path.join(self.home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 " + self.f.chars("b", 68))
        vals = self.collect()[0]
        self.assertIn(body[40:104], vals)
        self.assertEqual(len([v for v in vals if v in body]), 2)

    def test_certificate_only_pem(self):  # U-STO-14
        cert = "-----BEGIN CERTIFICATE-----\n" + "\n".join(self.f.chars("b", 64) for _ in range(5)) + \
               "\n-----END CERTIFICATE-----\n"
        write(os.path.join(self.home, "certs", "cacert.pem"), cert)
        _, stats, _ = self.collect()
        self.assertEqual(stats["values"], 0)

    def test_design_tokens_not_named(self):  # U-STO-15
        self.assertFalse(stores.is_named("brand-tokens.json"))
        self.assertTrue(stores.is_named("drive_token.json"))
        self.assertTrue(stores.is_named("client_secret_123.json"))
        self.assertFalse(stores.is_named("secrets_manager.py"))

    def test_cookies(self):  # U-STO-16
        v1, v2 = self.f.chars("u", 40), self.f.chars("u", 40)
        write(os.path.join(self.home, "dl", "site.cookies.json"),
              json.dumps([{"name": "__Secure-1PSIDCC", "value": v1, "domain": ".google.com"}]))
        write(os.path.join(self.home, "dl", "cookies.txt"),
              f"# Netscape HTTP Cookie File\n.example.org\tTRUE\t/\tTRUE\t0\tsid\t{v2}\n")
        vals = self.collect()[0]
        self.assertIn(v1, vals)
        self.assertIn(v2, vals)
        self.assertNotIn("__Secure-1PSIDCC", vals)

    def test_claude_json(self):  # U-STO-17
        k = self.f.sample("brave_api_key")
        write(os.path.join(self.home, ".claude.json"), json.dumps(
            {"userID": self.s(40), "mcpServers": {"b": {"env": {"BRAVE_API_KEY": k}, "headers": {"X": self.s(30)}}}}))
        vals = self.collect()[0]
        self.assertIn(k, vals)
        self.assertEqual(len(vals), 2)

    def test_rejections(self):  # U-STO-18
        c = stores.Collector()
        for v in ("your_api_key_here_123", "aaaaaaaaaaaaaaaa", "SOME_ENV_NAME_HERE", "me@example-mail.com",
                  "123-abc.apps.googleusercontent.com", "short"):
            c.add(v, "s", "k")
        self.assertEqual(c.values, {})

    def test_jwt_expiry(self):  # U-STO-19
        c = stores.Collector()
        old, new = jwt(self.f, int(time.time()) - 60), jwt(self.f, int(time.time()) + 3600)
        c.add(old, "s", "k")
        c.add(new, "s", "k")
        self.assertEqual(list(c.values), [new.encode()])
        self.assertEqual(c.expired, 1)

    def test_prefixes(self):  # U-STO-20
        distinctive = self.s(60).encode()
        values = {distinctive: [], b"eyJhbGciOiJIUzI1NiJ9" + self.s(40).encode(): [],
                  b"postgres://user:" + self.s(40).encode(): [],
                  b"DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + self.s(60).encode(): []}
        pref = stores.prefixes(values)
        self.assertEqual(list(pref), [distinctive[:24]])

    @requires_posix  # the macOS keychain is read through a /bin/sh helper
    def test_keychain(self):  # U-STO-21
        tok = "sk-ant-oat01-" + self.f.chars("u", 90)
        bindir = os.path.join(self.tmp, "bin")
        write(os.path.join(bindir, "security"), f"#!/bin/sh\necho '{json.dumps({'claudeAiOauth': {'accessToken': tok}})}'\n")
        os.chmod(os.path.join(bindir, "security"), stat.S_IRWXU)
        with mock.patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ["PATH"]}):
            vals, stats, _ = self.collect("macos", include_keychain=True)
        self.assertIn(tok, vals)
        self.assertEqual(stats["keychain"], "included")
        write(os.path.join(bindir, "security"), "#!/bin/sh\nexit 44\n")
        with mock.patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ["PATH"]}):
            _, stats, _ = self.collect("macos", include_keychain=True)
        self.assertTrue(stats["keychain"].startswith("failed"))

    def test_walk_budget(self):  # U-STO-22
        write(os.path.join(self.home, "a", "b", ".env"), f"API_KEY={self.s()}\n")
        _, stats, _ = self.collect(walk_budget=-1)
        self.assertIn(self.home, stats["walk_truncated"])

    def test_windows_side_stores(self):  # U-STO-23
        win = os.path.join(self.tmp, "Users", "me")
        rt = "1//0" + self.f.chars("u", 60)
        tok = "gho_" + self.s(36)
        write(os.path.join(win, "AppData", "Roaming", "gcloud", "credentials.db.json"), json.dumps({"refresh_token": rt}))
        write(os.path.join(win, "AppData", "Roaming", "GitHub CLI", "hosts.yml"), f"github.com:\n  oauth_token: {tok}\n")
        vals = self.collect("wsl", win=win)[0]
        self.assertIn(rt, vals)
        self.assertIn(tok, vals)


@requires_rg
class KnownTests(TempDirTest):
    def test_search_and_index(self):  # U-KNOWN-1, U-KNOWN-2
        f = SecretFactory(12)
        home = os.path.join(self.tmp, "home")
        full = f.chars("a", 60)
        other = f.chars("a", 30)
        write(os.path.join(home, "app", ".env"), f"API_KEY={full}\nDB_PASSWORD={other}\n")
        data = os.path.join(self.tmp, "data")
        write(os.path.join(data, "a.jsonl"), f"exact {full} and truncated {full[:30]}...\n")
        cfg = make_cfg(self.tmp, "linux", home)
        srcs = {"platform": "linux", "windows_home": None, "project_dirs": [os.path.join(home, "app")]}
        with no_resource_warnings(self):
            stats = known.run(cfg, srcs, [data, os.path.join(home, "app")])
        with open(cfg.w("known.jsonl"), encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh]
        self.assertEqual({(r["vh"], r["prefix"]) for r in rows}, {(sha16(full), False), (sha16(full), True)})
        self.assertFalse(any(r["f"].endswith(".env") for r in rows))
        with open(cfg.w("live_index.json"), encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn(full, raw)
        idx = json.loads(raw)
        self.assertEqual(idx[sha16(full)]["stores"][0]["key"], "API_KEY")
        self.assertEqual(stats["values"], 2)


class RuleTests(TempDirTest):
    def test_key_tail_rule(self):  # U-STO-24
        for k in ("ANTHROPIC_API_KEY", "client-key-data", "SECRET_KEY_BASE", "claudeAiOauth.accessToken", "DB_PASSWORD"):
            self.assertTrue(stores.key_is_secret(k), k)
        for k in ("mcpNeedsAuthNoticed[0]", "private_key_id", "token_type", "expires_in", "session_state"):
            self.assertFalse(stores.key_is_secret(k), k)

    def test_value_rejections(self):  # U-STO-25
        c = stores.Collector()
        for v in ("plugin:linear:linear", "billers_password", "postgres://app:Xy7pQ2mL9w@localhost:5432/db",
                  "postgres://app:Xy7pQ2mL9w@db/app"):
            c.add(v, "s", "k")
        self.assertEqual(c.values, {})
        c.add("postgres://app:Xy7pQ2mL9w@db.prod.acme-host.com/app", "s", "k")
        self.assertEqual(len(c.values), 1)

    def test_ai_tool_folders_not_stores(self):  # U-STO-26
        home = os.path.join(self.tmp, "home")
        write(os.path.join(home, ".claude", "sessions", "1012.abc.key"), "Zx8Qw2Lp9Rt5Mn3Vb7Kc\n")
        write(os.path.join(home, "proj", ".cursor", "secrets.json"), json.dumps({"api_key": "Zx8Qw2Lp9Rt5Mn3Vb7Kd"}))
        cfg = make_cfg(self.tmp, "linux", home)
        values, stats = stores.collect(cfg, {"platform": "linux", "windows_home": None, "project_dirs": []})
        self.assertEqual(values, {})

