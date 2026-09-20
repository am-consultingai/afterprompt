"""M7: Docker and Podman. Containers are read, images are inspected, and neither is ever run.

The tar arriving from `docker cp` came out of a filesystem this machine does not control, so most of
these tests are about what it is not allowed to do to us.
"""
import io
import json
import os
import subprocess
import tarfile
import unittest
from unittest import mock

from afterprompt import containers
from tests.helpers import TempDirTest


def tar_bytes(entries):
    """entries: [(name, data|None, kind)] — kind: file, dir, sym, link, dev."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                tar.addfile(info)
            elif kind == "link":
                info.type = tarfile.LNKTYPE
                info.linkname = data
                tar.addfile(info)
            elif kind == "dev":
                info.type = tarfile.CHRTYPE
                tar.addfile(info)
            else:
                payload = data.encode() if isinstance(data, str) else data
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class FakePopen:
    """A stand-in for `docker cp <c>:<path> -` that answers from a table of paths."""

    def __init__(self, table):
        self.table = table
        self.asked = []

    def __call__(self, cmd, stdout=None, stderr=None):
        ref = cmd[2]
        self.asked.append(ref)
        path = ref.split(":", 1)[1]
        blob = self.table.get(path)
        p = mock.Mock()
        p.stdout = io.BytesIO(blob if blob is not None else b"")
        p.stderr = io.BytesIO(b"" if blob is not None else b"Error: Could not find the file")
        p.wait.return_value = 0 if blob is not None else 1
        p.kill.return_value = None
        return p


def fake_run(table):
    def run(cmd, **kw):
        key = " ".join(cmd[:3])
        for prefix, out in table.items():
            if key.startswith(prefix):
                return subprocess.CompletedProcess(cmd, 0, out.encode(), b"")
        return subprocess.CompletedProcess(cmd, 1, b"", b"no such thing")
    return run


class ListingTests(unittest.TestCase):
    def test_containers_running_and_stopped(self):  # U-DOC-1
        run = fake_run({"docker ps": "api\tmyimg\trunning\ndb\tpostgres:16\texited\n"})
        rows = containers.containers("docker", run)
        self.assertEqual([r["name"] for r in rows], ["api", "db"])
        self.assertEqual(rows[1]["state"], "exited")

    def test_a_missing_cli_answers_none_not_an_empty_list(self):  # U-DOC-2
        """None means "could not ask"; [] means "asked, and there are none". The report says different things."""
        run = fake_run({})
        self.assertIsNone(containers.containers("docker", run))
        self.assertIsNone(containers.images("docker", run))

    def test_home_comes_from_the_configuration(self):  # U-DOC-3
        self.assertEqual(containers.home_of({"Env": ["HOME=/home/node", "X=1"]}), "/home/node")
        self.assertEqual(containers.home_of({"User": "node"}), "/home/node")
        self.assertEqual(containers.home_of({"User": "0"}), "/root")
        self.assertEqual(containers.home_of({}), "/root")
        self.assertEqual(containers.home_of({"Env": ["HOME=not-a-path"]}), "/root")

    def test_the_paths_asked_for_are_the_catalogue_s(self):  # U-DOC-4
        paths = containers.ai_paths("linux")
        self.assertIn(".claude", paths)
        self.assertIn(".config", paths)
        self.assertTrue(any(p.startswith(".config/") for p in paths[".config"]))
        for head in paths:
            self.assertFalse(head.startswith(("/", "$", "~")), head)


class TarSafetyTests(TempDirTest):
    """The tar came out of someone else's filesystem. It gets no benefit of the doubt."""

    def extract(self, entries, cap=containers.COPY_CAP):
        dest = os.path.join(self.tmp, "dest")
        popen = FakePopen({"/root/.claude": tar_bytes(entries)})
        written = containers.copy_path("c", "/root/.claude", dest, "docker", popen, cap)
        got = []
        for dp, _, fns in os.walk(dest):
            for fn in fns:
                got.append(os.path.relpath(os.path.join(dp, fn), dest).replace(os.sep, "/"))
        return written, sorted(got), dest

    def test_a_normal_folder_arrives(self):  # U-DOC-5
        written, got, dest = self.extract([(".claude", None, "dir"),
                                           (".claude/history.jsonl", "sk-test\n", "file")])
        self.assertEqual(got, [".claude/history.jsonl"])
        self.assertEqual(written, len("sk-test\n"))

    def test_an_absolute_path_cannot_escape(self):  # U-DOC-6
        written, got, dest = self.extract([("/etc/cron.d/evil", "boom", "file")])
        self.assertEqual(got, [])
        self.assertFalse(os.path.exists("/etc/cron.d/evil"))

    def test_dot_dot_cannot_escape(self):  # U-DOC-7
        written, got, _ = self.extract([("../../escaped.txt", "boom", "file")])
        self.assertEqual(got, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escaped.txt")))

    def test_links_and_devices_are_refused(self):  # U-DOC-8
        """A symlink to /etc/shadow followed by a write through it is the classic tar escape."""
        written, got, dest = self.extract([("passwd", "/etc/passwd", "sym"),
                                           ("hard", "/etc/shadow", "link"),
                                           ("null", None, "dev"),
                                           ("real.txt", "fine", "file")])
        self.assertEqual(got, ["real.txt"])
        self.assertFalse(os.path.islink(os.path.join(dest, "passwd")))

    def test_the_cap_stops_a_huge_copy(self):  # U-DOC-9
        big = "x" * 4096
        written, got, _ = self.extract([(f"f{i}.txt", big, "file") for i in range(10)], cap=8192)
        self.assertLessEqual(written, 8192)
        self.assertLess(len(got), 10)

    def test_a_file_bigger_than_the_file_cap_is_skipped(self):  # U-DOC-10
        with mock.patch.object(containers, "FILE_CAP", 10):
            written, got, _ = self.extract([("small.txt", "hi", "file"), ("big.txt", "x" * 50, "file")])
        self.assertEqual(got, ["small.txt"])

    def test_a_path_that_is_not_there_is_not_an_error(self):  # U-DOC-11
        popen = FakePopen({})
        self.assertIsNone(containers.copy_path("c", "/root/.claude", os.path.join(self.tmp, "d"), "docker",
                                               popen))


class MemberFilterTests(unittest.TestCase):
    """The first of the two layers: what safe_members lets through at all.

    copy_path also refuses anything that would land outside the destination, so these cases are caught
    twice on purpose — this test is what proves the first layer is doing its job."""

    def kept(self, entries):
        blob = tar_bytes(entries)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r|*") as tar:
            return [m.name for m, _ in containers.safe_members(tar, containers.COPY_CAP)]

    def test_it_refuses_what_a_hostile_tar_is_made_of(self):  # U-DOC-17
        kept = self.kept([("ok.txt", "fine", "file"),
                          ("/etc/passwd", "boom", "file"),
                          ("../escape.txt", "boom", "file"),
                          ("a/../../escape2.txt", "boom", "file"),
                          ("link", "/etc/shadow", "sym"),
                          ("hard", "/etc/shadow", "link"),
                          ("dev", None, "dev")])
        self.assertEqual(kept, ["ok.txt"])

    def test_it_stops_at_the_cap(self):  # U-DOC-18
        blob = tar_bytes([(f"f{i}.txt", "x" * 100, "file") for i in range(10)])
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r|*") as tar:
            kept = [m.name for m, _ in containers.safe_members(tar, 250)]
        self.assertEqual(kept, ["f0.txt", "f1.txt"])


class CollectTests(TempDirTest):
    def test_it_copies_the_ai_folders_that_exist(self):  # U-DOC-12
        table = {"/root/.claude": tar_bytes([(".claude", None, "dir"),
                                             (".claude/history.jsonl", '{"k": "sk-ant-x"}\n', "file")])}
        popen = FakePopen(table)
        run = fake_run({"docker inspect": json.dumps({"Env": ["HOME=/root", "API_KEY=sk-live-abc"],
                                                      "User": ""})})
        dest = os.path.join(self.tmp, "home")
        out = containers.collect("api", dest, "docker", run, popen)
        self.assertEqual(out["home"], "/root")
        self.assertIn(".claude", out["paths"])
        self.assertTrue(os.path.exists(os.path.join(dest, ".claude", "history.jsonl")))
        # The container's own environment variables are configuration, not a leak into a conversation:
        # they are read for HOME and then left alone.
        self.assertFalse(os.path.exists(os.path.join(dest, ".env")))
        self.assertNotIn("env_vars", out)

    def test_nothing_is_ever_executed_in_the_container(self):  # U-DOC-13
        """The whole design rests on this: cp and inspect, never exec, run, start or stop."""
        table = {"/root/.claude": tar_bytes([(".claude/h.jsonl", "x", "file")])}
        popen = FakePopen(table)
        seen = []

        def run(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"Env": []}).encode(), b"")

        containers.collect("api", os.path.join(self.tmp, "h"), "docker", run, popen)
        for cmd in seen:
            self.assertIn(cmd[1], ("inspect", "image"), cmd)
        for ref in popen.asked:
            self.assertTrue(ref.startswith("api:"), ref)
        forbidden = {"exec", "run", "start", "stop", "rm", "create", "commit", "build", "save", "load"}
        for cmd in seen:
            self.assertFalse(forbidden & set(cmd), cmd)

    def test_a_shared_root_is_probed_once_before_its_paths_are_asked_for(self):  # U-DOC-14
        """Otherwise every container costs one failed copy per known path under .config."""
        popen = FakePopen({})           # nothing exists
        run = fake_run({"docker inspect": json.dumps({"Env": []})})
        containers.collect("api", os.path.join(self.tmp, "h"), "docker", run, popen)
        under_config = [r for r in popen.asked if r.startswith("api:/root/.config/")]
        self.assertEqual(under_config, [], "the root was missing; nothing under it should have been asked for")


class ImageTests(unittest.TestCase):
    """An image is listed and left alone: it holds no conversation history to look through."""

    def test_images_are_listed_only(self):  # U-DOC-15
        run = fake_run({"docker images": "api:latest\npostgres:16\n<none>:<none>\n"})
        self.assertEqual(containers.images("docker", run), ["api:latest", "postgres:16"])
        self.assertFalse(hasattr(containers, "image_secrets"),
                         "reading an image's configuration is a different tool's job")

    def test_nothing_in_the_module_opens_an_image(self):  # U-DOC-16
        import inspect as _inspect
        src = _inspect.getsource(containers)
        for verb in ('"save"', '"create"', '"export"', '"load"', '"run"', '"exec"'):
            self.assertNotIn(f"exe, {verb}", src)


if __name__ == "__main__":
    unittest.main()


class ContainerAsEnvironmentTests(TempDirTest):
    """A container is an environment like a distribution is: the scan merges its findings and its side."""

    def test_the_provider_lists_containers_as_environments(self):  # U-DOC-19
        from afterprompt import envs
        from tests.helpers import make_cfg
        cfg = make_cfg(self.tmp, "linux")
        cfg.containers = "running"
        listing = lambda exe: [{"name": "api", "image": "x", "state": "running"}] if exe == "docker" else None
        with mock.patch("afterprompt.detect.Probe.which", lambda self, n: "/usr/bin/" + n if n == "docker" else None):
            found = envs.container_provider(cfg, env={}, listing=listing)
        self.assertEqual([(e.name, e.kind, e.side) for e in found],
                         [("api", "docker", "docker:api")])

    def test_turning_them_off_asks_docker_nothing(self):  # U-DOC-20
        from afterprompt import envs
        from tests.helpers import make_cfg
        cfg = make_cfg(self.tmp, "linux")
        cfg.containers = "none"
        asked = []
        self.assertEqual(envs.container_provider(cfg, env={}, listing=lambda exe: asked.append(exe) or []), [])
        self.assertEqual(asked, [])

    def test_a_fixture_run_does_not_adopt_this_machines_containers(self):  # U-DOC-21
        from afterprompt import envs
        from tests.helpers import make_cfg
        cfg = make_cfg(self.tmp, "linux")
        cfg.containers = "running"
        env = {"AFTERPROMPT_HOME": "/somewhere/else"}
        self.assertEqual(envs.container_provider(cfg, env=env, listing=lambda exe: [{"name": "api"}]), [])

    def test_a_container_with_no_assistant_history_is_skipped_not_failed(self):  # U-DOC-22
        """Most containers run a database. Skipping them quietly is the common path, not an error."""
        from afterprompt import envs
        from tests.helpers import make_cfg
        cfg = make_cfg(self.tmp, "linux")
        e = envs.Environment("db", "docker", "Docker: db", "docker:db")
        with mock.patch.object(containers, "collect", return_value={"name": "db", "home": "/root",
                                                                    "paths": [], "bytes": 0}):
            res = envs._scan_container(e, cfg, [], lambda m: None, os.path.join(self.tmp, "envs"), None)
        self.assertEqual(res["status"], "skipped")
        self.assertIn("no AI tool history", res["reason"])

    def test_the_copy_does_not_outlive_the_scan(self):  # U-DOC-23
        """It holds someone's transcripts in plain text; it is deleted whether the worker worked or not."""
        from afterprompt import envs
        from tests.helpers import make_cfg
        cfg = make_cfg(self.tmp, "linux")
        cfg.keep_work = False
        e = envs.Environment("api", "docker", "Docker: api", "docker:api")
        state = os.path.join(self.tmp, "envs")
        copied = {}

        def collect(name, dest, **kw):
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "history.jsonl"), "w", encoding="utf-8") as fh:
                fh.write("sk-ant-secret\n")
            copied["dest"] = dest
            return {"name": name, "home": "/root", "paths": [".claude"], "bytes": 14}

        with mock.patch.object(containers, "collect", side_effect=collect), \
                mock.patch.object(envs, "run_local", return_value={"exit": 1, "error": {"kind": "boom"}}):
            envs._scan_container(e, cfg, [], lambda m: None, state, None)
        self.assertFalse(os.path.exists(copied["dest"]), "the copied home was left on disk")
