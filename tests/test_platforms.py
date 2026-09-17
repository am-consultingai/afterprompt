import os
import unittest
from types import SimpleNamespace

from afterprompt import platforms as P
from tests.helpers import TempDirTest, write


class DetectTests(TempDirTest):
    def test_detect(self):  # U-PLAT-1
        rel = write(os.path.join(self.tmp, "osrelease"), "6.6.87.2-microsoft-standard-WSL2\n")
        plain = write(os.path.join(self.tmp, "plain"), "6.8.0-generic\n")
        self.assertEqual(P.detect(sys_platform="darwin", env={}), "macos")
        self.assertEqual(P.detect(sys_platform="linux", osrelease_path=rel, env={}), "wsl")
        self.assertEqual(P.detect(sys_platform="linux", osrelease_path=plain, env={}), "linux")
        self.assertEqual(P.detect(sys_platform="linux", osrelease_path=plain, env={"WSL_DISTRO_NAME": "U"}), "wsl")
        self.assertEqual(P.detect("macos"), "macos")
        with self.assertRaises(ValueError):
            P.detect("windows")

    def test_automount_root(self):  # U-PLAT-6
        conf = write(os.path.join(self.tmp, "wsl.conf"), "[boot]\nsystemd=true\n[automount]\nroot = /win/\n")
        self.assertEqual(P.automount_root(conf), "/win/")
        self.assertEqual(P.automount_root(os.path.join(self.tmp, "missing")), "/mnt/")


class PathTests(unittest.TestCase):
    def test_from_windows_path(self):  # U-PLAT-2
        self.assertEqual(P.from_windows_path("C:\\Users\\me\\app", "/mnt/"), "/mnt/c/Users/me/app")
        self.assertEqual(P.from_windows_path("c:/Users/me/app", "/mnt/"), "/mnt/c/Users/me/app")
        self.assertEqual(P.from_windows_path("file:///c%3A/Users/me/app", "/mnt/"), "/mnt/c/Users/me/app")
        self.assertEqual(P.from_windows_path("D:\\data", "/win/"), "/win/d/data")
        self.assertIsNone(P.from_windows_path("/home/me", "/mnt/"))

    def test_from_uri_and_back(self):  # U-PLAT-3
        self.assertEqual(P.from_uri("vscode-remote://wsl%2BUbuntu/home/u/p", "/mnt/"), "/home/u/p")
        self.assertEqual(P.from_uri("file:///Users/u/my%20p", "/mnt/"), "/Users/u/my p")
        self.assertEqual(P.from_uri("file:///c%3A/Users/u/p", "/mnt/"), "/mnt/c/Users/u/p")
        self.assertIsNone(P.from_uri("vscode-remote://ssh-remote%2Bbox/home/u", "/mnt/"))
        self.assertEqual(P.to_windows_path("/mnt/c/Users/u/p", "/mnt/"), "C:\\Users\\u\\p")
        self.assertIsNone(P.to_windows_path("/home/u", "/mnt/"))

    def test_claude_project_dirname(self):  # U-PLAT-5
        self.assertEqual(P.claude_project_dirname("/home/u/afterprompt"), "-home-u-afterprompt")
        self.assertEqual(P.claude_project_dirname("/home/u/my_app.v2"), "-home-u-my-app-v2")


class WindowsHomeTests(TempDirTest):  # U-PLAT-4
    def setUp(self):
        super().setUp()
        self.mount = self.tmp + "/"
        os.makedirs(os.path.join(self.tmp, "c", "Users", "me"))
        os.makedirs(os.path.join(self.tmp, "c", "Users", "Public"))

    def runner(self, outputs):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd[0])
            out = outputs.get(os.path.basename(cmd[0]) if "System32" not in cmd[0] else "System32")
            if out is None:
                raise OSError("not available")
            return SimpleNamespace(returncode=0, stdout=out.encode())
        run.calls = calls
        return run

    def which(self, available):
        return lambda name: name if name in available else None

    def test_cmd_exe(self):
        run = self.runner({"cmd.exe": "C:\\Users\\me\r\n"})
        self.assertEqual(P.detect_windows_home(run, self.mount, {}, self.which({"cmd.exe"})),
                         (os.path.join(self.tmp, "c", "Users", "me"), "cmd.exe"))

    def test_system32_fallback(self):
        s32 = write(os.path.join(self.tmp, "c", "Windows", "System32", "cmd.exe"), "")
        run = self.runner({"System32": "C:\\Users\\me"})
        path, source = P.detect_windows_home(run, self.mount, {}, self.which(set()))
        self.assertEqual(source, "cmd.exe (System32)")
        self.assertTrue(os.path.exists(s32))

    def test_powershell_fallback(self):
        run = self.runner({"cmd.exe": "%USERPROFILE%", "powershell.exe": "C:\\Users\\me"})
        path, source = P.detect_windows_home(run, self.mount, {}, self.which({"cmd.exe", "powershell.exe"}))
        self.assertEqual(source, "powershell.exe")

    def test_user_env_fallback(self):
        run = self.runner({})
        os.makedirs(os.path.join(self.tmp, "c", "Users", "other"))
        path, source = P.detect_windows_home(run, self.mount, {"USER": "me"}, self.which(set()))
        self.assertEqual((path, source), (os.path.join(self.tmp, "c", "Users", "me"), "$USER"))

    def test_single_profile_and_ambiguous(self):
        run = self.runner({})
        path, source = P.detect_windows_home(run, self.mount, {"USER": "nobody"}, self.which(set()))
        self.assertEqual(source, "single profile")
        os.makedirs(os.path.join(self.tmp, "c", "Users", "other"))
        self.assertEqual(P.detect_windows_home(run, self.mount, {"USER": "nobody"}, self.which(set())),
                         (None, "not found"))

    @unittest.skipUnless(os.environ.get("AFTERPROMPT_TEST_REAL_WSL") == "1", "real WSL check not requested")
    def test_real_wsl(self):
        path, source = P.detect_windows_home()
        self.assertIsNotNone(path, source)
        self.assertTrue(os.path.isdir(path))
