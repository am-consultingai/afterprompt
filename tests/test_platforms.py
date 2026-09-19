import os
import sys
import unittest
from types import SimpleNamespace

from afterprompt import platforms as P
from tests.helpers import TempDirTest, requires_posix, write


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
            P.detect("plan9")

    def test_detect_native_windows(self):  # U-PLAT-7 (W2)
        """win32 is Windows, never 'linux' — a mislabelled run silently skips the AppData locations."""
        self.assertEqual(P.detect(sys_platform="win32", env={}), "windows")
        # No /proc on Windows: detection must not depend on reading it.
        self.assertEqual(P.detect(sys_platform="win32", osrelease_path=os.path.join(self.tmp, "nope"), env={}),
                         "windows")
        # A stray WSL variable in a Windows environment does not make it a WSL run.
        self.assertEqual(P.detect(sys_platform="win32", env={"WSL_DISTRO_NAME": "Ubuntu"}), "windows")
        self.assertEqual(P.detect("windows"), "windows")

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


@requires_posix  # finding the Windows profile across /mnt is only meaningful from WSL
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


class NativeWindowsPathTests(unittest.TestCase):
    """Path translation when the scan runs on Windows itself: nothing goes through /mnt."""

    def test_from_windows_path_native(self):  # U-PLAT-8 (W2)
        self.assertEqual(P.from_windows_path("C:\\Users\\me\\app", native=True), "C:\\Users\\me\\app")
        self.assertEqual(P.from_windows_path("c:/Users/me/app", native=True), "C:\\Users\\me\\app")
        self.assertEqual(P.from_windows_path("file:///c%3A/Users/me/app", native=True), "C:\\Users\\me\\app")
        self.assertEqual(P.from_windows_path("D:\\", native=True), "D:\\")
        self.assertIsNone(P.from_windows_path("/home/me/app", native=True))

    def test_from_uri_native(self):  # U-PLAT-9 (W2)
        self.assertEqual(P.from_uri("file:///c%3A/Users/me/app", native=True), "C:\\Users\\me\\app")
        # A WSL remote workspace is not reachable as a Windows path; it must not become a bogus C:\ path.
        self.assertIsNone(P.from_uri("vscode-remote://wsl%2BUbuntu/home/me/app", native=True))
        self.assertIsNone(P.from_uri("file:///home/me/app", native=True))
        # The WSL side keeps translating through the mount, unchanged.
        self.assertEqual(P.from_uri("vscode-remote://wsl%2BUbuntu/home/me/app", "/mnt/"), "/home/me/app")
        self.assertEqual(P.from_uri("file:///c%3A/Users/me/app", "/mnt/"), "/mnt/c/Users/me/app")


class WslDistroTests(unittest.TestCase):
    """W5: from a Windows run, WSL distros are an optional extra — never a requirement."""

    def runner(self, stdout, rc=0):
        def run(cmd, **kw):
            self.called = cmd
            return SimpleNamespace(returncode=rc, stdout=stdout)
        self.called = None
        return run

    def utf16(self, *names):
        return ("\r\n".join(names) + "\r\n").encode("utf-16-le")

    def test_no_wsl_installed_is_not_an_error(self):  # U-PLAT-W1 (W5)
        """The common case on a plain Windows machine: wsl.exe does not exist."""
        self.assertEqual(P.wsl_distros(self.runner(b""), which=lambda n: None), [])
        self.assertIsNone(self.called)

    def test_lists_real_distros_only(self):  # U-PLAT-W2 (W5)
        out = self.utf16("Ubuntu-22.04", "docker-desktop", "Debian", "docker-desktop-data", "")
        self.assertEqual(P.wsl_distros(self.runner(out), which=lambda n: n), ["Ubuntu-22.04", "Debian"])

    def test_tolerates_odd_output(self):  # U-PLAT-W3 (W5)
        # A BOM, stray NULs and blank lines are all normal from wsl.exe.
        self.assertEqual(P.wsl_distros(self.runner("\ufeffUbuntu\r\n\r\n".encode("utf-16-le")),
                                       which=lambda n: n), ["Ubuntu"])
        self.assertEqual(P.wsl_distros(self.runner(b"Ubuntu\n"), which=lambda n: n), ["Ubuntu"])
        self.assertEqual(P.wsl_distros(self.runner(b"", rc=1), which=lambda n: n), [])

    def test_failure_is_empty_not_raised(self):  # U-PLAT-W4 (W5)
        def boom(cmd, **kw):
            raise OSError("wsl.exe is broken")
        self.assertEqual(P.wsl_distros(boom, which=lambda n: n), [])

    def test_home_unc(self):  # U-PLAT-W5 (W5)
        self.assertEqual(P.wsl_home_unc("Ubuntu-22.04"), r"\\wsl.localhost\Ubuntu-22.04\home")

    @unittest.skipUnless(os.environ.get("AFTERPROMPT_TEST_REAL_WSL") == "1", "real WSL check not requested")
    def test_real_machine(self):  # U-PLAT-W6 (W5)
        """On a real Windows host with WSL, enumeration must return the installed distros."""
        if sys.platform != "win32":
            self.skipTest("only meaningful from Windows")
        names = P.wsl_distros()
        if not names:
            # wsl.exe ships with Windows even when no distribution is installed (CI runners are like
            # this), and that is the case this feature is built for: an empty list, not a failure.
            self.skipTest("no WSL distribution installed on this host")
        self.assertNotIn("docker-desktop", names)
        self.assertTrue(os.path.isdir(P.wsl_home_unc(names[0])), names)
