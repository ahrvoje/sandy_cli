"""Focused regressions for the October 2026 audit; all resources are test-owned."""
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import uuid
import winreg
from ctypes import wintypes
from test_dacl_fidelity import dacl_sddl

SANDY = Path(os.environ.get("SANDY", Path(__file__).resolve().parents[1] / "x64/Release/sandy.exe"))
CMD = str(Path(os.environ["SystemRoot"]) / "System32/cmd.exe")


def process_creation_time():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(wintypes.HANDLE(-1), ctypes.byref(created),
                                 ctypes.byref(exited), ctypes.byref(system), ctypes.byref(user)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


def write_handle_dacl(handle, sddl):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetKernelObjectSecurity.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    sd = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.SetKernelObjectSecurity(handle, 4, sd):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(sd)


class AuditRegressions(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SANDY.is_file(), f"Missing binary: {SANDY}")
        self.temp = tempfile.TemporaryDirectory(prefix="sandy_audit_")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_sandy(self, *args):
        return subprocess.run([str(SANDY), *map(str, args)], capture_output=True,
                              encoding="utf-8", errors="strict", timeout=60)

    def config(self, text, name="config.toml"):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def profile(self, config):
        name = "audit-" + uuid.uuid4().hex
        result = self.run_sandy("--create-profile", name, "-c", config)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.addCleanup(self.delete_profile, name)
        return name

    def delete_profile(self, name):
        result = self.run_sandy("--delete-profile", name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_saved_profile_previews_do_not_launch(self):
        profile = self.profile(self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n[privileges]\ndesktop=false\n"))
        for flag in ("--dry-run", "--check", "--print-config"):
            with self.subTest(flag=flag):
                marker = self.root / (flag[2:] + ".marker")
                log = self.root / (flag[2:] + ".log")
                result = self.run_sandy(flag, "-p", profile, "-l", log, "-x", CMD,
                                        "/d", "/c", f'echo launched>"{marker}" & exit /b 7')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(marker.exists(), "Preview launched its child")
                self.assertNotIn("LAUNCH:", log.read_text(encoding="utf-8-sig"))
                if flag == "--print-config":
                    self.assertEqual(tomllib.loads(result.stdout)["sandbox"]["token"], "restricted")
                self.assertEqual(self.run_sandy(flag, "-p", profile).returncode, 0)

    def test_unicode_output_and_diagnostic(self):
        folder = self.root / "sandy_šđ_—_目录"
        folder.mkdir()
        cfg = self.config(f"[sandbox]\ntoken='appcontainer'\n[allow.deep]\nread=['{folder}']\n")
        result = self.run_sandy("--print-config", "-c", cfg)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tomllib.loads(result.stdout)["allow"]["deep"]["read"], [str(folder)])
        self.assertIn(str(folder), self.run_sandy("--dry-run", "-c", cfg).stdout)
        folder.rmdir()
        result = self.run_sandy("--print-config", "-c", cfg)
        self.assertEqual(result.returncode, 128)
        self.assertIn(str(folder), result.stderr)

    def test_empty_and_false_wrong_mode_sections(self):
        for mode, extra in (
            ("appcontainer", "[bogus_section]"),
            ("restricted", "[capabilities]"),
            ("restricted", "[pipes]"),
            ("restricted", "[privileges]\nloopback=false"),
            ("appcontainer", "strict=false"),
            ("appcontainer", "[deny.deep]\nread=[]"),
            ("appcontainer", "[deny.this]"),
            ("lpac", "[registry]"),
        ):
            with self.subTest(mode=mode, extra=extra):
                text = f"[sandbox]\ntoken='{mode}'\n"
                if mode == "restricted":
                    text += "integrity='medium'\n"
                result = self.run_sandy("--dry-run", "-c", self.config(text + extra + "\n"))
                self.assertEqual(result.returncode, 128, result.stdout + result.stderr)

    def test_dry_run_lists_pipes_and_profile_access(self):
        cfg = self.config("[sandbox]\ntoken='lpac'\n[capabilities]\nnames=['privateNetworkClientServer']\n"
                          "[privileges]\nloopback=true\n[pipes]\n'\\\\.\\pipe\\audit'='\\\\.\\pipe\\LOCAL\\audit'\n")
        for args in (("--dry-run",), ("--dry-run", "--create-profile", "audit-" + uuid.uuid4().hex)):
            result = self.run_sandy(*args, "-c", cfg)
            self.assertEqual(result.returncode, 0, result.stderr)
            for expected in ("[pipes]", "LOCAL\\audit", "[capabilities]", "privateNetworkClientServer", "loopback:"):
                self.assertIn(expected, result.stdout)
        cfg = self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n[privileges]\ndesktop=true\n")
        result = self.run_sandy("--dry-run", "--create-profile", "audit-" + uuid.uuid4().hex, "-c", cfg)
        self.assertIn("desktop:", result.stdout)

    def test_log_stamp_in_profile_modes_and_cleanup_log(self):
        cfg = self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n[privileges]\ndesktop=false\n")
        name = "audit-" + uuid.uuid4().hex
        result = self.run_sandy("--create-profile", name, "-c", cfg, "-L", "-l", self.root / "create.log")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(self.delete_profile, name)
        self.assertFalse((self.root / "create.log").exists())
        self.assertEqual(len(list(self.root.glob("*_create.log"))), 1)
        result = self.run_sandy("-p", name, "-L", "-l", self.root / "run.log", "-x", CMD, "/d", "/c", "exit 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        logs = list(self.root.glob("*_run.log"))
        self.assertEqual(len(logs), 1)
        text = logs[0].read_text(encoding="utf-8-sig")
        self.assertNotIn("cleanup retry still pending", text)
        self.assertIn("REG_CLEAR:", text)
        self.assertIn("SCHTASK: deleted", text)
        self.assertLess(text.index("REG_CLEAR:"), text.index("CLEANUP: complete"))

    def test_missing_profile_workdir_and_stdin_are_explained_and_logged(self):
        for kind in ("workdir", "stdin"):
            with self.subTest(kind=kind):
                target = self.root / kind
                if kind == "workdir":
                    target.mkdir()
                    extra = f"workdir='{target}'\n[privileges]\ndesktop=false\n"
                else:
                    target.write_text("input", encoding="utf-8")
                    extra = f"[privileges]\ndesktop=false\nstdin='{target}'\n"
                profile = self.profile(self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n" + extra))
                target.rmdir() if kind == "workdir" else target.unlink()
                log = self.root / (kind + ".log")
                result = self.run_sandy("-p", profile, "-l", log, "-x", CMD, "/d", "/c", "exit 0")
                self.assertEqual(result.returncode, 128)
                self.assertIn(str(target), result.stderr)
                self.assertNotIn("corrupted or incomplete", result.stderr)
                self.assertIn(str(target), log.read_text(encoding="utf-8-sig"))

    def test_error_text(self):
        result = self.run_sandy("--explain", "0x40010004")
        self.assertIn("DBG_TERMINATE_PROCESS", result.stdout)
        path = self.root / "utf16.toml"
        path.write_text("[sandbox]\ntoken='appcontainer'\n", encoding="utf-16")
        result = self.run_sandy("--dry-run", "-c", path)
        self.assertEqual(result.returncode, 128)
        self.assertIn("UTF-16", result.stderr)
        self.assertNotIn("unknown sections or keys", result.stderr.lower())
        result = self.run_sandy("--dry-run", "-c", self.config("bare=1\n[sandbox]\ntoken='appcontainer'\n"))
        self.assertEqual(result.returncode, 128)
        self.assertNotIn("will be ignored", result.stderr)

    def test_incomplete_ledger_is_recovered(self):
        name = "dead-test-" + uuid.uuid4().hex
        key = "Software\\Sandy\\Grants\\" + name
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, "_profile_name", 0, winreg.REG_SZ, "audit-abandoned")
        try:
            result = self.run_sandy("--cleanup")
            self.assertEqual(result.returncode, 0, result.stderr)
            with self.assertRaises(FileNotFoundError):
                winreg.OpenKey(winreg.HKEY_CURRENT_USER, key).Close()
        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except FileNotFoundError:
                pass

    def test_powershell_51_quick_start_encoding(self):
        path = self.root / "myconfig.toml"
        shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        env = dict(os.environ, PATH=str(SANDY.parent) + os.pathsep + os.environ["PATH"])
        result = subprocess.run([str(shell), "-NoProfile", "-Command",
                                 'cmd /c "sandy.exe --print-container-toml > myconfig.toml"'],
                                env=env, cwd=self.root, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(path.read_bytes().startswith(b"\xff\xfe"))
        self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"))
        result = self.run_sandy("--print-config", "-c", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tomllib.loads(result.stdout)["sandbox"]["token"], "appcontainer")

    def test_failed_acl_removal_keeps_recovery_and_task(self):
        target = self.root / "granted"
        target.mkdir()
        probe = self.root / "probe.py"
        shutil.copyfile(Path(__file__).with_name("audit_probe.py"), probe)
        cfg = self.config(f"[sandbox]\ntoken='restricted'\nintegrity='medium'\n"
                          f"[privileges]\ndesktop=false\n[allow.this]\nread=['{target}']\n")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(target), 0x40000, 7, None, 3, 0x02000000, None)
        self.assertNotEqual(handle, wintypes.HANDLE(-1).value)
        before = dacl_sddl(target)
        self.assertTrue(before.startswith("D:"), before)
        log = self.root / "failure.log"
        process = subprocess.Popen([str(SANDY), "-q", "-c", str(cfg), "-l", str(log),
                                    "-x", sys.executable, str(probe), "hold", str(self.root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        granted = None
        try:
            deadline = time.monotonic() + 20
            while not (self.root / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue((self.root / "ready").exists(), "Child did not start")
            granted = dacl_sddl(target)
            self.assertRegex(granted, r"S-1-9-")
            # Keep a WRITE_DAC handle opened before the deny so restoration is
            # guaranteed even when a new Sandy handle cannot modify the DACL.
            write_handle_dacl(handle, "D:P(D;;WD;;;WD)(A;;RC;;;OW)" + granted[granted.index("("):])
            (self.root / "release").touch()
            _, stderr = process.communicate(timeout=30)
            text = log.read_text(encoding="utf-8-sig")
            self.assertIn("ACL_REMOVE:", text)
            self.assertIn("FAILED (0x00000005", text)
            self.assertNotEqual(process.returncode, 0, text)
            self.assertIn("cleanup is incomplete", stderr.decode("utf-8"))
            instance = re.search(r"INSTANCE: ([\w-]+)", text).group(1)
            status = json.loads(self.run_sandy("--status", "--json").stdout)
            self.assertIn(instance, [entry["uuid"] for entry in status["instances"]])
            self.assertIn(instance, [entry["instance"] for entry in status["tasks"]])
            self.assertRegex(dacl_sddl(target), r"S-1-9-")
        finally:
            (self.root / "release").touch()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=30)
            write_handle_dacl(handle, granted or before)
            kernel.CloseHandle(handle)
            self.run_sandy("--cleanup")
        self.assertNotRegex(dacl_sddl(target), r"S-1-9-")
        status = json.loads(self.run_sandy("--status", "--json").stdout)
        self.assertNotIn(instance, [entry["uuid"] for entry in status["instances"]])
        self.assertNotIn(instance, [entry["instance"] for entry in status["tasks"]])

    def test_recovery_waits_for_incomplete_ledger_writer(self):
        sid = re.search(r"S-1-[\d-]+", subprocess.check_output(["whoami", "/user"], text=True)).group()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        mutex = kernel.CreateMutexW(None, True, "Global\\Sandy_Ledger_" + sid)
        self.assertTrue(mutex)
        key = "Software\\Sandy\\Grants\\dead-test-" + uuid.uuid4().hex
        process = None
        locked = True
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
                winreg.SetValueEx(handle, "_profile_name", 0, winreg.REG_SZ, "audit-writing")
            process = subprocess.Popen([str(SANDY), "--cleanup"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.5)
            self.assertIsNone(process.poll(), "Recovery did not wait for the ledger writer")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.SetValueEx(handle, "_ctime", 0, winreg.REG_QWORD, process_creation_time())
                winreg.SetValueEx(handle, "_pid", 0, winreg.REG_DWORD, os.getpid())
            self.assertTrue(kernel.ReleaseMutex(mutex))
            locked = False
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                self.assertEqual(winreg.QueryValueEx(handle, "_pid")[0], os.getpid())
        finally:
            if locked:
                kernel.ReleaseMutex(mutex)
            kernel.CloseHandle(mutex)
            if process:
                process.communicate(timeout=30)
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except FileNotFoundError:
                pass

    def create_container(self, name):
        userenv = ctypes.WinDLL("userenv")
        userenv.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        advapi = ctypes.WinDLL("advapi32")
        advapi.FreeSid.argtypes = [ctypes.c_void_p]
        sid = ctypes.c_void_p()
        self.assertEqual(userenv.CreateAppContainerProfile(name, name, name, None, 0, ctypes.byref(sid)), 0)
        advapi.FreeSid(sid)
        self.addCleanup(userenv.DeleteAppContainerProfile, name)

    def test_startup_recovers_container_without_ledger(self):
        name = "Sandy_dead-test-" + uuid.uuid4().hex
        self.create_container(name)
        self.assertIn(name.lower(), [n.lower() for n in json.loads(self.run_sandy("--status", "--json").stdout)["profiles"]])
        cfg = self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n[privileges]\ndesktop=false\n")
        self.assertEqual(self.run_sandy("-q", "-c", cfg, "-x", CMD, "/d", "/c", "exit 0").returncode, 0)
        self.assertNotIn(name.lower(), [n.lower() for n in json.loads(self.run_sandy("--status", "--json").stdout)["profiles"]])

    def test_cleanup_loopback_reports_actual_result(self):
        name = "Sandy_dead-test-" + uuid.uuid4().hex
        self.create_container(name)
        check = Path(os.environ["SystemRoot"]) / "System32/CheckNetIsolation.exe"
        direct = subprocess.run([str(check), "LoopbackExempt", "-d", "-n=" + name],
                                capture_output=True, timeout=10)
        result = self.run_sandy("--cleanup")
        expected = "loopback exemption removed" if direct.returncode == 0 else "loopback removal failed"
        self.assertIn(f"{name} -> {expected}".lower(), result.stdout.lower())

    def test_startup_preserves_live_staging_profile_container(self):
        name = "dead-test-" + uuid.uuid4().hex
        container = "Sandy_" + name
        key = "Software\\Sandy\\Profiles\\" + name
        # This is the state between publishing the creation intent and
        # persisting the SID returned by CreateAppContainerProfile.
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, "_staging", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(handle, "_staging_pid", 0, winreg.REG_DWORD, os.getpid())
            winreg.SetValueEx(handle, "_staging_ctime", 0, winreg.REG_QWORD, process_creation_time())
            winreg.SetValueEx(handle, "_container", 0, winreg.REG_SZ, container)
        self.addCleanup(winreg.DeleteKey, winreg.HKEY_CURRENT_USER, key)
        self.create_container(container)
        cfg = self.config("[sandbox]\ntoken='restricted'\nintegrity='medium'\n[privileges]\ndesktop=false\n")
        result = self.run_sandy("-q", "-c", cfg, "-x", CMD, "/d", "/c", "exit 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        mappings = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings"
        monikers = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mappings) as parent:
            for i in range(winreg.QueryInfoKey(parent)[0]):
                with winreg.OpenKey(parent, winreg.EnumKey(parent, i)) as mapping:
                    monikers.append(winreg.QueryValueEx(mapping, "Moniker")[0].lower())
        self.assertIn(container.lower(), monikers)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            self.assertEqual(winreg.QueryValueEx(handle, "_staging")[0], 1)

    def test_registry_grants_change_real_access(self):
        key = "Software\\Sandy\\Test\\audit-" + uuid.uuid4().hex
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, "value", 0, winreg.REG_SZ, "test")
        self.addCleanup(winreg.DeleteKey, winreg.HKEY_CURRENT_USER, key)
        # Remove broad inherited identities from this test key. Strict mode
        # still includes built-in groups, so their rights are not a control.
        whoami = str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe")
        sid = re.search(r"S-1-[\d-]+", subprocess.check_output([whoami, "/user"], text=True)).group()
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        advapi.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        sd, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        self.assertTrue(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"D:P(A;;KA;;;{sid})", 1, ctypes.byref(sd), None))
        try:
            self.assertTrue(advapi.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS) as handle:
                self.assertEqual(advapi.SetSecurityInfo(int(handle), 4, 0x80000004, None, None, dacl, None), 0)
        finally:
            kernel = ctypes.WinDLL("kernel32")
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree(sd)
        text = "[sandbox]\ntoken='restricted'\nintegrity='medium'\nstrict=true\n[privileges]\ndesktop=false\n"
        regexe = str(Path(os.environ["SystemRoot"]) / "System32/reg.exe")
        for grant, operation, expected in ((None, "read", 1), ("read", "read", 0),
                                            ("read", "write", 1), ("write", "write", 0)):
            with self.subTest(grant=grant, operation=operation):
                cfg = self.config(text + (f"[registry]\n{grant}=['HKCU\\{key}']\n" if grant else ""))
                command = ["query", "HKCU\\" + key, "/v", "value"] if operation == "read" else [
                    "add", "HKCU\\" + key, "/v", "value", "/t", "REG_SZ", "/d", "test", "/f"]
                result = self.run_sandy("-q", "-c", cfg, "-x", regexe, *command)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_real_loopback_reports_privilege_requirement(self):
        cfg = self.config("[sandbox]\ntoken='appcontainer'\n[capabilities]\n"
                          "names=['privateNetworkClientServer']\n[privileges]\nloopback=true\n")
        log = self.root / "loopback.log"
        result = self.run_sandy("-q", "-c", cfg, "-l", log, "-x", CMD, "/d", "/c", "exit 0")
        if ctypes.windll.shell32.IsUserAnAdmin():
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("LOOPBACK: enabled", log.read_text(encoding="utf-8-sig"))
        else:
            self.assertEqual(result.returncode, 129, result.stderr)
            self.assertIn("requires an administrator", result.stderr)
            self.assertIn("LOOPBACK_ADD:", log.read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
