"""Failure controls for the test scripts fixed by the audit."""
import ast
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import re
from types import SimpleNamespace
import unittest

from status_check import owned_entries

ROOT = Path(__file__).resolve().parent


class HarnessRegressions(unittest.TestCase):
    def run_batch_fragment(self, text):
        with tempfile.TemporaryDirectory(prefix="sandy_verdict_") as temp:
            script = Path(temp) / "verdict.bat"
            script.write_bytes(("@echo off\nsetlocal EnableDelayedExpansion\n" + text).replace("\n", "\r\n").encode())
            return subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(script)],
                                  capture_output=True, timeout=10).returncode

    def test_batch_verdicts_include_probe_and_cleanup_failures(self):
        acl = (ROOT / "test_acl_grants_rt.bat").read_text(encoding="utf-8")
        tail = acl[acl.index("if !FAIL! GTR 0 set EXIT_CODE=1"):] if "if !FAIL! GTR 0 set EXIT_CODE=1" in acl else acl[acl.index("if !EXIT_CODE! EQU 0"):]
        self.assertNotEqual(self.run_batch_fragment("set FAIL=1\nset EXIT_CODE=0\n" + tail), 0)
        mixed = (ROOT / "test_mixed_ac_rt.bat").read_text(encoding="utf-8")
        tail = mixed[mixed.rindex("if !FAIL! GTR 0 exit /b 1"):]
        for mode in ("AC", "RT"):
            block = re.search(rf"set {mode}_EXIT=!ERRORLEVEL!\n(.*?)echo\.", mixed, re.S).group()
            self.assertNotEqual(self.run_batch_fragment("set FAIL=0\ncmd /d /c exit 7\n" + block + "\n" + tail), 0)
        actors = (ROOT / "test_collude4.bat").read_text(encoding="utf-8")
        block = actors[actors.index("if !ALL_DONE! EQU 0 (\n    echo"):actors.index("REM The probes are done")]
        tail = actors[actors.rindex("if !FAIL! NEQ 0 exit /b 1"):]
        self.assertNotEqual(self.run_batch_fragment("set FAIL=0\nset ALL_DONE=0\n" + block + tail), 0)
        collusion = (ROOT / "test_collusion.bat").read_text(encoding="utf-8")
        block = collusion[collusion.index("set CLEANUP_FAIL=0"):collusion.index("REM --- Check for ANY AppContainer")]
        tail = collusion[collusion.rindex("if !CLEANUP_FAIL! GTR 0 exit /b 1"):]
        with tempfile.TemporaryDirectory(prefix="sandy_actor_") as temp:
            signals = Path(temp) / "signals"
            signals.mkdir()
            (signals / "alice_done").write_text("1")
            (signals / "bob_done").write_text("0")
            self.assertNotEqual(self.run_batch_fragment(f'set "SHARED={temp}"\nset LIVE=0\n' + block + tail), 0)
            (signals / "alice_done").write_text("0")
            self.assertEqual(self.run_batch_fragment(f'set "SHARED={temp}"\nset LIVE=0\n' + block + tail), 0)
            (signals / "alice_done").unlink()
            self.assertNotEqual(self.run_batch_fragment(f'set "SHARED={temp}"\nset LIVE=0\n' + block + tail), 0)

    def test_missing_binary_is_a_failure(self):
        for name in ("test_removed_features.bat", "test_config_scalar_guards.bat",
                     "test_config_path_guards.bat", "test_string_mode_semantics.bat", "test_clean.bat"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="sandy_missing_") as temp:
                path = Path(temp) / name
                shutil.copyfile(ROOT / name, path)
                env = dict(os.environ, LOCALAPPDATA=temp)
                result = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(path)],
                                        cwd=temp, env=env, capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0, result.stdout.decode(errors="replace"))

    def test_native_dacl_snapshot_batch_quoting(self):
        with tempfile.TemporaryDirectory(prefix="sandy snapshot ") as temp:
            (Path(temp) / "shared").mkdir()
            for name, variable in (("test_collusion", "PRE_SHARED"), ("test_mixed_ac_rt", "PRE_SDDL_0"),
                                   ("test_collude4", "PRE_HUB")):
                with self.subTest(name=name):
                    script = (ROOT / (name + ".bat")).read_text(encoding="utf-8")
                    line = next(line for line in script.splitlines() if f'set "{variable}=%%S"' in line)
                    line = line.replace("%~dp0", str(ROOT) + "\\")
                    fragment = f'set "SHARED={temp}"\nset "ROOT={temp}"\nset "HUB={temp}"\n'
                    fragment += line + f"\nif not defined {variable} exit /b 1\nexit /b 0\n"
                    self.assertEqual(self.run_batch_fragment(fragment), 0)

    def test_probe_errors_fail_the_summary(self):
        for name in ("evil", "evil_rt", "diabolical", "diabolical_rt", "expert", "expert_rt", "phantom"):
            with self.subTest(name=name):
                tree = ast.parse((ROOT / f"test_{name}.py").read_text(encoding="utf-8-sig"))
                assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                                  and any(isinstance(t, ast.Name) and t.id == "failed" for t in node.targets))
                expression = compile(ast.Expression(assignment.value), f"test_{name}.py", "eval")
                for outcome in ("FAIL", "ERR"):
                    self.assertGreater(eval(expression, {"results": [(outcome, "injected")] }), 0)
                self.assertEqual(eval(expression, {"results": [("PASS", "control")] }), 0)

    def test_process_limit_probe_rejects_unrestricted_result(self):
        tree = ast.parse((ROOT / "test_allow_limits.py").read_text(encoding="utf-8-sig"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "spawn_many")
        module = ast.Module(body=[function], type_ignores=[])
        class Child:
            def poll(self): return None
            def kill(self): pass
            def wait(self, timeout): pass
        for allowed in (10, 2):
            created = []
            def popen(*args, **kwargs):
                if len(created) >= allowed:
                    raise OSError("process limit")
                created.append(Child())
                return created[-1]
            scope = {"subprocess": SimpleNamespace(Popen=popen, PIPE=-1),
                     "sys": SimpleNamespace(executable="python"), "time": SimpleNamespace(sleep=lambda _: None)}
            exec(compile(module, "test_allow_limits.py", "exec"), scope)
            if allowed == 10:
                with self.assertRaises(AssertionError):
                    scope["spawn_many"]()
            else:
                self.assertIn("8 blocked", scope["spawn_many"]())

    def test_status_checks_ignore_other_users_runs_and_profiles(self):
        status = {"instances": [{"uuid": "other"}], "retry_containers": [{"instance": "other"}],
                  "tasks": [{"instance": "other"}], "profiles": ["Sandy_other"],
                  "saved_profiles": [{"name": "libreoffice-lpac-demo"}]}
        self.assertEqual(owned_entries(status, {"ours"}, {"audit-profile"}), [])
        for field, item in (("instances", {"uuid": "ours"}), ("retry_containers", {"instance": "ours"}),
                            ("tasks", {"instance": "ours"}), ("profiles", "Sandy_ours"),
                            ("saved_profiles", {"name": "audit-profile"})):
            with self.subTest(field=field):
                fixture = {**status, field: status[field] + [item]}
                self.assertEqual(owned_entries(fixture, {"ours"}, {"audit-profile"}), [item])

    def test_real_process_limit_probe(self):
        tree = ast.parse((ROOT / "test_allow_limits.py").read_text(encoding="utf-8-sig"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "spawn_many")
        code = "import subprocess, sys, time\n" + ast.unparse(function) + "\nprint(spawn_many())"
        sandy = ROOT.parent / "x64/Release/sandy.exe"
        config = "[sandbox]\\ntoken='restricted'\\nintegrity='medium'\\n[privileges]\\ndesktop=false\\n[limit]\\nprocesses=3"
        result = subprocess.run([str(sandy), "-q", "-s", config, "-x", sys.executable, "-c", code],
                                capture_output=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("8 blocked", result.stdout)

    def test_sneaky_mode_validation_cases(self):
        script = (ROOT / "test_sneaky.bat").read_text(encoding="utf-8")
        cases = script[script.index("REM GROUP 2:"):script.index("REM GROUP 3:")]
        prefix = f'set "SANDY={ROOT.parent / "x64/Release/sandy.exe"}"\nset PASS=0\nset FAIL=0\n'
        self.assertEqual(self.run_batch_fragment(prefix + cases +
                         "\nif !FAIL! GTR 0 exit /b 1\nexit /b 0\n"), 0)


if __name__ == "__main__":
    unittest.main()
