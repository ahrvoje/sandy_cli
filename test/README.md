# Focused tests

Build `sandy.sln` with the command in `.agents/guidelines.md` before running tests.
The Python wrappers use `%LOCALAPPDATA%\Programs\Python\Python314\python.exe`
unless `PYTHON` is set. A missing dependency is a failure, not a passing skip.

Run these from the repository root:

```bat
test\test_audit_regressions.bat
test\test_audit_harness.bat
test\test_dacl_fidelity.bat
test\test_pipe_hook.bat
```

`test_audit_regressions` covers preview safety, Unicode, mode validation,
profile logging, incomplete ledgers, failed ACL cleanup, container recovery,
real registry access, and the loopback privilege requirement. It uses temporary
folders and unique test-owned profile and registry names. The failed-cleanup
case keeps an open DACL-write handle so it can restore its own test folder.

`test_audit_harness` supplies failing and passing controls to the test scripts:
missing dependencies, probe errors, unlimited child processes, missing actor
results, and unrelated saved profiles. `status_check.py` limits recovery checks
to the instance IDs read from test logs and to explicitly named test profiles.

`test_dacl_fidelity` includes a file moved from a parent with a different
inherited ACE. Windows recalculates inheritance on DACL writes; the test checks
that exception separately from normal DACL preservation.

The main runner includes both audit scripts and the pipe-hook test. The full
runner was not run for this audit. See [the audit record](audit_findings.md) for
the focused checks and each finding's resolution.

## LibreOffice integration

These tests are manual integrations because they need an installed LibreOffice
and a visible desktop. Run without elevation. They are not default runner entries.

```bat
test\test_libreoffice_launcher.bat --libreoffice "C:\Program Files\LibreOffice"
```

The launcher test creates its own scratch folder, opens Writer, verifies its
LPAC token and pipe, closes Writer, then checks export and cleanup. Its live
checks call `verify_writer` from `test_libreoffice_lpac.py`.

To inspect an already running demo that you started with `docs/libreoffice-demo.py`,
pass that demo's scratch folder:

```bat
test\test_libreoffice_lpac.bat --scratch "C:\path\to\demo-scratch"
```

The old standalone experiments and unreferenced probe/config pairs were removed.
The current runner, focused regressions, and these documented integrations are
the supported test entry points.
