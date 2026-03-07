@echo off
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Hardening Test Suite
REM Tests: grant parser validation, parent key cleanup, LogFmt
REM        diagnostics, loopback lifecycle, dry-run ASCII output.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set RT_CONFIG=%~dp0test_resilience_rt.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Hardening Test Suite
echo =====================================================================

REM ===================================================================
REM S1 — Grant Record Parser: malformed records are rejected by --cleanup
REM ===================================================================
echo.
echo --- S1: Grant Record Parser Validation ---

REM Each record below targets a different ParseGrantRecord rejection path.
REM All should be tolerated by --cleanup and cleaned up.

REM S1.1: TYPE is not FILE or REG
reg add "HKCU\Software\Sandy\Grants\A0001" /v _pid /t REG_DWORD /d 99990 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0001" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0001" /v 0 /t REG_SZ /d "BOGUS|C:\foo|S-1-5-21-0-0-0-1" /f >nul 2>nul

REM S1.2: Missing PATH|SID separator
reg add "HKCU\Software\Sandy\Grants\A0002" /v _pid /t REG_DWORD /d 99991 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0002" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0002" /v 0 /t REG_SZ /d "FILE|no-second-pipe" /f >nul 2>nul

REM S1.3: Empty PATH
reg add "HKCU\Software\Sandy\Grants\A0003" /v _pid /t REG_DWORD /d 99992 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0003" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0003" /v 0 /t REG_SZ /d "FILE||S-1-5-21-0-0-0-1" /f >nul 2>nul

REM S1.4: PATH is relative
reg add "HKCU\Software\Sandy\Grants\A0004" /v _pid /t REG_DWORD /d 99993 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0004" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0004" /v 0 /t REG_SZ /d "FILE|relative\path|S-1-5-21-0-0-0-1" /f >nul 2>nul

REM S1.5: SID doesn't match S-rev-auth format
reg add "HKCU\Software\Sandy\Grants\A0005" /v _pid /t REG_DWORD /d 99994 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0005" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0005" /v 0 /t REG_SZ /d "FILE|C:\foo|D:FA-WD" /f >nul 2>nul

REM S1.6: Unknown flag suffix
reg add "HKCU\Software\Sandy\Grants\A0006" /v _pid /t REG_DWORD /d 99995 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0006" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0006" /v 0 /t REG_SZ /d "FILE|C:\foo|S-1-5-21-0-0-0-1|UNKNOWN:1" /f >nul 2>nul

REM S1.7: Invalid trapped SID
reg add "HKCU\Software\Sandy\Grants\A0007" /v _pid /t REG_DWORD /d 99996 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0007" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0007" /v 0 /t REG_SZ /d "FILE|C:\foo|S-1-5-21-0-0-0-1|TRAPPED:NOTSID" /f >nul 2>nul

REM S1.8: No pipe at all
reg add "HKCU\Software\Sandy\Grants\A0008" /v _pid /t REG_DWORD /d 99997 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0008" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0008" /v 0 /t REG_SZ /d "GARBAGE_NO_PIPES" /f >nul 2>nul

REM S1.9: Valid record with DENY:1 flag
reg add "HKCU\Software\Sandy\Grants\A0009" /v _pid /t REG_DWORD /d 99998 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0009" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0009" /v 0 /t REG_SZ /d "FILE|C:\foo|S-1-5-21-0-0-0-9|DENY:1" /f >nul 2>nul

REM S1.10: Valid record with TRAPPED + valid SIDs
reg add "HKCU\Software\Sandy\Grants\A0010" /v _pid /t REG_DWORD /d 99999 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0010" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0010" /v 0 /t REG_SZ /d "FILE|C:\foo|S-1-5-21-0-0-0-10|DENY:1|TRAPPED:S-1-5-21-1-2-3-4;S-1-5-21-5-6-7-8" /f >nul 2>nul

REM S1.11: REG type with HKEY path
reg add "HKCU\Software\Sandy\Grants\A0011" /v _pid /t REG_DWORD /d 99900 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0011" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0011" /v 0 /t REG_SZ /d "REG|HKEY_CURRENT_USER\Software\Test|S-1-5-21-0-0-0-11" /f >nul 2>nul

REM S1.12: UNC path
reg add "HKCU\Software\Sandy\Grants\A0012" /v _pid /t REG_DWORD /d 99901 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0012" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\A0012" /v 0 /t REG_SZ /d "FILE|\\server\share|S-1-5-21-0-0-0-12" /f >nul 2>nul

REM Run --cleanup and verify it exits cleanly
"!SANDY!" --cleanup >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S1a: --cleanup tolerates all malformed records
    set /a PASS+=1
) else (
    echo   [FAIL] S1a: --cleanup failed on malformed records
    set /a FAIL+=1
)

REM Verify all stale keys were cleaned
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S1b: All 12 stale keys cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] S1b: Some stale keys remain after cleanup
    set /a FAIL+=1
    reg delete "HKCU\Software\Sandy\Grants" /f >nul 2>nul
)

REM ===================================================================
REM S2 — Parent Key Cleanup: cascade-delete when empty
REM ===================================================================
echo.
echo --- S2: Parent Key Cascade Cleanup ---
reg add "HKCU\Software\Sandy\Grants\CASCADE1" /v _pid /t REG_DWORD /d 88888 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\CASCADE1" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\CASCADE1" /v 0 /t REG_SZ /d "FILE|C:\foo|S-1-5-21-0-0-0-1" /f >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S2a: Grants key removed when empty
    set /a PASS+=1
) else (
    echo   [FAIL] S2a: Grants key still exists when empty
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S2b: Software\Sandy removed by cascade
    set /a PASS+=1
) else (
    echo   [FAIL] S2b: Software\Sandy still exists
    set /a FAIL+=1
    reg delete "HKCU\Software\Sandy" /f >nul 2>nul
)

REM ===================================================================
REM S3 — Multiple Dead PIDs Cleaned Together
REM ===================================================================
echo.
echo --- S3: Multiple Dead PIDs Cleaned ---
reg add "HKCU\Software\Sandy\Grants\SURV1" /v _pid /t REG_DWORD /d 77771 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\SURV1" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\SURV1" /v 0 /t REG_SZ /d "FILE|C:\a|S-1-5-21-0-0-0-1" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\SURV2" /v _pid /t REG_DWORD /d 77772 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\SURV2" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\SURV2" /v 0 /t REG_SZ /d "FILE|C:\b|S-1-5-21-0-0-0-2" /f >nul 2>nul

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S3: Both dead PIDs cleaned, key removed
    set /a PASS+=1
) else (
    echo   [FAIL] S3: Keys still remain
    set /a FAIL+=1
    reg delete "HKCU\Software\Sandy" /f >nul 2>nul
)

REM ===================================================================
REM S4 — Dry-Run Outputs Clean ASCII
REM ===================================================================
echo.
echo --- S4: Dry-Run ASCII Output ---

set DRYRUN_OUT=%TEMP%\sandy_hardening_dryrun.txt
"!SANDY!" --dry-run -c "!RT_CONFIG!" -x "!PYTHON!" >"!DRYRUN_OUT!" 2>nul

findstr /C:"Sandy Dry Run" "!DRYRUN_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S4a: Dry-run header is findstr-readable
    set /a PASS+=1
) else (
    echo   [FAIL] S4a: Dry-run header not found by findstr
    set /a FAIL+=1
)

findstr /C:"Working dir" "!DRYRUN_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S4b: Working dir present in dry-run
    set /a PASS+=1
) else (
    echo   [FAIL] S4b: Working dir missing from dry-run
    set /a FAIL+=1
)

findstr /C:"Mode: restricted" "!DRYRUN_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S4c: Mode shown as restricted
    set /a PASS+=1
) else (
    echo   [FAIL] S4c: Mode not shown correctly
    set /a FAIL+=1
)

REM Verify no NUL bytes — proves not UTF-16
powershell -NoProfile -Command "if (([System.IO.File]::ReadAllBytes('%DRYRUN_OUT%') | Where-Object { $_ -eq 0 }).Count -eq 0) { exit 0 } else { exit 1 }"
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S4d: Output has zero NUL bytes
    set /a PASS+=1
) else (
    echo   [FAIL] S4d: Output contains NUL bytes
    set /a FAIL+=1
)

del "!DRYRUN_OUT!" 2>nul

REM ===================================================================
REM S5 — Print-Config Outputs Clean ASCII
REM ===================================================================
echo.
echo --- S5: Print-Config ASCII Output ---

set PCFG_OUT=%TEMP%\sandy_hardening_pcfg.txt
"!SANDY!" --print-config -c "!RT_CONFIG!" >"!PCFG_OUT!" 2>nul

findstr /C:"[sandbox]" "!PCFG_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S5a: sandbox section present
    set /a PASS+=1
) else (
    echo   [FAIL] S5a: sandbox section missing
    set /a FAIL+=1
)

findstr /C:"workdir" "!PCFG_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S5b: workdir present in print-config
    set /a PASS+=1
) else (
    echo   [FAIL] S5b: workdir missing from print-config
    set /a FAIL+=1
)

findstr /C:"token = 'restricted'" "!PCFG_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S5c: Token mode shown as restricted
    set /a PASS+=1
) else (
    echo   [FAIL] S5c: Token mode not shown correctly
    set /a FAIL+=1
)

powershell -NoProfile -Command "if (([System.IO.File]::ReadAllBytes('%PCFG_OUT%') | Where-Object { $_ -eq 0 }).Count -eq 0) { exit 0 } else { exit 1 }"
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S5d: Output has zero NUL bytes
    set /a PASS+=1
) else (
    echo   [FAIL] S5d: Output contains NUL bytes
    set /a FAIL+=1
)

del "!PCFG_OUT!" 2>nul

REM ===================================================================
REM S6 — LogFmt Session Markers
REM ===================================================================
echo.
echo --- S6: LogFmt Session Markers ---

REM Use lightweight cmd.exe config for speed
set LOGFMT_LOG=%TEMP%\sandy_logfmt_test.txt
set QUICK_CONFIG=%~dp0test_hardening_quick.toml
"!SANDY!" -c "!QUICK_CONFIG!" -l "!LOGFMT_LOG!" -x "C:\Windows\System32\cmd.exe" -- /c exit >nul 2>nul

REM Find log file — may have timestamp suffix
set LOG_FOUND=
for %%f in ("!LOGFMT_LOG!"*) do set LOG_FOUND=%%f

if defined LOG_FOUND (
    findstr /C:"=== Sandy Log ===" "!LOG_FOUND!" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] S6a: Session log has Sandy Log header
        set /a PASS+=1
    ) else (
        echo   [FAIL] S6a: Session log missing header
        set /a FAIL+=1
    )

    findstr /C:"=== Log end ===" "!LOG_FOUND!" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] S6b: Session log has clean end marker
        set /a PASS+=1
    ) else (
        echo   [FAIL] S6b: Session log missing end marker
        set /a FAIL+=1
    )

    findstr /C:"LOG_DIAG" "!LOG_FOUND!" >nul 2>nul
    if !ERRORLEVEL! NEQ 0 (
        echo   [PASS] S6c: No LOG_DIAG in normal session
        set /a PASS+=1
    ) else (
        echo   [FAIL] S6c: Unexpected LOG_DIAG in normal session
        set /a FAIL+=1
    )
    del "!LOG_FOUND!" 2>nul
) else (
    echo   [FAIL] S6a: No log file created
    set /a FAIL+=1
    echo   [FAIL] S6b: No log file created
    set /a FAIL+=1
    echo   [FAIL] S6c: No log file created
    set /a FAIL+=1
)

REM ===================================================================
REM S7 — Status Shows Summary Counts
REM ===================================================================
echo.
echo --- S7: Status Summary Counts ---

"!SANDY!" --status >"%TEMP%\sandy_hard_status.txt" 2>nul
findstr /C:"no active" "%TEMP%\sandy_hard_status.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S7a: --status reports clean state
    set /a PASS+=1
) else (
    echo   [FAIL] S7a: --status unexpected clean-state output
    set /a FAIL+=1
)

"!SANDY!" --status --json >"%TEMP%\sandy_hard_json.txt" 2>nul
findstr /C:"summary" "%TEMP%\sandy_hard_json.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S7b: --status --json includes summary
    set /a PASS+=1
) else (
    echo   [FAIL] S7b: --status --json missing summary
    set /a FAIL+=1
)

del "%TEMP%\sandy_hard_status.txt" 2>nul
del "%TEMP%\sandy_hard_json.txt" 2>nul

REM ===================================================================
REM S8 — Cleanup Idempotency
REM ===================================================================
echo.
echo --- S8: Cleanup Idempotency ---

"!SANDY!" --cleanup >nul 2>nul
set C1=!ERRORLEVEL!
"!SANDY!" --cleanup >nul 2>nul
set C2=!ERRORLEVEL!
"!SANDY!" --cleanup >nul 2>nul
set C3=!ERRORLEVEL!

if !C1! EQU 0 if !C2! EQU 0 if !C3! EQU 0 (
    echo   [PASS] S8: Three consecutive --cleanup calls return 0
    set /a PASS+=1
) else (
    echo   [FAIL] S8: --cleanup not idempotent
    set /a FAIL+=1
)

REM ===================================================================
REM Summary
REM ===================================================================
echo.
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.
if !FAIL! GTR 0 (
    echo Some tests FAILED!
    exit /b 1
)
exit /b 0
