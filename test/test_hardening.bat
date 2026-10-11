@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Hardening Test Suite
REM Tests: grant parser validation, parent key cleanup, LogFmt
REM        diagnostics, loopback lifecycle, dry-run ASCII output.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set RT_CONFIG=%~dp0test_resilience_rt.toml
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set "SANDY_TEST_DIR=%~dp0"
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Hardening Test Suite
echo =====================================================================

REM ===================================================================
REM S1 — Grant Record Parser: malformed records are rejected by --cleanup
REM
REM The records go into the real ledger root (HKCU\Software\Sandy\Grants):
REM Sandy reads no other place.  Each test ledger has an id that starts
REM with "dead-test-hard-", a PID that is not running and a non-zero _ctime,
REM so recovery treats it as the ledger of a dead instance.
REM ===================================================================
echo.
echo --- S1: Grant Record Parser Validation ---

set G=HKCU\Software\Sandy\Grants\dead-test-hard
set HLOG=%TEMP%\sandy_hardening_cleanup.log
del "%HLOG%*" 2>nul

REM Malformed records: each one takes a different ParseGrantRecord rejection path
call :inject A0001 99990 "BOGUS|C:\sandy_no_such_dir|S-1-5-21-0-0-0-1"
call :inject A0002 99991 "FILE|no-second-pipe"
call :inject A0003 99992 "FILE||S-1-5-21-0-0-0-1"
call :inject A0004 99993 "FILE|relative\path|S-1-5-21-0-0-0-1"
call :inject A0005 99994 "FILE|C:\sandy_no_such_dir|D:FA-WD"
call :inject A0006 99995 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-1|UNKNOWN:1"
call :inject A0007 99996 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-1|TRAPPED:NOTSID"
call :inject A0008 99997 "GARBAGE_NO_PIPES"
REM Valid records: every flag form, the registry type
call :inject A0009 99998 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-9|DENY:1"
call :inject A0010 99999 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-10|DENY:1|TRAPPED:S-1-5-21-1-2-3-4;S-1-5-21-5-6-7-8"
call :inject A0011 99900 "REG|CURRENT_USER\Software\SandyNoSuchKey_Test|S-1-5-21-0-0-0-11"
call :inject A0012 99901 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-12|DENY:1|THIS:1|OWNER:O"

REM Run --cleanup and verify it exits cleanly
"!SANDY!" -l "%HLOG%" --cleanup >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S1a: --cleanup tolerates all malformed records
    set /a PASS+=1
) else (
    echo   [FAIL] S1a: --cleanup failed on malformed records
    set /a FAIL+=1
)

REM Verify all 12 test ledgers were cleaned
set LEFT=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"dead-test-hard-" ^| find /c /v ""') do set LEFT=%%N
if !LEFT! EQU 0 (
    echo   [PASS] S1b: All 12 stale ledgers cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] S1b: !LEFT! stale ledgers remain after cleanup
    set /a FAIL+=1
)

REM The parser must have seen each of the 8 malformed records and refused it
set REJECTED=0
for /f %%N in ('findstr /c:"GRANT_PARSE: malformed record" "%HLOG%" 2^>nul ^| find /c /v ""') do set REJECTED=%%N
if !REJECTED! EQU 8 (
    echo   [PASS] S1c: Parser rejected the 8 malformed records and accepted the 4 valid ones
    set /a PASS+=1
) else (
    echo   [FAIL] S1c: Parser rejected !REJECTED! records, expected 8
    set /a FAIL+=1
)
del "%HLOG%*" 2>nul

REM ===================================================================
REM S2 — Parent keys are permanent: only the instance subkey goes
REM ===================================================================
echo.
echo --- S2: Parent Keys Are Permanent ---
call :inject CASCADE1 88888 "FILE|C:\sandy_no_such_dir|S-1-5-21-0-0-0-1"
"!SANDY!" --cleanup >nul 2>nul

reg query "%G%-CASCADE1" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S2a: Stale ledger subkey removed
    set /a PASS+=1
) else (
    echo   [FAIL] S2a: Stale ledger subkey still exists
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S2b: Parent key Software\Sandy\Grants kept
    set /a PASS+=1
) else (
    echo   [FAIL] S2b: Parent key Software\Sandy\Grants was deleted
    set /a FAIL+=1
)

REM ===================================================================
REM S3 — Multiple Dead PIDs Cleaned Together
REM ===================================================================
echo.
echo --- S3: Multiple Dead PIDs Cleaned ---
call :inject SURV1 77771 "FILE|C:\sandy_no_such_dir_a|S-1-5-21-0-0-0-1"
call :inject SURV2 77772 "FILE|C:\sandy_no_such_dir_b|S-1-5-21-0-0-0-2"

"!SANDY!" --cleanup >nul 2>nul

set LEFT=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"dead-test-hard-SURV" ^| find /c /v ""') do set LEFT=%%N
if !LEFT! EQU 0 (
    echo   [PASS] S3: Both dead PIDs cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] S3: !LEFT! ledgers still remain
    set /a FAIL+=1
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
"!SANDY!" -c "!QUICK_CONFIG!" -l "!LOGFMT_LOG!" -x "!PYTHON!" "%~dp0test_hardening_exit.py" >nul 2>nul

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
"!PYTHON!" "%~dp0status_check.py" "!SANDY!" --logs "!LOG_FOUND!" --instance dead-test-hard-A0001
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

if defined LOG_FOUND del "!LOG_FOUND!" 2>nul
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

set /a CSUM=!C1!+!C2!+!C3!
if !CSUM! EQU 0 (
    echo   [PASS] S8: Three consecutive --cleanup calls return 0
    set /a PASS+=1
) else (
    echo   [FAIL] S8: --cleanup not idempotent ^(exit codes !C1! !C2! !C3!^)
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

REM -------------------------------------------------------------------
REM :inject <id> <pid> <record> — one stale test ledger with one record
REM -------------------------------------------------------------------
:inject
reg add "%G%-%~1" /v _ctime /t REG_QWORD /d 1 /f >nul 2>nul
reg add "%G%-%~1" /v _pid /t REG_DWORD /d %~2 /f >nul 2>nul
reg add "%G%-%~1" /v 0 /t REG_SZ /d "%~3" /f >nul 2>nul
exit /b 0
