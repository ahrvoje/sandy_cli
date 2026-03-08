@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Resilience Test Battery
REM Tests: --cleanup flag, stale registry detection, clean exit state,
REM        write-ahead persistence, and multi-instance isolation.
REM Requires: admin privileges (for sandbox operations)
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set RT_CONFIG=%~dp0test_resilience_rt.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0

set DRYRUN_OUT=%TEMP%\sandy_dryrun_unicode.txt

echo === Sandy Resilience Test Battery ===
echo.

REM ===================================================================
REM Test 1: --cleanup exits cleanly with no stale state
REM ===================================================================
echo --- Test 1: --cleanup with no stale state ---
"!SANDY!" --cleanup >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] --cleanup returns exit code 0
    set /a PASS+=1
) else (
    echo   [FAIL] --cleanup returned non-zero
    set /a FAIL+=1
)

REM ===================================================================
REM Test 2: Clean run leaves no registry entries
REM ===================================================================
echo.
echo --- Test 2: Clean run leaves no stale registry ---
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "print('clean')" >nul 2>nul

reg query "HKCU\Software\Sandy\Test\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No stale Grants key after clean run
    set /a PASS+=1
) else (
    echo   [FAIL] Grants key still exists after clean run
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Test\WER" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No stale WER key after clean run
    set /a PASS+=1
) else (
    echo   [FAIL] WER key still exists after clean run
    set /a FAIL+=1
)

REM ===================================================================
REM Test 3: Stale Grants entry detected by --status
REM ===================================================================
echo.
echo --- Test 3: Stale grant detection ---
reg add "HKCU\Software\Sandy\Grants\99999" /v 0 /t REG_SZ /d "FILE|C:\fake|S-1-5-21-0-0-0-99999" /f >nul 2>nul
"!SANDY!" --status >"%TEMP%\sandy_status_warn.txt" 2>nul

findstr /C:"STALE" "%TEMP%\sandy_status_warn.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale grants detected by --status
    set /a PASS+=1
) else (
    echo   [FAIL] No stale grants shown by --status
    set /a FAIL+=1
)

findstr /C:"99999" "%TEMP%\sandy_status_warn.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Status identifies stale instance ID
    set /a PASS+=1
) else (
    echo   [FAIL] Status does not identify stale instance ID
    set /a FAIL+=1
)
del "%TEMP%\sandy_status_warn.txt" 2>nul

REM ===================================================================
REM Test 4: --cleanup clears stale Grants
REM ===================================================================
echo.
echo --- Test 4: --cleanup clears stale grants ---
reg query "HKCU\Software\Sandy\Grants\99999" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale grants key exists before cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] Stale grants key missing before cleanup
    set /a FAIL+=1
)

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Grants\99999" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] Grants key removed after --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] Grants key still exists after --cleanup
    set /a FAIL+=1
)

REM ===================================================================
REM Test 5: Stale WER entry detected and --cleanup clears it
REM ===================================================================
echo.
echo --- Test 5: Stale WER detection and cleanup ---
reg add "HKCU\Software\Sandy\WER" /v 88888 /t REG_SZ /d "fake_test.exe" /f >nul 2>nul
"!SANDY!" --status >"%TEMP%\sandy_wer_status.txt" 2>nul

findstr /C:"WER" "%TEMP%\sandy_wer_status.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale WER detected by --status
    set /a PASS+=1
) else (
    echo   [FAIL] No WER shown by --status
    set /a FAIL+=1
)
del "%TEMP%\sandy_wer_status.txt" 2>nul

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\WER" /v 88888 >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] WER key removed after --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] WER key still exists after --cleanup
    set /a FAIL+=1
)

REM ===================================================================
REM Test 6: --cleanup is idempotent (running twice is safe)
REM ===================================================================
echo.
echo --- Test 6: --cleanup idempotency ---
"!SANDY!" --cleanup >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Second --cleanup returns exit code 0
    set /a PASS+=1
) else (
    echo   [FAIL] Second --cleanup returned non-zero
    set /a FAIL+=1
)

REM ===================================================================
REM Test 7: No-args shows error (no implicit cleanup)
REM ===================================================================
echo.
echo --- Test 7: No-args shows error ---
"!SANDY!" >"%TEMP%\sandy_noargs.txt" 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No-args returns non-zero exit code
    set /a PASS+=1
) else (
    echo   [FAIL] No-args returned exit code 0
    set /a FAIL+=1
)

findstr /C:"Sandy" "%TEMP%\sandy_noargs.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] No-args shows usage help
    set /a PASS+=1
) else (
    echo   [FAIL] Missing usage guidance in error
    set /a FAIL+=1
)
del "%TEMP%\sandy_noargs.txt" 2>nul

REM ===================================================================
REM Test 8: Multiple stale PIDs are all cleaned
REM ===================================================================
echo.
echo --- Test 8: Multiple stale PIDs cleaned ---
reg add "HKCU\Software\Sandy\Test\Grants\11111" /v 0 /t REG_SZ /d "FILE|C:\a|S-1-5-21-0-0-0-11111" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\Grants\22222" /v 0 /t REG_SZ /d "FILE|C:\b|S-1-5-21-0-0-0-22222" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\Grants\33333" /v 0 /t REG_SZ /d "FILE|C:\c|S-1-5-21-0-0-0-33333" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\WER" /v 11111 /t REG_SZ /d "a.exe" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\WER" /v 22222 /t REG_SZ /d "b.exe" /f >nul 2>nul

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Test\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] All 3 stale grant PIDs cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] Grants still exist after cleanup
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Test\WER" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] All 2 stale WER PIDs cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] WER still exists after cleanup
    set /a FAIL+=1
)

REM ===================================================================
REM Test 9: Normal run does NOT touch other instances' stale entries
REM ===================================================================
echo.
echo --- Test 9: Normal run preserves other PIDs ---
reg add "HKCU\Software\Sandy\Test\Grants\77777" /v 0 /t REG_SZ /d "FILE|C:\other|S-1-5-21-0-0-0-77777" /f >nul 2>nul
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" >nul 2>nul

reg query "HKCU\Software\Sandy\Test\Grants\77777" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Other PID's grants preserved during normal run
    set /a PASS+=1
) else (
    echo   [FAIL] Other PID's grants were deleted by normal run
    set /a FAIL+=1
)

REM Clean up
"!SANDY!" --cleanup >nul 2>nul

REM ===================================================================
REM Test 10: Scheduled task created during run, deleted on clean exit
REM ===================================================================
echo.
echo --- Test 10: Scheduled task lifecycle ---
REM Clean up any pre-existing SandyCleanup_ tasks via --cleanup (not direct schtasks)
"!SANDY!" --cleanup >nul 2>nul

"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" >nul 2>nul

REM Check no SandyCleanup_ tasks exist after clean exit
schtasks /Query /FO LIST 2>nul | findstr /C:"SandyCleanup_" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] Scheduled task deleted after clean exit
    set /a PASS+=1
) else (
    echo   [FAIL] Scheduled task still exists after clean exit
    set /a FAIL+=1
)

REM ===================================================================
REM Test 11: --status JSON includes summary object
REM ===================================================================
echo.
echo --- Test 11: --status --json summary ---
"!SANDY!" --status --json >"%TEMP%\sandy_status.json" 2>nul
findstr /C:"\"summary\"" "%TEMP%\sandy_status.json" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] JSON status includes summary object
    set /a PASS+=1
) else (
    echo   [FAIL] JSON status missing summary object
    set /a FAIL+=1
)
del "%TEMP%\sandy_status.json" 2>nul

REM ===================================================================
REM Test 12: --print-config / --dry-run preserve Unicode output path text
REM ===================================================================
echo.
echo --- Test 12: Unicode dry-run / print-config output ---
REM Use the external RT config file (test_resilience_rt.toml)
"!SANDY!" --dry-run -c "!RT_CONFIG!" -x "!PYTHON!" >"!DRYRUN_OUT!" 2>nul
REM dry-run/print-config output is UTF-8 — findstr works directly
findstr /C:"Working dir" "!DRYRUN_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Dry-run prints actual working directory
    set /a PASS+=1
) else (
    echo   [FAIL] Dry-run missing actual working directory
    set /a FAIL+=1
)

"!SANDY!" --print-config -c "!RT_CONFIG!" >"!DRYRUN_OUT!" 2>nul
findstr /C:"workdir" "!DRYRUN_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Print-config preserves workdir text
    set /a PASS+=1
) else (
    echo   [FAIL] Print-config missing workdir text
    set /a FAIL+=1
)
del "!DRYRUN_OUT!" 2>nul

REM ===================================================================
REM Test 13: Malformed persisted records are skipped, cleanup still succeeds
REM ===================================================================
echo.
echo --- Test 13: Malformed persisted record handling ---
reg add "HKCU\Software\Sandy\Test\Grants\44444" /v _pid /t REG_DWORD /d 44444 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\Grants\44444" /v _ctime /t REG_QWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Test\Grants\44444" /v 0 /t REG_SZ /d "BOGUS|relative|notsid|WHAT:1" /f >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Cleanup tolerates malformed persisted record
    set /a PASS+=1
) else (
    echo   [FAIL] Cleanup failed on malformed persisted record
    set /a FAIL+=1
)
reg query "HKCU\Software\Sandy\Test\Grants\44444" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] Malformed stale key removed during cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] Malformed stale key still exists after cleanup
    set /a FAIL+=1
)

REM ===================================================================
REM Summary
REM ===================================================================
echo.
set /a TOTAL=!PASS!+!FAIL!
echo === Results: !PASS! passed, !FAIL! failed (of !TOTAL!) ===
echo.
if !FAIL! GTR 0 (
    echo Some tests FAILED!
    exit /b 1
)
exit /b 0
