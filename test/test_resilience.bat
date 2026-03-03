@echo off
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Resilience Test Battery
REM Tests: --cleanup flag, stale registry detection, clean exit state,
REM        write-ahead persistence, and multi-instance isolation.
REM Requires: admin privileges (for sandbox operations)
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0

echo === Sandy Resilience Test Battery ===
echo.

REM ===================================================================
REM Test 1: --cleanup exits cleanly with no stale state
REM ===================================================================
echo --- Test 1: --cleanup with no stale state ---
"!SANDY!" --cleanup 2>nul
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

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No stale Grants key after clean run
    set /a PASS+=1
) else (
    echo   [FAIL] Grants key still exists after clean run
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\WER" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No stale WER key after clean run
    set /a PASS+=1
) else (
    echo   [FAIL] WER key still exists after clean run
    set /a FAIL+=1
)

REM ===================================================================
REM Test 3: Stale Grants entry triggers startup warning
REM ===================================================================
echo.
echo --- Test 3: Stale grant detection ---
reg add "HKCU\Software\Sandy\Grants\99999" /v 0 /t REG_SZ /d "FILE|C:\fake|D:(A;;FA;;;WD)" /f >nul 2>nul
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" 2>"%TEMP%\sandy_warn.txt"

findstr /C:"WARNING" "%TEMP%\sandy_warn.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale grants warning detected
    set /a PASS+=1
) else (
    echo   [FAIL] No warning for stale grants
    set /a FAIL+=1
)

findstr /C:"--cleanup" "%TEMP%\sandy_warn.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Warning mentions --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] Warning does not mention --cleanup
    set /a FAIL+=1
)
del "%TEMP%\sandy_warn.txt" 2>nul

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

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] Grants key removed after --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] Grants key still exists after --cleanup
    set /a FAIL+=1
)

REM ===================================================================
REM Test 5: Stale WER entry triggers warning and --cleanup clears it
REM ===================================================================
echo.
echo --- Test 5: Stale WER detection and cleanup ---
reg add "HKCU\Software\Sandy\WER" /v 88888 /t REG_SZ /d "fake_test.exe" /f >nul 2>nul
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" 2>"%TEMP%\sandy_wer_warn.txt"

findstr /C:"WARNING" "%TEMP%\sandy_wer_warn.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale WER warning detected
    set /a PASS+=1
) else (
    echo   [FAIL] No warning for stale WER
    set /a FAIL+=1
)
del "%TEMP%\sandy_wer_warn.txt" 2>nul

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\WER" >nul 2>nul
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
"!SANDY!" >nul 2>"%TEMP%\sandy_noargs.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No-args returns non-zero exit code
    set /a PASS+=1
) else (
    echo   [FAIL] No-args returned exit code 0
    set /a FAIL+=1
)

findstr /C:"-x is required" "%TEMP%\sandy_noargs.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Error message shows usage guidance
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
reg add "HKCU\Software\Sandy\Grants\11111" /v 0 /t REG_SZ /d "FILE|C:\a|D:(A;;FA;;;WD)" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\22222" /v 0 /t REG_SZ /d "FILE|C:\b|D:(A;;FA;;;WD)" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\33333" /v 0 /t REG_SZ /d "FILE|C:\c|D:(A;;FA;;;WD)" /f >nul 2>nul
reg add "HKCU\Software\Sandy\WER" /v 11111 /t REG_SZ /d "a.exe" /f >nul 2>nul
reg add "HKCU\Software\Sandy\WER" /v 22222 /t REG_SZ /d "b.exe" /f >nul 2>nul

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] All 3 stale grant PIDs cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] Grants still exist after cleanup
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\WER" >nul 2>nul
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
reg add "HKCU\Software\Sandy\Grants\77777" /v 0 /t REG_SZ /d "FILE|C:\other|D:(A;;FA;;;WD)" /f >nul 2>nul
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" >nul 2>nul

reg query "HKCU\Software\Sandy\Grants\77777" >nul 2>nul
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
schtasks /Delete /TN "SandyCleanup" /F >nul 2>nul

"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" -c "pass" >nul 2>nul

schtasks /Query /TN "SandyCleanup" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] Scheduled task deleted after clean exit
    set /a PASS+=1
) else (
    echo   [FAIL] Scheduled task still exists after clean exit
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
