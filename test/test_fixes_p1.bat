@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Post-P1 Fixes Test Suite
echo =====================================================================

"!SANDY!" --delete-profile f1_test >nul 2>nul
"!SANDY!" --delete-profile f2_test >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul

echo [sandbox] > "%TEMP%\sandy_f1_config.toml"
echo token = 'appcontainer' >> "%TEMP%\sandy_f1_config.toml"

echo [sandbox] > "%TEMP%\sandy_f2_config.toml"
echo token = 'restricted' >> "%TEMP%\sandy_f2_config.toml"
echo integrity = 'low' >> "%TEMP%\sandy_f2_config.toml"

REM ===================================================================
REM F1: Profile Creation Serialization Strictness
REM ===================================================================
echo.
echo --- F1: Profile Creation Serialization Strictness ---

start /b "" "!SANDY!" --create-profile f1_test -c "%TEMP%\sandy_f1_config.toml" >"%TEMP%\sandy_f1_1.txt" 2>&1
start /b "" "!SANDY!" --create-profile f1_test -c "%TEMP%\sandy_f1_config.toml" >"%TEMP%\sandy_f1_2.txt" 2>&1

REM Wait for both to finish
:wait_f1
tasklist /FI "IMAGENAME eq sandy.exe" 2>nul | findstr /I "sandy.exe" >nul
if !ERRORLEVEL! EQU 0 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_f1
)

set SUCCESS_COUNT=0
set FAIL_COUNT=0

findstr /C:"created successfully" "%TEMP%\sandy_f1_1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 set /a SUCCESS_COUNT+=1
findstr /C:"created successfully" "%TEMP%\sandy_f1_2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 set /a SUCCESS_COUNT+=1

findstr /C:"already exists or is being created" "%TEMP%\sandy_f1_1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 set /a FAIL_COUNT+=1
findstr /C:"already exists or is being created" "%TEMP%\sandy_f1_2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 set /a FAIL_COUNT+=1

if !SUCCESS_COUNT! EQU 1 (
    echo   [PASS] F1a: Exactly one profile creation succeeded
    set /a PASS+=1
) else (
    echo   [FAIL] F1a: Expected 1 success, got !SUCCESS_COUNT!
    type "%TEMP%\sandy_f1_1.txt"
    type "%TEMP%\sandy_f1_2.txt"
    set /a FAIL+=1
)

if !FAIL_COUNT! EQU 1 (
    echo   [PASS] F1b: Exactly one profile creation was rejected due to lock
    set /a PASS+=1
) else (
    echo   [FAIL] F1b: Expected 1 rejection, got !FAIL_COUNT!
    type "%TEMP%\sandy_f1_1.txt"
    type "%TEMP%\sandy_f1_2.txt"
    set /a FAIL+=1
)

del "%TEMP%\sandy_f1_1.txt" 2>nul
del "%TEMP%\sandy_f1_2.txt" 2>nul

REM ===================================================================
REM F2: Hardening Restricted-Profile Keys
REM ===================================================================
echo.
echo --- F2: Hardening Restricted-Profile Keys ---

"!SANDY!" --create-profile f2_test -c "%TEMP%\sandy_f2_config.toml" >nul 2>nul
"!SANDY!" -p f2_test -x C:\Windows\System32\reg.exe delete HKCU\Software\Sandy\Profiles\f2_test /f >"%TEMP%\sandy_f2.txt" 2>&1

findstr /C:"Access is denied" "%TEMP%\sandy_f2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] F2a: Sandboxed child got Access Denied modifying its profile key
    set /a PASS+=1
) else (
    echo   [FAIL] F2a: Sandboxed child could modify its profile key
    type "%TEMP%\sandy_f2.txt"
    set /a FAIL+=1
)

reg query HKCU\Software\Sandy\Profiles\f2_test >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] F2b: Profile key still exists
    set /a PASS+=1
) else (
    echo   [FAIL] F2b: Profile key was deleted
    set /a FAIL+=1
)

del "%TEMP%\sandy_f2.txt" 2>nul

REM ===================================================================
REM F3: Transient Bare-Run Liveness Tracking
REM ===================================================================
echo.
echo --- F3: Transient Bare-Run Liveness Tracking ---

REM Create a minimal AC config with no grants
echo [sandbox] > "%TEMP%\sandy_f3_config.toml"
echo token = 'appcontainer' >> "%TEMP%\sandy_f3_config.toml"

REM Run a 4 second sleep in background
start /b "" "!SANDY!" -c "%TEMP%\sandy_f3_config.toml" -x cmd.exe /c "ping 127.0.0.1 -n 5 >nul"

REM Give it a moment to lock and create the ledger
ping 127.0.0.1 -n 2 >nul

"!SANDY!" --status >"%TEMP%\sandy_f3_out.txt" 2>&1

findstr /C:"appcontainer" "%TEMP%\sandy_f3_out.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] F3a: Zero-grant bare run appears in --status
    set /a PASS+=1
) else (
    echo   [FAIL] F3a: Zero-grant bare run missing from --status
    echo -- --status output was:
    type "%TEMP%\sandy_f3_out.txt"
    set /a FAIL+=1
)

REM Cleanup background process naturally
:wait_f3
tasklist /FI "IMAGENAME eq ping.exe" 2>nul | findstr /I "ping.exe" >nul
if !ERRORLEVEL! EQU 0 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_f3
)

del "%TEMP%\sandy_f3_config.toml" 2>nul
del "%TEMP%\sandy_f3_out.txt" 2>nul

REM ===================================================================
REM Final cleanup
REM ===================================================================
"!SANDY!" --delete-profile f1_test >nul 2>nul
"!SANDY!" --delete-profile f2_test >nul 2>nul
del "%TEMP%\sandy_f1_config.toml" 2>nul
del "%TEMP%\sandy_f2_config.toml" 2>nul

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
