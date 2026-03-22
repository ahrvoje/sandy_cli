@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy config scalar guard regression test
REM Verifies malformed array/empty-string values for scalar-only keys are
REM rejected instead of silently collapsing into permissive defaults.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Config Scalar Guard Test
echo =====================================================================

if not exist "!SANDY!" (
    echo   [SKIP] sandy.exe not found at !SANDY!
    exit /b 0
)

echo.
echo --- SG1: workdir = [] rejected ---

"!SANDY!" --print-config -s "[sandbox]\ntoken = 'appcontainer'\nworkdir = []" >nul 2>"%TEMP%\sandy_sg1.txt"
set SG1_EC=!ERRORLEVEL!

if !SG1_EC! EQU 128 (
    echo   [PASS] SG1a: workdir array rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] SG1a: exit code !SG1_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'workdir' in [sandbox] must be a scalar value, got array." "%TEMP%\sandy_sg1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SG1b: workdir array rejection message shown
    set /a PASS+=1
) else (
    echo   [FAIL] SG1b: missing workdir array rejection message
    set /a FAIL+=1
)

del "%TEMP%\sandy_sg1.txt" 2>nul

echo.
echo --- SG2: workdir = '' rejected ---

"!SANDY!" --print-config -s "[sandbox]\ntoken = 'appcontainer'\nworkdir = ''" >nul 2>"%TEMP%\sandy_sg2.txt"
set SG2_EC=!ERRORLEVEL!

if !SG2_EC! EQU 128 (
    echo   [PASS] SG2a: empty workdir rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] SG2a: exit code !SG2_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'workdir' in [sandbox] must be 'inherit' or a path, got empty string." "%TEMP%\sandy_sg2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SG2b: empty workdir rejection message shown
    set /a PASS+=1
) else (
    echo   [FAIL] SG2b: missing empty workdir rejection message
    set /a FAIL+=1
)

del "%TEMP%\sandy_sg2.txt" 2>nul

echo.
echo --- SG3: stdin = [] rejected ---

"!SANDY!" --print-config -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nstdin = []" >nul 2>"%TEMP%\sandy_sg3.txt"
set SG3_EC=!ERRORLEVEL!

if !SG3_EC! EQU 128 (
    echo   [PASS] SG3a: stdin array rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] SG3a: exit code !SG3_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'stdin' in [privileges] must be a scalar value, got array." "%TEMP%\sandy_sg3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SG3b: stdin array rejection message shown
    set /a PASS+=1
) else (
    echo   [FAIL] SG3b: missing stdin array rejection message
    set /a FAIL+=1
)

del "%TEMP%\sandy_sg3.txt" 2>nul

echo.
echo --- SG4: stdin = '' rejected ---

"!SANDY!" --print-config -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nstdin = ''" >nul 2>"%TEMP%\sandy_sg4.txt"
set SG4_EC=!ERRORLEVEL!

if !SG4_EC! EQU 128 (
    echo   [PASS] SG4a: empty stdin rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] SG4a: exit code !SG4_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'stdin' in [privileges] must be true, false, or a path, got empty string." "%TEMP%\sandy_sg4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SG4b: empty stdin rejection message shown
    set /a PASS+=1
) else (
    echo   [FAIL] SG4b: missing empty stdin rejection message
    set /a FAIL+=1
)

del "%TEMP%\sandy_sg4.txt" 2>nul

echo.
echo =====================================================================
echo  PASS: !PASS!   FAIL: !FAIL!
echo =====================================================================

if !FAIL! NEQ 0 exit /b 1
exit /b 0
