@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion

REM =====================================================================
REM test_bugs.bat — Config defects that were found once must stay fixed
REM
REM Each case is one config that Sandy accepted in an earlier version
REM although it is wrong.  PASS = Sandy rejects it (or warns) now.
REM Configs are passed inline with -s; --dry-run changes no system state.
REM =====================================================================

echo =====================================================================
echo  Sandy Config Regression Tests (former bug detectors)
echo =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
if not exist "!SANDY!" (
    echo   [FAIL] Sandy not found at: !SANDY!
    exit /b 1
)

set PASS=0
set FAIL=0
set OUT=%TEMP%\sandy_bugs_out.txt

REM --- 1: the same key twice in one section ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\Windows']\nread = ['C:\Users']" >"%OUT%" 2>&1
call :expect_exit 128 "1: duplicate key in a section is rejected"

REM --- 2: limit value beyond the allowed range (was clamped silently) ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[limit]\ntimeout = 99999999999" >"%OUT%" 2>&1
call :expect_exit 128 "2: timeout overflow is rejected"

REM --- 3: the same path in two spellings (Windows paths ignore case) ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\Windows', 'c:\windows']" >"%OUT%" 2>&1
findstr /C:"Duplicate path" "%OUT%" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 3: case-different duplicate path gives a warning
    set /a PASS+=1
) else (
    echo   [FAIL] 3: case-different duplicate path gives no warning
    type "%OUT%"
    set /a FAIL+=1
)

REM --- 4: empty string in a path array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['', 'C:\Windows']" >"%OUT%" 2>&1
call :expect_exit 128 "4: empty path in an allow array is rejected"

REM --- 5: empty string in the environment pass array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[environment]\npass = ['', 'PATH', '']" >"%OUT%" 2>&1
call :expect_exit 128 "5: empty variable name in [environment] pass is rejected"

REM --- 6: the same section header twice ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\Windows']\n[allow.deep]\nwrite = ['C:\Users']" >"%OUT%" 2>&1
call :expect_exit 128 "6: duplicate section header is rejected"

REM --- 7: memory limit beyond the allowed range ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[limit]\nmemory = 3000000" >"%OUT%" 2>&1
call :expect_exit 128 "7: memory limit overflow is rejected"

del "%OUT%" 2>nul

echo.
echo =====================================================================
echo  Config Regression Results: !PASS! passed, !FAIL! failed (of 7)
echo =====================================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0

REM ---------------------------------------------------------------------
REM :expect_exit <code> <label> — the Sandy call before this must have
REM ended with <code>.  ERRORLEVEL is read first, before anything else.
REM ---------------------------------------------------------------------
:expect_exit
set GOT=!ERRORLEVEL!
if !GOT! EQU %~1 (
    echo   [PASS] %~2
    set /a PASS+=1
) else (
    echo   [FAIL] %~2 ^(exit !GOT!, expected %~1^)
    type "%OUT%"
    set /a FAIL+=1
)
exit /b 0
