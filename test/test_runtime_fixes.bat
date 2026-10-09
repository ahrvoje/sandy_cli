@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Runtime Fixes Test
REM
REM   T1  timeout: ends the run when the root process has exited but a
REM       descendant still runs (exit 130, descendant ended)
REM   T2  desktop = false: the sandbox cannot list or use windows of other processes
REM   T3  session log: the child does not inherit a handle to the log
REM   T4  command line: options after -x belong to the child (-l, -q, ...)
REM   T5  session log rotation: the given path holds the newest run
REM   T6  strict restricted token: the sandbox can start child processes
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_runtime_fixes
set PROBE=%ROOT%\scripts\test_runtime_fixes.py
set OUT=%TEMP%\sandy_rtfix
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Runtime Fixes Test
echo  timeout tree, desktop isolation, session log, command line, strict
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\work"
copy /y "%~dp0test_runtime_fixes.py" "%PROBE%" >nul
del "%OUT%_*.txt" 2>nul

REM =====================================================================
REM T1: timeout on a process tree
REM =====================================================================
echo --- T1: timeout ends a run whose root process has already exited ---
set MARKER=%ROOT%\work\descendant_alive.txt
"%SANDY%" -c "%~dp0test_runtime_fixes_timeout.toml" -q -x "%PYTHON%" "%PROBE%" spawn "%MARKER%" 8 >"%OUT%_t1.txt" 2>&1
set RC=!ERRORLEVEL!
findstr /c:"SPAWN: root exits" "%OUT%_t1.txt" >nul 2>nul
call :expect0 !ERRORLEVEL! "T1a: root process started a descendant and exited"
if !RC! EQU 130 (
    echo   [PASS] T1b: Sandy waited for the tree and the timeout ended it ^(exit 130^)
    set /a PASS+=1
) else (
    echo   [FAIL] T1b: exit code !RC!, expected 130
    set /a FAIL+=1
)
REM The descendant writes its marker 8 s after start.  Wait past that moment.
ping -n 10 127.0.0.1 >nul
if not exist "%MARKER%" (
    echo   [PASS] T1c: the descendant was ended with the run
    set /a PASS+=1
) else (
    echo   [FAIL] T1c: the descendant outlived the run and wrote its marker
    set /a FAIL+=1
)
echo.

REM =====================================================================
REM T2: desktop = false
REM =====================================================================
echo --- T2: desktop = false cuts the sandbox off from the windows of other processes ---
"%SANDY%" -c "%~dp0test_runtime_fixes_desktop_on.toml" -q -x "%PYTHON%" "%PROBE%" desktop >"%OUT%_t2on.txt" 2>&1
"%SANDY%" -c "%~dp0test_runtime_fixes_desktop_off.toml" -q -x "%PYTHON%" "%PROBE%" desktop >"%OUT%_t2off.txt" 2>&1
set WIN_ON=0
set WIN_OFF=-1
for /f "tokens=2" %%N in ('findstr /c:"WINDOWS:" "%OUT%_t2on.txt"') do set WIN_ON=%%N
for /f "tokens=2" %%N in ('findstr /c:"WINDOWS:" "%OUT%_t2off.txt"') do set WIN_OFF=%%N
findstr /c:"TASKBAR: REACHABLE" "%OUT%_t2on.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [INFO] T2: no taskbar window in this session - the isolation cannot be shown here
) else (
    findstr /c:"TASKBAR: BLOCKED" "%OUT%_t2off.txt" >nul 2>nul
    call :expect0 !ERRORLEVEL! "T2a: a message to the taskbar window works with desktop = true and fails with desktop = false"
    set OK=0
    if !WIN_OFF! GEQ 0 if !WIN_OFF! LSS !WIN_ON! set OK=1
    if !OK! EQU 1 (
        echo   [PASS] T2b: top-level windows visible: !WIN_ON! with desktop = true, !WIN_OFF! with desktop = false
        set /a PASS+=1
    ) else (
        echo   [FAIL] T2b: top-level windows visible: !WIN_ON! with desktop = true, !WIN_OFF! with desktop = false
        set /a FAIL+=1
    )
)
echo.

REM =====================================================================
REM T3: the child does not inherit the session log handle
REM =====================================================================
echo --- T3: session log handle is not inherited by the child ---
set LOG=%ROOT%\session.log
"%SANDY%" -c "%~dp0test_runtime_fixes_plain.toml" -q -l "%LOG%" -x "%PYTHON%" "%PROBE%" loghandle session.log >"%OUT%_t3.txt" 2>&1
findstr /c:"LOGHANDLE: NONE" "%OUT%_t3.txt" >nul 2>nul
call :expect0 !ERRORLEVEL! "T3a: child holds no handle to the session log"
findstr /c:"FORGED-BY-CHILD" "%LOG%" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] T3b: session log holds no line written by the child
    set /a PASS+=1
) else (
    echo   [FAIL] T3b: the child wrote into the session log
    set /a FAIL+=1
)
findstr /c:"LAUNCH:" "%LOG%" >nul 2>nul
call :expect0 !ERRORLEVEL! "T3c: session log was written by Sandy"
echo.

REM =====================================================================
REM T4: everything after -x belongs to the child
REM =====================================================================
echo --- T4: options after -x are passed to the child ---
for %%O in (-l --log -q -c --status --cleanup) do (
    "%SANDY%" -c "%~dp0test_runtime_fixes_plain.toml" -q -x "%ComSpec%" /c echo forwarded %%O >"%OUT%_t4.txt" 2>&1
    set RC=!ERRORLEVEL!
    set OK=0
    findstr /c:"forwarded %%O" "%OUT%_t4.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 if !RC! EQU 0 set OK=1
    if !OK! EQU 1 (
        echo   [PASS] T4: trailing %%O reached the child
        set /a PASS+=1
    ) else (
        echo   [FAIL] T4: trailing %%O did not reach the child ^(exit !RC!^)
        type "%OUT%_t4.txt"
        set /a FAIL+=1
    )
)
echo.

REM =====================================================================
REM T5: log rotation
REM =====================================================================
echo --- T5: the path given to -l holds the newest run ---
set RLOG=%ROOT%\rot.log
for %%R in (1 2 3) do "%SANDY%" -c "%~dp0test_runtime_fixes_plain.toml" -q -l "%RLOG%" -x "%ComSpec%" /c echo rotation-run-%%R >nul 2>nul
findstr /c:"rotation-run-3" "%RLOG%" >nul 2>nul
call :expect0 !ERRORLEVEL! "T5a: rot.log holds run 3 (the newest)"
findstr /c:"rotation-run-1" /c:"rotation-run-2" "%RLOG%" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] T5b: rot.log holds no older run
    set /a PASS+=1
) else (
    echo   [FAIL] T5b: rot.log still holds an older run
    set /a FAIL+=1
)
findstr /c:"rotation-run-1" "%RLOG%.1" >nul 2>nul
call :expect0 !ERRORLEVEL! "T5c: rot.log.1 holds run 1"
findstr /c:"rotation-run-2" "%RLOG%.2" >nul 2>nul
call :expect0 !ERRORLEVEL! "T5d: rot.log.2 holds run 2"
echo.

REM =====================================================================
REM T6: strict restricted token can start child processes
REM =====================================================================
echo --- T6: strict = true can start a child process ---
"%SANDY%" -c "%~dp0test_runtime_fixes_strict.toml" -q -x "%PYTHON%" "%PROBE%" child >"%OUT%_t6.txt" 2>&1
findstr /c:"CHILD: 42 (exit 0)" "%OUT%_t6.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] T6: child process started and its output was read
    set /a PASS+=1
) else (
    echo   [FAIL] T6: child process did not run
    type "%OUT%_t6.txt"
    set /a FAIL+=1
)
echo.

REM === Post-run state ===
set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    echo   [FAIL] !REMAIN! grant subkeys persist
    set /a FAIL+=1
)

REM === Final Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
del "%OUT%_*.txt" 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

set /a TOTAL=!PASS!+!FAIL!
echo.
echo =====================================================================
echo  Runtime Fixes: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0

REM ---------------------------------------------------------------------
REM :expect0 <errorlevel> <label> — errorlevel 0 is a pass
REM ---------------------------------------------------------------------
:expect0
REM The label goes through a variable: a ")" in it must not close the block.
set "LABEL=%~2"
if %~1 EQU 0 (
    echo   [PASS] !LABEL!
    set /a PASS+=1
) else (
    echo   [FAIL] !LABEL!
    set /a FAIL+=1
)
exit /b 0
