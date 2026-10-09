@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ============================================================
REM Concurrent Sandy Container Test Battery
REM Launches 3 containers with different grants on the same folder,
REM checks --status while all are running, checks what each container
REM could do, and checks that nothing is left when all have ended.
REM
REM Launches are staggered by 5s: each instance grants on the shared
REM Python directory, and the grants are serialized.
REM
REM Self-contained: all artifacts under %USERPROFILE%\test_concurrent
REM   scripts/  — probe script (read by all containers)
REM   data/     — shared test data folder (different access per container)
REM ============================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set TEST=%~dp0
set ROOT=%USERPROFILE%\test_concurrent
set WAIT=25
set PASS=0
set FAIL=0

echo ============================================================
echo  Concurrent Sandy Container Test Battery
echo  3 containers, same folder, different grants
echo  (staggered 5s apart)
echo ============================================================
echo.

REM Cleanup stale state
"%SANDY%" --cleanup >nul 2>nul

REM Create test folder structure
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\data"
echo concurrent test seed > "%ROOT%\data\seed.txt"
copy /y "%TEST%concurrent_probe.py" "%ROOT%\scripts\concurrent_probe.py" >nul
set PROBE=%ROOT%\scripts\concurrent_probe.py
del "%TEMP%\sandy_conc_*.txt" 2>nul
echo Created: %ROOT%
echo.

echo [1/6] Launching container 1 (READ)...
start /b "" "%SANDY%" -c "%TEST%concurrent_read.toml" -q -x "%PYTHON%" "%PROBE%" read %WAIT% >"%TEMP%\sandy_conc_read.txt" 2>&1
ping -n 6 127.0.0.1 >nul

echo [2/6] Launching container 2 (WRITE)...
start /b "" "%SANDY%" -c "%TEST%concurrent_write.toml" -q -x "%PYTHON%" "%PROBE%" write %WAIT% >"%TEMP%\sandy_conc_write.txt" 2>&1
ping -n 6 127.0.0.1 >nul

echo [3/6] Launching container 3 (ALL)...
start /b "" "%SANDY%" -c "%TEST%concurrent_all.toml" -q -x "%PYTHON%" "%PROBE%" all %WAIT% >"%TEMP%\sandy_conc_all.txt" 2>&1
ping -n 5 127.0.0.1 >nul

echo.
echo [4/6] Status check (all 3 must be active):
"%SANDY%" --status >"%TEMP%\sandy_conc_status.txt" 2>nul
type "%TEMP%\sandy_conc_status.txt"
set ACTIVE=0
for /f %%N in ('findstr /c:"[ACTIVE]" "%TEMP%\sandy_conc_status.txt" ^| find /c /v ""') do set ACTIVE=%%N
if !ACTIVE! EQU 3 (
    echo   [PASS] --status shows 3 active instances
    set /a PASS+=1
) else (
    echo   [FAIL] --status shows !ACTIVE! active instances, expected 3
    set /a FAIL+=1
)
echo.

echo [5/6] Waiting for containers to finish...
set ACTIVE=1
for /l %%W in (1,1,30) do (
    if !ACTIVE! NEQ 0 (
        ping -n 3 127.0.0.1 >nul
        set ACTIVE=0
        "%SANDY%" --status >"%TEMP%\sandy_conc_status.txt" 2>nul
        for /f %%N in ('findstr /c:"[ACTIVE]" "%TEMP%\sandy_conc_status.txt" ^| find /c /v ""') do set ACTIVE=%%N
    )
)
if !ACTIVE! EQU 0 (
    echo   [PASS] All containers ended
    set /a PASS+=1
) else (
    echo   [FAIL] !ACTIVE! containers still active after the wait
    set /a FAIL+=1
)
echo.

echo [6/6] What each container could do in the shared folder:
REM read: list + read, no write
call :expect read  "LIST:  OK"       "read container can list"
call :expect read  "READ:  OK"       "read container can read"
call :expect read  "WRITE: BLOCKED"  "read container cannot write"
REM write: write, no list, no read, no delete
call :expect write "WRITE: OK"       "write container can write"
call :expect write "LIST:  BLOCKED"  "write container cannot list"
call :expect write "READ:  BLOCKED"  "write container cannot read"
call :expect write "DEL:   BLOCKED"  "write container cannot delete"
REM all: everything
call :expect all   "LIST:  OK"       "all container can list"
call :expect all   "READ:  OK"       "all container can read"
call :expect all   "WRITE: OK"       "all container can write"
call :expect all   "DEL:   OK"       "all container can delete"
echo.

echo Post-run state:
set LEDGERS=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set LEDGERS=%%N
if !LEDGERS! EQU 0 (
    echo   [PASS] No ledger left under Grants
    set /a PASS+=1
) else (
    echo   [FAIL] !LEDGERS! ledgers left under Grants
    set /a FAIL+=1
)
set SC=0
for /f %%N in ('icacls "%ROOT%\data" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No AppContainer ACE left on the shared folder
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! AppContainer ACE entries left on the shared folder
    set /a FAIL+=1
)

REM Cleanup
"%SANDY%" --cleanup >nul 2>nul
del "%TEMP%\sandy_conc_*.txt" 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

set /a TOTAL=!PASS!+!FAIL!
echo.
echo ============================================================
echo  Concurrent test: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo ============================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0

REM ------------------------------------------------------------
REM :expect <role> <text> <label> — the output of that container
REM must hold <text>
REM ------------------------------------------------------------
:expect
findstr /c:%2 "%TEMP%\sandy_conc_%~1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] %~3
    set /a PASS+=1
) else (
    echo   [FAIL] %~3
    type "%TEMP%\sandy_conc_%~1.txt"
    set /a FAIL+=1
)
exit /b 0
