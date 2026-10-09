@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Interrupt Test
REM
REM Sandy is interrupted at the moments where a leak is most likely:
REM   Part 1  killed in the middle of a grant on a large tree
REM           -- sandy --cleanup must remove every ACE of that run
REM   Part 2  Ctrl+C while the sandboxed child runs
REM           -- Sandy must clean up by itself; exit code 0xC000013A
REM   Part 3  restricted-token runs killed while the child runs
REM           -- sandy --cleanup must remove the desktop ACEs of the runs
REM
REM The driver ends only the Sandy processes that it started (by handle).
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set DRIVER=%~dp0test_interrupt.py
set ROOT=%USERPROFILE%\test_interrupt
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Interrupt Test
echo  kill during grant, Ctrl+C, desktop ACE recovery
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create the trees ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%"
"%PYTHON%" "%DRIVER%" build "%ROOT%"
echo.

echo === Part 1: Sandy killed in the middle of a grant ===
"%PYTHON%" "%DRIVER%" killgrant "%ROOT%"
call :verdict !ERRORLEVEL! "Part 1: kill during grant"
echo.

echo === Part 2: Ctrl+C while the child runs ===
"%PYTHON%" "%DRIVER%" ctrlc "%ROOT%"
call :verdict !ERRORLEVEL! "Part 2: Ctrl+C"
echo.

echo === Part 3: desktop ACEs of killed runs ===
"%PYTHON%" "%DRIVER%" desktop "%ROOT%"
call :verdict !ERRORLEVEL! "Part 3: desktop ACE recovery"
echo.

REM === Post-run state ===
"%SANDY%" --cleanup >nul 2>nul
set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    echo   [FAIL] !REMAIN! grant subkeys persist
    set /a FAIL+=1
)
schtasks /Query /FO LIST 2>nul | findstr /C:"SandyCleanup_" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No cleanup task remains
    set /a PASS+=1
) else (
    echo   [FAIL] A SandyCleanup_ task remains
    set /a FAIL+=1
)

REM === Final Cleanup ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"

set /a TOTAL=!PASS!+!FAIL!
echo.
echo =====================================================================
echo  Interrupt Test: !PASS! passed, !FAIL! failed (of !TOTAL! batch checks)
echo =====================================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0

REM ---------------------------------------------------------------------
REM :verdict <exit code> <label> — exit code 0 is a pass
REM ---------------------------------------------------------------------
:verdict
REM The label goes through a variable: a ")" in it must not close the block.
set "LABEL=%~2"
if %~1 EQU 0 (
    echo   [PASS] !LABEL!
    set /a PASS+=1
) else (
    echo   [FAIL] !LABEL! ^(exit code %~1^)
    set /a FAIL+=1
)
exit /b 0
