@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy config path guard regression test
REM Verifies launch-critical filesystem paths are rejected during config
REM validation instead of surviving into runtime or dry-run previews.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set TMP_DIR=%TEMP%\sandy_path_guard_dir
set TMP_FILE=%TEMP%\sandy_path_guard_file.txt
set MISSING_FILE=%TEMP%\sandy_missing_stdin.txt
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Config Path Guard Test
echo =====================================================================

if not exist "!SANDY!" (
    echo   [SKIP] sandy.exe not found at !SANDY!
    exit /b 0
)

if exist "!TMP_DIR!" rmdir /s /q "!TMP_DIR!" 2>nul
mkdir "!TMP_DIR!" >nul 2>nul
> "!TMP_FILE!" echo probe
if exist "!MISSING_FILE!" del "!MISSING_FILE!" 2>nul

echo.
echo --- PG1: workdir relative path rejected ---

"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\nworkdir = 'relative_dir'" >nul 2>"%TEMP%\sandy_pg1.txt"
set PG1_EC=!ERRORLEVEL!

if !PG1_EC! EQU 128 (
    echo   [PASS] PG1a: relative workdir rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] PG1a: exit code !PG1_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'workdir' in [sandbox] is not an absolute path." "%TEMP%\sandy_pg1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] PG1b: relative workdir error shown
    set /a PASS+=1
) else (
    echo   [FAIL] PG1b: missing relative workdir error
    set /a FAIL+=1
)

del "%TEMP%\sandy_pg1.txt" 2>nul

echo.
echo --- PG2: workdir file path rejected ---

"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\nworkdir = '!TMP_FILE!'" >nul 2>"%TEMP%\sandy_pg2.txt"
set PG2_EC=!ERRORLEVEL!

if !PG2_EC! EQU 128 (
    echo   [PASS] PG2a: file-backed workdir rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] PG2a: exit code !PG2_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'workdir' in [sandbox] must reference a directory, got file:" "%TEMP%\sandy_pg2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] PG2b: workdir file/directory mismatch shown
    set /a PASS+=1
) else (
    echo   [FAIL] PG2b: missing workdir directory mismatch error
    set /a FAIL+=1
)

del "%TEMP%\sandy_pg2.txt" 2>nul

echo.
echo --- PG3: stdin relative path rejected ---

"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nstdin = 'relative_input.txt'" >nul 2>"%TEMP%\sandy_pg3.txt"
set PG3_EC=!ERRORLEVEL!

if !PG3_EC! EQU 128 (
    echo   [PASS] PG3a: relative stdin path rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] PG3a: exit code !PG3_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'stdin' in [privileges] is not an absolute path." "%TEMP%\sandy_pg3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] PG3b: relative stdin error shown
    set /a PASS+=1
) else (
    echo   [FAIL] PG3b: missing relative stdin error
    set /a FAIL+=1
)

del "%TEMP%\sandy_pg3.txt" 2>nul

echo.
echo --- PG4: stdin missing file rejected ---

"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nstdin = '!MISSING_FILE!'" >nul 2>"%TEMP%\sandy_pg4.txt"
set PG4_EC=!ERRORLEVEL!

if !PG4_EC! EQU 128 (
    echo   [PASS] PG4a: missing stdin file rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] PG4a: exit code !PG4_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"Path does not exist: !MISSING_FILE! (in [privileges] 'stdin')" "%TEMP%\sandy_pg4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] PG4b: missing stdin path error shown
    set /a PASS+=1
) else (
    echo   [FAIL] PG4b: missing missing-stdin error
    set /a FAIL+=1
)

del "%TEMP%\sandy_pg4.txt" 2>nul

echo.
echo --- PG5: stdin directory path rejected ---

"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nstdin = '!TMP_DIR!'" >nul 2>"%TEMP%\sandy_pg5.txt"
set PG5_EC=!ERRORLEVEL!

if !PG5_EC! EQU 128 (
    echo   [PASS] PG5a: directory stdin path rejected with config error
    set /a PASS+=1
) else (
    echo   [FAIL] PG5a: exit code !PG5_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"'stdin' in [privileges] must reference a file, got directory:" "%TEMP%\sandy_pg5.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] PG5b: stdin file/directory mismatch shown
    set /a PASS+=1
) else (
    echo   [FAIL] PG5b: missing stdin directory mismatch error
    set /a FAIL+=1
)

del "%TEMP%\sandy_pg5.txt" 2>nul

del "!TMP_FILE!" 2>nul
rmdir /s /q "!TMP_DIR!" 2>nul

echo.
echo =====================================================================
echo  PASS: !PASS!   FAIL: !FAIL!
echo =====================================================================

if !FAIL! NEQ 0 exit /b 1
exit /b 0
