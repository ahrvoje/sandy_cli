@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy config string vs file semantics regression test
REM Verifies literal \n expansion is accepted only for -s/--string and
REM not for file-backed TOML configs.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set TMP_FILE=%TEMP%\sandy_literal_newline.toml
set FILE_OUT=%TEMP%\sandy_string_mode_file_out.txt
set FILE_ERR=%TEMP%\sandy_string_mode_file_err.txt
set STR_OUT=%TEMP%\sandy_string_mode_str_out.txt
set STR_ERR=%TEMP%\sandy_string_mode_str_err.txt
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Config String Semantics Test
echo =====================================================================

if not exist "!SANDY!" (
    echo   [SKIP] sandy.exe not found at !SANDY!
    exit /b 0
)

echo [sandbox]\n token = 'appcontainer' > "!TMP_FILE!"

echo.
echo --- SS1: file-backed TOML treats \n literally ---

"!SANDY!" --print-config -c "!TMP_FILE!" >"!FILE_OUT!" 2>"!FILE_ERR!"
set FILE_EC=!ERRORLEVEL!

if !FILE_EC! NEQ 0 (
    echo   [PASS] SS1a: file-backed config rejected literal \n
    set /a PASS+=1
) else (
    echo   [FAIL] SS1a: file-backed config should reject literal \n
    set /a FAIL+=1
)

findstr /C:"Config contains unknown sections or keys. Aborting." "!FILE_ERR!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SS1b: rejection surfaced through config error path
    set /a PASS+=1
) else (
    echo   [FAIL] SS1b: expected config error message missing
    set /a FAIL+=1
)

echo.
echo --- SS2: -s expands literal \n into real newlines ---

"!SANDY!" --print-config -s "[sandbox]\n token = 'appcontainer'" >"!STR_OUT!" 2>"!STR_ERR!"
set STR_EC=!ERRORLEVEL!

if !STR_EC! EQU 0 (
    echo   [PASS] SS2a: -s accepted literal \n inline config
    set /a PASS+=1
) else (
    echo   [FAIL] SS2a: -s should accept literal \n inline config
    set /a FAIL+=1
)

findstr /C:"token = 'appcontainer'" "!STR_OUT!" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SS2b: printed config resolved correctly
    set /a PASS+=1
) else (
    echo   [FAIL] SS2b: expected resolved config output missing
    set /a FAIL+=1
)

del "!TMP_FILE!" 2>nul
del "!FILE_OUT!" 2>nul
del "!FILE_ERR!" 2>nul
del "!STR_OUT!" 2>nul
del "!STR_ERR!" 2>nul

echo.
echo =====================================================================
echo  PASS: !PASS!   FAIL: !FAIL!
echo =====================================================================

if !FAIL! NEQ 0 exit /b 1
exit /b 0
