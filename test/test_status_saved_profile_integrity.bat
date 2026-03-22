@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_profile_ac.toml
set ROOT=%USERPROFILE%\test_sandy_profile
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Status Saved Profile Integrity Test
echo =====================================================================

"!SANDY!" --delete-profile status_bad >nul 2>nul
"!SANDY!" --delete-profile status_ghost >nul 2>nul
reg delete "HKCU\Software\Sandy\Profiles\status_ghost" /f >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul
if exist "!ROOT!" rmdir /s /q "!ROOT!"
mkdir "!ROOT!\data"
echo test data > "!ROOT!\data\hello.txt"

echo.
echo --- SPI1: create valid profile ---
"!SANDY!" --create-profile status_bad -c "!AC_CONFIG!" >"%TEMP%\sandy_spi1.txt" 2>&1
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI1a: profile created
    set /a PASS+=1
) else (
    echo   [FAIL] SPI1a: profile creation failed
    set /a FAIL+=1
)
"!SANDY!" --status >"%TEMP%\sandy_spi1s.txt" 2>&1
findstr /C:"Sandy_status_bad" "%TEMP%\sandy_spi1s.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI1b: status does not duplicate saved container mapping
    set /a PASS+=1
) else (
    echo   [FAIL] SPI1b: status duplicated saved container mapping
    set /a FAIL+=1
)

echo.
echo --- SPI2: corrupt _token_mode and verify load rejects ---
reg add "HKCU\Software\Sandy\Profiles\status_bad" /v _token_mode /t REG_SZ /d restricted /f >nul 2>nul
"!SANDY!" --profile-info status_bad >nul 2>"%TEMP%\sandy_spi2.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI2a: corrupted profile rejected by --profile-info
    set /a PASS+=1
) else (
    echo   [FAIL] SPI2a: corrupted profile unexpectedly accepted
    set /a FAIL+=1
)
findstr /C:"corrupted or incomplete" "%TEMP%\sandy_spi2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI2b: rejection explains corruption
    set /a PASS+=1
) else (
    echo   [FAIL] SPI2b: corruption message missing
    set /a FAIL+=1
)

echo.
echo --- SPI3: --status surfaces corrupted saved profile ---
"!SANDY!" --status >"%TEMP%\sandy_spi3.txt" 2>&1
findstr /C:"[SAVED_PROFILE] status_bad  (corrupted" "%TEMP%\sandy_spi3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI3a: text status marks corrupted profile
    set /a PASS+=1
) else (
    echo   [FAIL] SPI3a: text status missed corrupted profile
    set /a FAIL+=1
)

"!SANDY!" --status --json >"%TEMP%\sandy_spi3j.txt" 2>&1
findstr /C:"\"name\":\"status_bad\"" "%TEMP%\sandy_spi3j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI3b: JSON status includes corrupted profile entry
    set /a PASS+=1
) else (
    echo   [FAIL] SPI3b: JSON status missing corrupted profile entry
    set /a FAIL+=1
)
findstr /C:"\"status\":\"invalid\"" "%TEMP%\sandy_spi3j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI3c: JSON status marks corrupted profile invalid
    set /a PASS+=1
) else (
    echo   [FAIL] SPI3c: JSON status missing invalid marker
    set /a FAIL+=1
)
findstr /C:"Sandy_status_bad" "%TEMP%\sandy_spi3j.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI3d: JSON status does not duplicate saved container mapping
    set /a PASS+=1
) else (
    echo   [FAIL] SPI3d: JSON status duplicated saved container mapping
    set /a FAIL+=1
)

echo.
echo --- SPI4: hidden ghost profile becomes visible in status ---
reg add "HKCU\Software\Sandy\Profiles\status_ghost" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Profiles\status_ghost" /v _created /t REG_SZ /d 2026-03-22T00:00:00Z /f >nul 2>nul
reg add "HKCU\Software\Sandy\Profiles\status_ghost" /v _container /t REG_SZ /d Sandy_status_ghost /f >nul 2>nul
"!SANDY!" --status >"%TEMP%\sandy_spi4.txt" 2>&1
findstr /C:"[SAVED_PROFILE] status_ghost  (corrupted" "%TEMP%\sandy_spi4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI4a: text status surfaces ghost profile as invalid
    set /a PASS+=1
) else (
    echo   [FAIL] SPI4a: text status hid ghost profile
    set /a FAIL+=1
)
findstr /C:"[PROFILE] Sandy_status_ghost" "%TEMP%\sandy_spi4.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI4b: text status does not duplicate ghost container mapping
    set /a PASS+=1
) else (
    echo   [FAIL] SPI4b: text status duplicated ghost container mapping
    set /a FAIL+=1
)

"!SANDY!" --status --json >"%TEMP%\sandy_spi4j.txt" 2>&1
findstr /C:"\"name\":\"status_ghost\"" "%TEMP%\sandy_spi4j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI4c: JSON status includes ghost profile entry
    set /a PASS+=1
) else (
    echo   [FAIL] SPI4c: JSON status missing ghost profile entry
    set /a FAIL+=1
)
findstr /C:"\"status\":\"invalid\"" "%TEMP%\sandy_spi4j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI4d: JSON status marks ghost profile invalid
    set /a PASS+=1
) else (
    echo   [FAIL] SPI4d: JSON status missing ghost invalid marker
    set /a FAIL+=1
)
findstr /C:"Sandy_status_ghost" "%TEMP%\sandy_spi4j.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI4e: JSON status does not duplicate ghost container mapping
    set /a PASS+=1
) else (
    echo   [FAIL] SPI4e: JSON status duplicated ghost container mapping
    set /a FAIL+=1
)

echo.
echo --- SPI5: cleanup ---
"!SANDY!" --delete-profile status_bad >"%TEMP%\sandy_spi5.txt" 2>&1
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI5a: corrupted profile deleted successfully
    set /a PASS+=1
) else (
    echo   [FAIL] SPI5a: corrupted profile delete failed
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Profiles\status_bad" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI5b: corrupted profile registry key removed
    set /a PASS+=1
) else (
    echo   [FAIL] SPI5b: corrupted profile registry key still exists
    set /a FAIL+=1
)

"!SANDY!" --delete-profile status_ghost >"%TEMP%\sandy_spi5g.txt" 2>&1
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] SPI5c: ghost profile deleted successfully
    set /a PASS+=1
) else (
    echo   [FAIL] SPI5c: ghost profile delete failed
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Profiles\status_ghost" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] SPI5d: ghost profile registry key removed
    set /a PASS+=1
) else (
    echo   [FAIL] SPI5d: ghost profile registry key still exists
    set /a FAIL+=1
)

del "%TEMP%\sandy_spi1.txt" 2>nul
del "%TEMP%\sandy_spi1s.txt" 2>nul
del "%TEMP%\sandy_spi2.txt" 2>nul
del "%TEMP%\sandy_spi3.txt" 2>nul
del "%TEMP%\sandy_spi3j.txt" 2>nul
del "%TEMP%\sandy_spi4.txt" 2>nul
del "%TEMP%\sandy_spi4j.txt" 2>nul
del "%TEMP%\sandy_spi5.txt" 2>nul
del "%TEMP%\sandy_spi5g.txt" 2>nul
"!SANDY!" --cleanup >nul 2>nul
if exist "!ROOT!" rmdir /s /q "!ROOT!"

echo.
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed
echo =====================================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0
