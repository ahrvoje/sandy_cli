@echo off
REM ---------------------------------------------------------------
REM test_sandy.bat — Set up test folders and run sandbox tests
REM Run from the sandy build/exe directory (e.g. x64\Debug)
REM ---------------------------------------------------------------

set SANDY_EXE=%~dp0x64\Debug\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set SCRIPT=%~dp0test_sandy.py

echo === Sandy Test Runner ===
echo.

REM --- Create test folders if they don't exist ---
echo Creating test folders...
if not exist "%USERPROFILE%\test_R"  mkdir "%USERPROFILE%\test_R"
if not exist "%USERPROFILE%\test_W"  mkdir "%USERPROFILE%\test_W"
if not exist "%USERPROFILE%\test_RW" mkdir "%USERPROFILE%\test_RW"

REM --- Create seed file for read-only tests ---
if not exist "%USERPROFILE%\test_R\seed.txt" (
    echo This is a seed file for read-only testing> "%USERPROFILE%\test_R\seed.txt"
    echo Created seed.txt in test_R
)

echo.
echo --- Running sandbox tests ---
echo.

"%SANDY_EXE%" -c "%CONFIG%" -x "%PYTHON%" "%SCRIPT%"

echo.
echo --- Done (exit code: %ERRORLEVEL%) ---
pause
