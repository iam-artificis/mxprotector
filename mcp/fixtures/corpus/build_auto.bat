@echo off
REM ==========================================================================
REM  Convenience wrapper around build.bat — loads the MSVC x64 environment
REM  first so callers don't need to open a Developer Command Prompt.
REM
REM  Hard-codes the VS 2022 Community default path. For a different VS
REM  edition / install location, edit VCVARS below or run build.bat from
REM  a prepared Developer Command Prompt directly.
REM ==========================================================================

setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat

if not exist "%VCVARS%" (
    echo [!] vcvars64.bat not found at:
    echo       %VCVARS%
    echo     Edit VCVARS in this script or run build.bat from a Developer
    echo     Command Prompt instead.
    exit /b 2
)

call "%VCVARS%" >NUL 2>&1
if errorlevel 1 (
    echo [!] vcvars64 failed
    exit /b 1
)

call "%~dp0build.bat"
exit /b %errorlevel%
