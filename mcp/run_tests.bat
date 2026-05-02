@echo off
REM Run the full mx-mcp test suite. Works from any cwd.
REM
REM Usage:
REM   mcp\run_tests.bat                # all 750+ tests
REM   mcp\run_tests.bat tests\test_x.py # one file
REM   mcp\run_tests.bat -k pattern     # subset by name

setlocal
set "_HERE=%~dp0"
pushd "%_HERE%" || (
    echo failed to enter %_HERE%
    exit /b 1
)
py -3 -m pytest %*
set "_RC=%ERRORLEVEL%"
popd
exit /b %_RC%
