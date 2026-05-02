# Run the full mx-mcp test suite. Works from any cwd.
#
# Usage:
#   .\mcp\run_tests.ps1                # all tests
#   .\mcp\run_tests.ps1 tests\test_x.py # one file
#   .\mcp\run_tests.ps1 -k pattern      # subset by name

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    & py -3 -m pytest @args
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
