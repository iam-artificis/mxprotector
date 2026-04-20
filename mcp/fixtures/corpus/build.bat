@echo off
REM ==========================================================================
REM  Corpus build script — produces the unprotected .exe inputs declared in
REM  corpus.json. Run from a Visual Studio Developer Command Prompt (x64)
REM  so cl.exe is on PATH. Output lands in bin\unprotected\.
REM
REM  These binaries are the BENCHMARK INPUTS. They are compiled with the
REM  SDK headers but NOT yet through mxprotector_builder — that step
REM  happens inside each benchmark run (so metrics reflect the current
REM  builder state, not a stale protected copy).
REM ==========================================================================

setlocal
set D=%~dp0
set SDK=%D%..\..\..\src\sdk\include
set SRC=%D%src
set OUT=%D%bin\unprotected

if not exist "%OUT%" mkdir "%OUT%"

REM Shared flags: release optimisation, static CRT, UTF-8 source encoding,
REM C++23 to match the SDK's own standard.
set CLFLAGS=/nologo /EHsc /O2 /MT /std:c++latest /utf-8 /I"%SDK%"

echo [*] building pure_vm.exe
cl %CLFLAGS% "%SRC%\pure_vm.cpp" /Fe:"%OUT%\pure_vm.exe" /Fo"%OUT%\pure_vm.obj"
if errorlevel 1 goto :fail

echo [*] building pure_cff.exe
cl %CLFLAGS% "%SRC%\pure_cff.cpp" /Fe:"%OUT%\pure_cff.exe" /Fo"%OUT%\pure_cff.obj"
if errorlevel 1 goto :fail

echo [*] building mixed.exe
cl %CLFLAGS% "%SRC%\mixed.cpp" /Fe:"%OUT%\mixed.exe" /Fo"%OUT%\mixed.obj"
if errorlevel 1 goto :fail

echo [+] corpus built to %OUT%
exit /b 0

:fail
echo [!] corpus build failed
exit /b 1
