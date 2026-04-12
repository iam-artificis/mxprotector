@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERR] vcvars64 failed
    exit /b 1
)
cd /d "%~dp0"
cl /nologo /std:c++20 /EHsc /O1 /Fe:test_vm_branch.exe ^
   /I ..\src\sdk\include ^
   ..\tests\testapp\test_vm_branch.cpp ^
   /link /SUBSYSTEM:CONSOLE
