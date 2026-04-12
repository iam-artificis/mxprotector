@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /std:c++20 /EHsc /O2 /Fe:test_vm_showcase.exe ^
   /I ..\src\sdk\include ^
   ..\tests\testapp\test_vm_showcase.cpp ^
   /link /SUBSYSTEM:CONSOLE
