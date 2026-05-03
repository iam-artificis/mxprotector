@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /std:c++20 /EHsc /O2 /Fe:test_tls.exe test_tls.cpp /link /SUBSYSTEM:CONSOLE
