@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >/dev/null
cl /nologo /std:c++20 /EHsc /O2 /Fe:test_simple_cpp.exe test_simple_cpp.cpp /link /SUBSYSTEM:CONSOLE
