@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /std:c++20 /EHsc /O2 /LD ^
   /I ..\src\sdk\include ^
   ..\tests\testapp\test_dll_basic.cpp ^
   /Fe:test_dll_basic.dll ^
   /link kernel32.lib
cl /nologo /std:c++20 /EHsc /O2 ^
   ..\tests\testapp\test_dll_loader.cpp ^
   /Fe:test_dll_loader.exe ^
   /link /SUBSYSTEM:CONSOLE kernel32.lib
