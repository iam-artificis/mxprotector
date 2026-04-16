@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /std:c++20 /EHsc /O2 /LD ^
   /I ..\src\sdk\include ^
   ..\tests\testapp\hello_guard_dll.cpp ^
   /Fe:hello_guard_dll.dll ^
   /link kernel32.lib user32.lib
cl /nologo /std:c++20 /EHsc /O2 ^
   ..\tests\testapp\hello_inject_loader.cpp ^
   /Fe:hello_inject_loader.exe ^
   /link /SUBSYSTEM:CONSOLE kernel32.lib
