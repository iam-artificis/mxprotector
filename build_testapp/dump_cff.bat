@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >/dev/null
dumpbin /disasm test_exception.exe > disasm_full.txt 2>&1
