@echo off
setlocal EnableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat not found. Adjust the path at the top of this file.
    exit /b 1
)
cd /d "%~dp0"
if not exist build mkdir build
if not exist build\dll mkdir build\dll

powershell -NoProfile -ExecutionPolicy Bypass -File gen_def.ps1
if errorlevel 1 ( echo DEF GENERATION FAILED & exit /b 1 )

set SRC=
for /r src %%f in (*.c) do set SRC=!SRC! "%%f"

cl /nologo /std:c11 /W3 /WX /D_CRT_SECURE_NO_WARNINGS /Iinclude /LD %SRC% /Fo:build\dll\ /Fe:build\qs_crypt.dll /link /DEF:qs_crypt.def bcrypt.lib
if errorlevel 1 (
    echo DLL BUILD FAILED
    exit /b 1
)

cl /nologo /std:c11 /W3 /WX /D_CRT_SECURE_NO_WARNINGS /Iinclude tests\dll\test_dll.c /Fo:build\dll\ /Fe:build\dll\test_dll.exe /link build\qs_crypt.lib
if errorlevel 1 (
    echo DLL TEST BUILD FAILED
    exit /b 1
)

copy /y build\qs_crypt.dll build\dll\ >nul
build\dll\test_dll.exe
exit /b %errorlevel%
