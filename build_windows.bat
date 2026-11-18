@echo off
rem qs_crypt: build and run the test suite with MSVC (Visual Studio 2022 Build Tools).
rem Usage: build_windows.bat        (builds build\qs_crypt_tests.exe and runs it)
setlocal enabledelayedexpansion

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat not found. Adjust the path at the top of this file.
    exit /b 1
)

cd /d "%~dp0"
if not exist build mkdir build

set SRC=
for /r src %%f in (*.c) do set SRC=!SRC! "%%f"

set TESTS=tests\test_main.c tests\unit\test_api.c tests\negative\test_negative.c tests\serialization\test_container.c tests\property\test_property.c tests\known_answer\test_kat.c tests\known_answer\test_kat2.c tests\known_answer\test_ed25519.c tests\fhe\test_fhe.c tests\rsa\test_rsa.c tests\ecdsa\test_ecdsa.c tests\mlkem\test_mlkem.c tests\mldsa\test_mldsa.c

set FLAGS=/nologo /std:c11 /W3 /WX /D_CRT_SECURE_NO_WARNINGS /Iinclude /Itests

cl %FLAGS% %SRC% %TESTS% /Fobuild\ /Fe:build\qs_crypt_tests.exe /link bcrypt.lib
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

build\qs_crypt_tests.exe
exit /b %errorlevel%
