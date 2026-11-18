@echo off
rem qsvault: build the CLI and its tests with MSVC (same toolchain as build_windows.bat).
rem Usage:
rem   build_vault.bat           build build\qsvault.exe and build\qsv_tests.exe, run the tests
rem   build_vault.bat cloud     same, with the cloud layer ENABLED (see tools\vault\CLOUD_SETUP.md)
setlocal enabledelayedexpansion

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo ERROR: vcvars64.bat not found. Adjust the path at the top of this file.
    exit /b 1
)

cd /d "%~dp0"
if not exist build mkdir build

set CLOUDDEF=
if /i "%~1"=="cloud" (
    set CLOUDDEF=/DQSV_CLOUD_ENABLED=1
    echo NOTE: building with the cloud layer ENABLED
)

set SRC=
for /r src %%f in (*.c) do set SRC=!SRC! "%%f"

set VSRC=tools\vault\qsv_core.c tools\vault\qsv_cloud.c tools\vault\qsv_cloudstore.c
set FLAGS=/nologo /std:c11 /W3 /WX /D_CRT_SECURE_NO_WARNINGS /Iinclude /Itools\vault !CLOUDDEF!

echo === qsenc CLI
cl %FLAGS% %SRC% %VSRC% tools\vault\qsvault.c /Fobuild\ /Fe:build\qsenc.exe /link bcrypt.lib
if errorlevel 1 (
    echo BUILD FAILED: qsenc.exe
    exit /b 1
)

echo === qsvault tests
cl %FLAGS% %SRC% %VSRC% tests\vault\test_vault.c /Fobuild\ /Fe:build\qsv_tests.exe /link bcrypt.lib
if errorlevel 1 (
    echo BUILD FAILED: qsv_tests.exe
    exit /b 1
)

if defined CLOUDDEF (
    echo NOTE: cloud build. Offline unit tests skipped. Run tests\vault\e2e.bat with QSV_CLOUD_URL set.
) else (
    build\qsv_tests.exe
    if errorlevel 1 (
        echo TESTS FAILED
        exit /b 1
    )
)

echo === cloud store tests (both builds)
cl %FLAGS% %SRC% %VSRC% tests\vault\test_cloudstore.c /Fobuild\ /Fe:build\qsv_cloudstore_tests.exe /link bcrypt.lib
if errorlevel 1 (
    echo BUILD FAILED: qsv_cloudstore_tests.exe
    exit /b 1
)
build\qsv_cloudstore_tests.exe
if errorlevel 1 (
    echo CLOUDSTORE TESTS FAILED
    exit /b 1
)
echo qsenc build OK
