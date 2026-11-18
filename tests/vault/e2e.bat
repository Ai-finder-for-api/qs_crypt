@echo off
rem End-to-end check of build\qsvault.exe on real files. Uses QSV_PASSWORD so it runs unattended.
setlocal
cd /d "%~dp0\..\.."
set Q=build\qsenc.exe
set QSV_PASSWORD=this is a long test password
set T=build\e2e
if not exist %T% mkdir %T%
echo hello from qsvault, end to end> %T%\plain.txt

%Q% keygen-ckey %T%\a.qs.ckey || goto :fail
%Q% keygen-ckey %T%\usb.qs.ckey || goto :fail
%Q% keygen-sign %T%\signer --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey || goto :fail
%Q% encrypt %T%\plain.txt %T%\out.qsv --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey --sign %T%\signer || goto :fail
%Q% info %T%\out.qsv || goto :fail
%Q% decrypt %T%\out.qsv %T%\back.txt --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey --trust %T%\signer || goto :fail
fc %T%\plain.txt %T%\back.txt >nul && echo ROUNDTRIP MATCH || goto :fail

echo --- negative checks (each must FAIL) ---
%Q% decrypt %T%\out.qsv %T%\x1.txt --ckey %T%\a.qs.ckey --trust %T%\signer 2>nul && goto :fail
echo ok: missing usb key refused
set QSV_PASSWORD=a wrong password value
%Q% decrypt %T%\out.qsv %T%\x2.txt --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey --trust %T%\signer 2>nul && goto :fail
echo ok: wrong password refused
set QSV_PASSWORD=this is a long test password
%Q% keygen-ckey %T%\other.qs.ckey
%Q% decrypt %T%\out.qsv %T%\x3.txt --ckey %T%\other.qs.ckey --usb %T%\usb.qs.ckey --trust %T%\signer 2>nul && goto :fail
echo ok: wrong .qs.ckey refused
%Q% keygen-sign %T%\impostor --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey
%Q% decrypt %T%\out.qsv %T%\x4.txt --ckey %T%\a.qs.ckey --usb %T%\usb.qs.ckey --trust %T%\impostor 2>nul && goto :fail
echo ok: wrong signer refused

echo ALL E2E CHECKS PASSED
exit /b 0
:fail
echo E2E FAILED
exit /b 1
