@echo off
cd /d C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt
del /q run_both.bat final_build.bat run_cloud.bat 2>nul
del /q build_cloud.log build_default.log 2>nul
del /q tests\vault\e2e_cloud.log 2>nul
echo cleanup done
