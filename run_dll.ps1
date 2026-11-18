$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
$log = Join-Path $root 'dll_log.txt'
cmd /c ('"' + (Join-Path $root 'build_dll.bat') + '"') > $log 2>&1
$code = $LASTEXITCODE
Get-Content $log | Select-Object -Last 40 | ForEach-Object { Write-Output $_ }
Write-Output ('EXIT CODE: ' + $code)
