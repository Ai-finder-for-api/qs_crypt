$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
$log = Join-Path $root 'build_log.txt'
cmd /c ('"' + (Join-Path $root 'build_windows.bat') + '"') > $log 2>&1
$tail = Get-Content $log | Select-Object -Last 4
foreach ($l in $tail) { Write-Output $l }
$t = Measure-Command { & (Join-Path $root 'build\qs_crypt_tests.exe') 2>&1 | Out-Null }
Write-Output ('test run wall time (MSVC, unoptimized): ' + [math]::Round($t.TotalSeconds, 1) + ' s')
