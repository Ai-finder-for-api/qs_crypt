$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
$log = Join-Path $root 'build_log.txt'
cmd /c ('"' + (Join-Path $root 'build_windows.bat') + '"') > $log 2>&1
$lines = Get-Content $log
$hits = $lines | Select-String -Pattern 'error|warning|FAIL|checks|BUILD' | Select-Object -First 60
foreach ($h in $hits) { Write-Output $h.Line }
Write-Output ('total log lines: ' + $lines.Count)
