$log = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\build_log.txt'
$lines = Get-Content $log
$f = $lines | Where-Object { $_ -match 'FAIL|bad kat' }
Write-Output ('failure lines: ' + $f.Count)
foreach ($x in $f) { Write-Output $x }
