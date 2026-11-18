$j = Get-Content 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors\mldsa_65_verify_test.json' -Raw | ConvertFrom-Json
Write-Output ('algorithm=' + $j.algorithm + ' numberOfTests=' + $j.numberOfTests)
$g = $j.testGroups[0]
Write-Output ('group keys: ' + (($g | Get-Member -MemberType NoteProperty).Name -join ','))
$t = $g.tests[0]
Write-Output ('test keys: ' + (($t | Get-Member -MemberType NoteProperty).Name -join ','))
$res = @{}; $cnt = 0; $ctxs = @{}
foreach ($gg in $j.testGroups) { foreach ($x in $gg.tests) { $cnt++; $res[[string]$x.result] = 1 + [int]$res[[string]$x.result]; $ctxs[[string]$x.ctx] = 1 } }
Write-Output ('total=' + $cnt + ' results: ' + (($res.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ' '))
Write-Output ('distinct ctx values: ' + $ctxs.Count)
Write-Output ('group publicKey keys: ' + (($g.publicKey | Get-Member -MemberType NoteProperty).Name -join ','))
Write-Output ('pk len hex: ' + ([string]$g.publicKey.pk).Length + ' sig len hex(first test): ' + ([string]$t.sig).Length + ' msg len: ' + ([string]$t.msg).Length)
Write-Output ('tcId sample: ' + $t.tcId + ' flags: ' + (($t.flags) -join ','))
