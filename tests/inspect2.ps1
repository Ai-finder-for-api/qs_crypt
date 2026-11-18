$d = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors'
$j = Get-Content (Join-Path $d 'mlkem_768_test.json') -Raw | ConvertFrom-Json
foreach ($g in $j.testGroups) {
    $keys = (($g | Get-Member -MemberType NoteProperty).Name -join ',')
    $tk = (($g.tests[0] | Get-Member -MemberType NoteProperty).Name -join ',')
    Write-Output ('group type=' + $g.type + ' parameterSet=' + $g.parameterSet + ' n=' + $g.tests.Count + ' groupKeys=' + $keys + ' testKeys=' + $tk)
}
$k = Get-Content (Join-Path $d 'rsa_pss_2048_sha256_mgf1_32_test.json') -Raw | ConvertFrom-Json
Write-Output ('pss publicKey keys: ' + (($k.testGroups[0].publicKey | Get-Member -MemberType NoteProperty).Name -join ','))
$o = Get-Content (Join-Path $d 'rsa_oaep_2048_sha256_mgf1sha256_test.json') -Raw | ConvertFrom-Json
Write-Output ('oaep privateKey keys: ' + (($o.testGroups[0].privateKey | Get-Member -MemberType NoteProperty).Name -join ','))
$e = Get-Content (Join-Path $d 'ecdsa_secp256r1_sha256_test.json') -Raw | ConvertFrom-Json
Write-Output ('ecdsa publicKey keys: ' + (($e.testGroups[0].publicKey | Get-Member -MemberType NoteProperty).Name -join ','))
$r = @{}
foreach ($t in $o.testGroups) { foreach ($x in $t.tests) { $r[$x.result] = 1 + [int]$r[$x.result] } }
Write-Output ('oaep results: ' + (($r.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ' '))
$lbl = 0; foreach ($t in $o.testGroups) { foreach ($x in $t.tests) { if ($x.label -ne '') { $lbl++ } } }
Write-Output ('oaep tests with non-empty label: ' + $lbl)
