$d = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors'
foreach ($f in @('ecdsa_secp256r1_sha256_test.json','rsa_pss_2048_sha256_mgf1_32_test.json','rsa_oaep_2048_sha256_mgf1sha256_test.json','mlkem_768_test.json')) {
    $j = Get-Content (Join-Path $d $f) -Raw | ConvertFrom-Json
    Write-Output ('== ' + $f)
    Write-Output ('algorithm: ' + $j.algorithm + '  numberOfTests: ' + $j.numberOfTests)
    $g = $j.testGroups[0]
    Write-Output ('group keys: ' + (($g | Get-Member -MemberType NoteProperty).Name -join ','))
    $t = $g.tests[0]
    Write-Output ('test keys: ' + (($t | Get-Member -MemberType NoteProperty).Name -join ','))
    Write-Output ('first test: ' + ($t | ConvertTo-Json -Depth 4 -Compress).Substring(0, [Math]::Min(700, ($t | ConvertTo-Json -Depth 4 -Compress).Length)))
    $cnt = 0; foreach ($gg in $j.testGroups) { $cnt += $gg.tests.Count }
    Write-Output ('total tests: ' + $cnt)
}
