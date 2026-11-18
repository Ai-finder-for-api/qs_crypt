$j = Get-Content 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors\mldsa_65_verify_test.json' -Raw | ConvertFrom-Json
foreach ($g in $j.testGroups) {
    foreach ($t in $g.tests) {
        if ($t.tcId -in 3,4,70) {
            Write-Output ('tc=' + $t.tcId + ' result=' + $t.result + ' flags=' + (($t.flags) -join ',') + ' comment=' + $t.comment + ' msgHexLen=' + ([string]$t.msg).Length + ' sigHexLen=' + ([string]$t.sig).Length)
        }
    }
}
