$d = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors'
$base = 'https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/'
$names = @('mldsa_65_verify_test.json', 'mldsa_65_sign_test.json', 'mldsa_65_keygen_test.json', 'mldsa_65_test.json', 'mldsa_65_verify_no_ctx_test.json')
foreach ($f in $names) {
    try {
        Invoke-WebRequest -Uri ($base + $f) -OutFile (Join-Path $d $f) -UseBasicParsing
        Write-Output ('OK ' + $f + ' ' + (Get-Item (Join-Path $d $f)).Length)
    } catch {
        Write-Output ('MISSING ' + $f)
    }
}
