$d = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors'
New-Item -ItemType Directory -Force -Path $d | Out-Null
$base = 'https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/'
$files = @('ecdsa_secp256r1_sha256_test.json', 'rsa_pss_2048_sha256_mgf1_32_test.json', 'rsa_oaep_2048_sha256_mgf1sha256_test.json', 'mlkem_768_test.json')
foreach ($f in $files) {
    try {
        Invoke-WebRequest -Uri ($base + $f) -OutFile (Join-Path $d $f) -UseBasicParsing
        Write-Output ('OK ' + $f + ' ' + (Get-Item (Join-Path $d $f)).Length)
    } catch {
        Write-Output ('FAIL ' + $f + ' ' + $_.Exception.Message)
    }
}
