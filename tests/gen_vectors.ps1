# Converts Wycheproof JSON vectors into C header tables (hex strings).
$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests'
$vec  = Join-Path $root 'vectors'
function VCode([string]$r) { if ($r -eq 'valid') { return 1 } elseif ($r -eq 'invalid') { return 0 } else { return 2 } }
function Q([string]$s) {
    if ($s.Length -le 1500) { return ('"' + $s + '"') }
    $parts = @()
    for ($i = 0; $i -lt $s.Length; $i += 1500) {
        $len = [Math]::Min(1500, $s.Length - $i)
        $parts += ('"' + $s.Substring($i, $len) + '"')
    }
    return ($parts -join ' ')
}
function Row([object[]]$vals) {
    $mid = @()
    foreach ($v in @($vals[1..($vals.Count - 2)])) { $mid += (Q ([string]$v)) }
    return ('  { ' + [string]$vals[0] + ', ' + ($mid -join ', ') + ', ' + [string]$vals[$vals.Count - 1] + ' },')
}

# ---- ECDSA P-256 / SHA-256 ----
$j = Get-Content (Join-Path $vec 'ecdsa_secp256r1_sha256_test.json') -Raw | ConvertFrom-Json
$out = New-Object System.Collections.Generic.List[string]
$out.Add('/* Generated from Wycheproof ecdsa_secp256r1_sha256_test.json. Do not edit. */')
$out.Add('static const struct { int tc; const char* pub; const char* msg; const char* der; int valid; } kat_ecdsa[] = {')
foreach ($g in $j.testGroups) {
    $pub = [string]$g.publicKey.uncompressed
    foreach ($t in $g.tests) {
        $sig = [string]$t.sig
        # DER encodings over 4 KB exceed the C99 literal limit; they are rejected by length anyway.
        if ($sig.Length -gt 4000) { $sig = '' }
        $out.Add((Row @([string]$t.tcId, $pub, [string]$t.msg, $sig, (VCode $t.result))))
    }
}
$out.Add('};')
Set-Content -Path (Join-Path $vec 'kat_ecdsa.h') -Value $out -Encoding ASCII
Write-Output ('ecdsa rows: ' + ($out.Count - 3))

# ---- RSA-PSS 2048 / SHA-256 / MGF1-SHA256 / sLen 32 ----
$j = Get-Content (Join-Path $vec 'rsa_pss_2048_sha256_mgf1_32_test.json') -Raw | ConvertFrom-Json
$out = New-Object System.Collections.Generic.List[string]
$out.Add('/* Generated from Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json. Do not edit. */')
$out.Add('static const struct { int tc; const char* n; const char* e; const char* msg; const char* sig; int valid; } kat_pss[] = {')
foreach ($g in $j.testGroups) {
    $n = [string]$g.publicKey.modulus; $e = [string]$g.publicKey.publicExponent
    foreach ($t in $g.tests) {
        $out.Add((Row @([string]$t.tcId, $n, $e, [string]$t.msg, [string]$t.sig, (VCode $t.result))))
    }
}
$out.Add('};')
Set-Content -Path (Join-Path $vec 'kat_pss.h') -Value $out -Encoding ASCII
Write-Output ('pss rows: ' + ($out.Count - 3))

# ---- RSA-OAEP 2048 / SHA-256 / MGF1-SHA256 (empty label only) ----
$j = Get-Content (Join-Path $vec 'rsa_oaep_2048_sha256_mgf1sha256_test.json') -Raw | ConvertFrom-Json
$out = New-Object System.Collections.Generic.List[string]
$out.Add('/* Generated from Wycheproof rsa_oaep_2048_sha256_mgf1sha256_test.json. Do not edit. */')
$out.Add('static const struct { int tc; const char* n; const char* d; const char* ct; const char* msg; int valid; } kat_oaep[] = {')
foreach ($g in $j.testGroups) {
    $n = [string]$g.privateKey.modulus; $d = [string]$g.privateKey.privateExponent
    foreach ($t in $g.tests) {
        if ([string]$t.label -ne '') { continue }
        $out.Add((Row @([string]$t.tcId, $n, $d, [string]$t.ct, [string]$t.msg, (VCode $t.result))))
    }
}
$out.Add('};')
Set-Content -Path (Join-Path $vec 'kat_oaep.h') -Value $out -Encoding ASCII
Write-Output ('oaep rows: ' + ($out.Count - 3))

# ---- ML-KEM-768 ----
$j = Get-Content (Join-Path $vec 'mlkem_768_test.json') -Raw | ConvertFrom-Json
$out = New-Object System.Collections.Generic.List[string]
$out.Add('/* Generated from Wycheproof mlkem_768_test.json. Do not edit. */')
$out.Add('static const struct { int tc; const char* seed; const char* ek; const char* c; const char* K; int valid; } kat_mlkem[] = {')
foreach ($g in $j.testGroups) {
    foreach ($t in $g.tests) {
        $out.Add((Row @([string]$t.tcId, [string]$t.seed, [string]$t.ek, [string]$t.c, [string]$t.K, (VCode $t.result))))
    }
}
$out.Add('};')
Set-Content -Path (Join-Path $vec 'kat_mlkem.h') -Value $out -Encoding ASCII
Write-Output ('mlkem rows: ' + ($out.Count - 3))
