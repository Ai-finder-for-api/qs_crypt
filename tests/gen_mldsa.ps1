$vec = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\vectors'
$j = Get-Content (Join-Path $vec 'mldsa_65_verify_test.json') -Raw | ConvertFrom-Json
function VCode([string]$r) { if ($r -eq 'valid') { return 1 } else { return 0 } }
$out = New-Object System.Collections.Generic.List[string]
$out.Add('/* Generated from Wycheproof mldsa_65_verify_test.json. Do not edit. */')
$out.Add('static const struct { int tc; const char* pk; const char* msg; const char* ctx; const char* s0; const char* s1; const char* s2; int valid; } kat_mldsa[] = {')
$maxMsg = 0; $maxSig = 0; $skipped = 0
foreach ($g in $j.testGroups) {
    $pk = [string]$g.publicKey
    foreach ($t in $g.tests) {
        $msg = [string]$t.msg
        $sig = [string]$t.sig
        if ($msg.Length -gt $maxMsg) { $maxMsg = $msg.Length }
        if ($sig.Length -gt $maxSig) { $maxSig = $sig.Length }
        if ($msg.Length -gt 3900 -or $sig.Length -gt 7800) { $skipped++; continue }
        $p = @('', '', '')
        for ($i = 0; $i -lt 3; $i++) {
            $start = $i * 2600
            if ($start -lt $sig.Length) {
                $len = [Math]::Min(2600, $sig.Length - $start)
                $p[$i] = $sig.Substring($start, $len)
            }
        }
        $ctxHex = ''
        if ($t.PSObject.Properties.Name -contains 'ctx') { $ctxHex = [string]$t.ctx }
        $fields = @([string]$t.tcId, ('"' + $pk + '"'), ('"' + $msg + '"'), ('"' + $ctxHex + '"'), ('"' + $p[0] + '"'), ('"' + $p[1] + '"'), ('"' + $p[2] + '"'), [string](VCode ([string]$t.result)))
        $out.Add('  { ' + ($fields -join ', ') + ' },')
    }
}
$out.Add('};')
Set-Content -Path (Join-Path $vec 'kat_mldsa.h') -Value $out -Encoding ASCII
Write-Output ('rows=' + ($out.Count - 3) + ' skipped=' + $skipped + ' maxMsgHex=' + $maxMsg + ' maxSigHex=' + $maxSig)
