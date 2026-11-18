$f = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\src\mldsa\qs_crypt_mldsa.c'
$lines = Get-Content $f
$changed = 0
$out = foreach ($l in $lines) {
    if ($l -match '^(\s+)static (poly|uint32_t|uint8_t)\b') {
        $changed++
        $l -replace '^(\s+)static ', '$1'
    } else { $l }
}
Set-Content -Path $f -Value $out -Encoding ASCII
Write-Output ('local static declarations removed: ' + $changed)
Write-Output ('remaining static lines:')
$out | Select-String -Pattern '^\s+static' | ForEach-Object { Write-Output $_.Line }
