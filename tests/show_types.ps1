$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
Write-Output '==== types'
Get-Content (Join-Path $root 'include\qs_crypt\qs_crypt_types.h') | Where-Object { $_ -match 'qsc_tag_t|qsc_digest_t|qsc_key_t|qsc_rng_t|qs_u8|qs_u64|typedef' } | ForEach-Object { Write-Output $_ }
Write-Output '==== seal source (buffer convention)'
$seal = Join-Path $root 'src\containers\qs_crypt_seal.c'
$n = 0
foreach ($line in (Get-Content $seal)) {
    $n++
    if ($line -match 'qsc_alloc|out->data|container_out|plaintext_out|->length|NULL|qsc_free' -and $n -lt 400) { Write-Output ($n.ToString() + ': ' + $line) }
}
