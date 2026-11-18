$inc = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\include\qs_crypt'
foreach ($f in @('qs_crypt_containers.h','qs_crypt_kdf.h','qs_crypt_mac.h','qs_crypt_keys.h')) {
    Write-Output ('==== ' + $f)
    Get-Content (Join-Path $inc $f) | Where-Object { $_ -notmatch '^\s*$' } | ForEach-Object { Write-Output $_ }
}
Write-Output '==== algorithm ids'
Get-Content (Join-Path $inc 'qs_crypt_types.h') | Where-Object { $_ -match 'QSC_ALG_|qsc_slice_t|qsc_buffer_t|QSC_OK|QSC_ERROR_' } | ForEach-Object { Write-Output $_ }
