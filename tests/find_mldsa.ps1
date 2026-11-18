$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
Get-ChildItem -Path (Join-Path $root 'src'), (Join-Path $root 'include') -Recurse -Include *.c,*.h | ForEach-Object {
    $n = 0
    foreach ($line in (Get-Content $_.FullName)) {
        $n++
        if ($line -match 'ML_DSA|ml_dsa|mldsa_65|MLDSA') { Write-Output ($_.FullName.Substring($root.Length) + ':' + $n + ': ' + $line) }
    }
}
