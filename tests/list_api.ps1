$inc = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\include\qs_crypt'
Get-ChildItem $inc -Filter *.h | ForEach-Object {
    Write-Output ('== ' + $_.Name)
    Get-Content $_.FullName | Where-Object { $_ -match '^\s*(qsc_error_t|void|size_t|int|qs_\w+|bool)\s+qsc_\w+\s*\(' } | ForEach-Object { Write-Output ('   ' + $_.Trim()) }
}
