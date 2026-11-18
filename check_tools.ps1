$found = @()
foreach ($t in @('gcc', 'clang', 'wsl', 'make')) {
    if (Get-Command $t -ErrorAction SilentlyContinue) { $found += $t }
}
if ($found.Count -eq 0) { Write-Output 'none' } else { Write-Output ($found -join ',') }
