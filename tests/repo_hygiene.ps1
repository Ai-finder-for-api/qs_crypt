$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
$gi = Join-Path $root '.gitignore'
$want = @('build/', '*.ckey', '*.qsv', '*.sk.qsv', '*.tmp', '*.log', 'qsv_cloud_body.tmp')
$have = if (Test-Path $gi) { Get-Content $gi } else { @() }
$add = @($want | Where-Object { $have -notcontains $_ })
if ($add.Count -gt 0) { Add-Content -Path $gi -Value $add }
Write-Output ('gitignore entries added: ' + ($add -join ' '))

Remove-Item -Recurse -Force (Join-Path $root 'build\e2e') -ErrorAction SilentlyContinue
$stray = Get-ChildItem $root -Recurse -File -Include *.ckey, *.qsv, *.sk.qsv -ErrorAction SilentlyContinue
$stray | Remove-Item -Force
Write-Output ('key files removed from the tree: ' + $stray.Count)

$doc = Join-Path $root 'tools\vault\CLOUD_SETUP.md'
$hits = Select-String -Path $doc -Pattern 'fqcv|supabase\.co/functions/v1/qsv/' -SimpleMatch:$false
Write-Output ('project-specific URLs left in CLOUD_SETUP.md: ' + @($hits).Count)
