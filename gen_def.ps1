# Builds qs_crypt.def from the public prototypes (qsc_* functions) in include\qs_crypt.
# Parses whole declarations, so prototypes that span several lines are exported too.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$inc  = Join-Path $root 'include\qs_crypt'
$names = New-Object System.Collections.Generic.SortedSet[string]
foreach ($f in Get-ChildItem -Path $inc -Filter '*.h') {
    if ($f.Name -like '*experimental*') { continue }
    $text = [System.IO.File]::ReadAllText($f.FullName)
    $text = [regex]::Replace($text, '(?s)/\*.*?\*/', ' ')       # block comments
    $text = [regex]::Replace($text, '//[^\r\n]*', ' ')          # line comments
    $text = [regex]::Replace($text, '(?m)^\s*#[^\r\n]*', ' ')   # preprocessor lines
    $text = [regex]::Replace($text, '(?s)typedef[^;{]*(\{[^}]*\})?[^;]*;', ' ')  # typedefs
    foreach ($m in [regex]::Matches($text, '\b(qsc_[A-Za-z0-9_]+)\s*\([^;{}]*\)\s*;')) {
        [void]$names.Add($m.Groups[1].Value)
    }
}
$out = New-Object System.Collections.Generic.List[string]
$out.Add('LIBRARY qs_crypt')
$out.Add('EXPORTS')
foreach ($n in $names) { $out.Add('    ' + $n) }
Set-Content -Path (Join-Path $root 'qs_crypt.def') -Value $out -Encoding ASCII
Write-Output ('exported symbols: ' + $names.Count)
