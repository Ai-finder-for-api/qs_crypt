$root = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt'
$files = @('tests\test_main.c', 'build.qs', 'build_windows.bat', 'Makefile')
foreach ($f in $files) {
    $p = Join-Path $root $f
    $n = 0
    foreach ($line in (Get-Content $p)) {
        $n++
        if ($line -match 'mlkem') { Write-Output ($f + ':' + $n + ': ' + $line) }
    }
}
