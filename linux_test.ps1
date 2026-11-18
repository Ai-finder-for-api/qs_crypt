$gen = 'C:\Users\Yash\Desktop\quantum-suite\core\qs_crypt\tests\gen_vectors.ps1'
powershell -NoProfile -ExecutionPolicy Bypass -File $gen
wsl -e sh -c "cd /mnt/c/Users/Yash/Desktop/quantum-suite/core/qs_crypt && (make test 2>&1 | grep -E 'error|warning|FAIL|checks|ERROR|Sanitizer|runtime' | head -60; echo EXIT=\$?)"
