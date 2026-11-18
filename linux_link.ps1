wsl -e sh -c "cd /mnt/c/Users/Yash/Desktop/quantum-suite/core/qs_crypt && make test 2>&1 | grep -iE 'undefined|multiple|error|warning' | head -30"
