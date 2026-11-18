#!/bin/bash
# GCC strict + AddressSanitizer + UndefinedBehaviorSanitizer: library tests, then the vault.
cd /mnt/c/Users/Yash/Desktop/quantum-suite/core/qs_crypt || exit 1
SRC=$(find src -name '*.c' | sort)
FL="-std=c11 -Wall -Wextra -pedantic -Iinclude -Itools/vault -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -D_GNU_SOURCE"

echo "=== library + vault: compile warnings"
gcc $FL $SRC tools/vault/qsv_core.c tools/vault/qsv_cloud.c tools/vault/qsvault.c -o /tmp/qsenc -lm 2>&1 | grep -E "warning|error" | head -n 40
echo "qsenc compile exit: ${PIPESTATUS[0]}"

echo "=== vault unit tests under ASan/UBSan"
gcc $FL $SRC tools/vault/qsv_core.c tools/vault/qsv_cloud.c tests/vault/test_vault.c -o /tmp/qsv_tests -lm 2>&1 | grep -E "warning|error" | head -n 40
/tmp/qsv_tests
echo "vault tests exit: $?"

echo "=== library test suite (make test)"
make clean >/dev/null 2>&1
make test 2>&1 | tail -n 15
echo "make test exit: ${PIPESTATUS[0]}"
