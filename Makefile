# qs_crypt — standalone build (zero external dependencies).
# In the monorepo, use the Quantum Suite build system (qs_build) instead.
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -D_GNU_SOURCE
CPPFLAGS += -Iinclude
AR      ?= ar

SRC := $(shell find src -name '*.c')
OBJ := $(SRC:.c=.o)
LIB := build/libqs_crypt.a

all: $(LIB)

$(LIB): $(OBJ)
	@mkdir -p build
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

TEST_SRC := $(filter-out tests/fuzz/% tests/dll/% tests/vault/%,$(shell find tests -name '*.c'))
TEST_BIN := build/qs_crypt_tests

# Test binary is built with AddressSanitizer + UBSan, and aborts on first UB.
$(TEST_BIN): $(SRC) $(TEST_SRC)
	@mkdir -p build
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
	    -Wall -Wextra -Wpedantic -Werror -D_GNU_SOURCE -Iinclude -Itests \
	    $(SRC) $(TEST_SRC) -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

FUZZ_BIN := build/qs_crypt_fuzz_smoke
fuzz-smoke: $(FUZZ_BIN)
	./$(FUZZ_BIN) 200000

$(FUZZ_BIN): $(SRC) tests/fuzz/fuzz_container.c
	@mkdir -p build
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
	    -Wall -Wextra -Wpedantic -Werror -D_GNU_SOURCE -Iinclude \
	    $(SRC) tests/fuzz/fuzz_container.c -o $@

BENCH_BIN := build/qs_crypt_bench
bench: $(LIB)
	@mkdir -p build
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
	    benchmarks/bench.c $(LIB) -o $(BENCH_BIN) && ./$(BENCH_BIN)

example: $(LIB)
	@mkdir -p build
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -Iinclude examples/seal_example.c $(LIB) -o build/seal_example && ./build/seal_example

clean:
	rm -rf build $(OBJ)

.PHONY: all clean test fuzz-smoke bench example
