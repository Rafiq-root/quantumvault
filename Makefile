# QuantumVault crypto engine build
# usage: make / make test / make clean
#
# .RECIPEPREFIX = > : recipe lines start with '>' instead of tab, so this
# file survives copy-paste and tab-to-space converting editors.

.RECIPEPREFIX = >

CC        := gcc
CFLAGS    := -O2 -Wall -Wextra
OQS_DIR   := $(HOME)/deps/liboqs
OQS_INC   := -I$(OQS_DIR)/build/include
OQS_LIB   := $(OQS_DIR)/build/lib/liboqs.a
LIBS      := -lcrypto -lm -lpthread

ENGINE_LIB := crypto/libqv_crypto.a

all: $(ENGINE_LIB) crypto/qv_contract_test crypto/qv_engine_test

crypto/qv_crypto.o: crypto/qv_crypto.c crypto/qv_crypto.h
> $(CC) $(CFLAGS) $(OQS_INC) -c $< -o $@

 $(ENGINE_LIB): crypto/qv_crypto.o
> ar rcs $@ $^

crypto/qv_contract_test: crypto/qv_contract_test.c crypto/qv_crypto.h $(ENGINE_LIB) $(OQS_LIB)
> $(CC) $(CFLAGS) $(OQS_INC) $< $(ENGINE_LIB) $(OQS_LIB) -o $@ $(LIBS)

crypto/qv_engine_test: crypto/qv_engine_test.c crypto/qv_crypto.h $(ENGINE_LIB) $(OQS_LIB)
> $(CC) $(CFLAGS) $(OQS_INC) $< $(ENGINE_LIB) $(OQS_LIB) -o $@ $(LIBS)

test: all
> ./crypto/qv_contract_test
> ./crypto/qv_engine_test

clean:
> rm -f crypto/*.o crypto/*.a crypto/qv_contract_test crypto/qv_engine_test

.PHONY: all test clean
