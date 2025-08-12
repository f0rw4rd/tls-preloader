CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -ldl

TEST_PROGS = test_mbedtls_basic test_mbedtls_versions

all: $(TEST_PROGS)

test_mbedtls_basic: test_mbedtls_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_mbedtls_versions: test_mbedtls_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean