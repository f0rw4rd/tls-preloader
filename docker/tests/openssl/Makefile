CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lssl -lcrypto -ldl

TEST_PROGS = test_openssl_basic test_openssl_versions

all: $(TEST_PROGS)

test_openssl_basic: test_openssl_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_openssl_versions: test_openssl_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean