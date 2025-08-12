CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lwolfssl -ldl

TEST_PROGS = test_wolfssl_basic test_wolfssl_versions

all: $(TEST_PROGS)

test_wolfssl_basic: test_wolfssl_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_wolfssl_versions: test_wolfssl_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean