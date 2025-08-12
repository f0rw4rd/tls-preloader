CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lgnutls -ldl

TEST_PROGS = test_gnutls_basic test_gnutls_versions

all: $(TEST_PROGS)

test_gnutls_basic: test_gnutls_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_gnutls_versions: test_gnutls_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean