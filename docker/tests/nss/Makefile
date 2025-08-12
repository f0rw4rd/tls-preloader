CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lnss3 -lnspr4 -ldl

TEST_PROGS = test_nss_basic test_nss_versions

all: $(TEST_PROGS)

test_nss_basic: test_nss_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_nss_versions: test_nss_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean