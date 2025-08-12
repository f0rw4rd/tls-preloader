CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lcurl -lpthread

TEST_PROGS = test_curl_basic test_curl_getinfo test_curl_doh test_curl_ocsp \
             test_proxy_ssl test_cert_pinning test_curl_versions

all: $(TEST_PROGS)

test_curl_basic: test_curl_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_curl_getinfo: test_curl_getinfo.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_curl_doh: test_curl_doh.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_curl_ocsp: test_curl_ocsp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_proxy_ssl: test_proxy_ssl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_cert_pinning: test_cert_pinning.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_curl_versions: test_curl_versions.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean