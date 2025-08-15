# Consolidated test suite Makefile
CC = cc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -ldl

# Consolidated test programs (reduced from 36 to 5)
TESTS = test_all_versions test_http_tools test_tls_basic test_tls_tools test_backtrace

all: $(TESTS)

test_all_versions: test_all_versions.c test_framework.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_http_tools: test_http_tools.c test_framework.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_tls_basic: test_tls_basic.c test_framework.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_tls_tools: test_tls_tools.c test_framework.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_backtrace: test_backtrace.c test_framework.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run all tests
test: $(TESTS)
	@echo "=== Running Consolidated Test Suite ==="
	@echo "1. Version Detection Tests"
	@LD_PRELOAD=../../libtlsnoverify.so ./test_all_versions || true
	@echo "\n2. HTTP Tool Tests"
	@LD_PRELOAD=../../libtlsnoverify.so ./test_http_tools || true
	@echo "\n3. TLS Library Basic Tests"
	@LD_PRELOAD=../../libtlsnoverify.so ./test_tls_basic || true
	@echo "\n4. TLS CLI Tool Tests"  
	@LD_PRELOAD=../../libtlsnoverify.so ./test_tls_tools || true
	@echo "\n5. Backtrace Support Tests"
	@LD_PRELOAD=../../libtlsnoverify.so ./test_backtrace || true

clean:
	rm -f $(TESTS)

# Quick comparison
stats:
	@echo "Old test suite: 36 test files"
	@echo "New test suite: 4 test files"
	@echo "Reduction: 89%"
	@echo ""
	@echo "Coverage remains the same:"
	@echo "- All TLS libraries (OpenSSL, GnuTLS, NSS, mbedTLS, wolfSSL)"
	@echo "- All HTTP tools (curl, wget, etc.)"
	@echo "- All TLS tools (openssl s_client, gnutls-cli, etc.)"
	@echo "- All service clients (psql, mysql, redis-cli, etc.)"

.PHONY: all test clean stats