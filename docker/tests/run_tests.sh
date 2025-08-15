#!/bin/bash
# Simple test runner for TLS preloader tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name=$1
    local test_cmd=$2
    
    echo -e "${YELLOW}Running: $test_name${NC}"
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if eval "$test_cmd"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo
}

# Check if library is preloaded
if [[ -z "$LD_PRELOAD" ]] || [[ ! "$LD_PRELOAD" =~ "libtlsnoverify.so" ]]; then
    echo -e "${RED}ERROR: libtlsnoverify.so not preloaded!${NC}"
    echo "Usage: LD_PRELOAD=/path/to/libtlsnoverify.so $0"
    exit 1
fi

echo "=== TLS Preloader Test Suite ==="
echo "LD_PRELOAD: $LD_PRELOAD"
echo "Debug: ${TLS_NOVERIFY_DEBUG:-0}"
echo "Backtrace: ${TLS_NOVERIFY_BACKTRACE:-0}"
echo

# Test expired certificate sites
echo -e "${YELLOW}=== Testing HTTPS Clients ===${NC}"

# curl tests
if command -v curl &> /dev/null; then
    run_test "curl - expired cert" "curl -s -I https://expired.badssl.com | grep -q 'HTTP/'"
    run_test "curl - self-signed cert" "curl -s -I https://self-signed.badssl.com | grep -q 'HTTP/'"
fi

# wget tests  
if command -v wget &> /dev/null; then
    run_test "wget - expired cert" "wget -q -O /dev/null --timeout=5 https://expired.badssl.com"
    run_test "wget - self-signed cert" "wget -q -O /dev/null --timeout=5 https://self-signed.badssl.com"
fi

# openssl s_client test
if command -v openssl &> /dev/null; then
    run_test "openssl s_client" "echo Q | timeout 5 openssl s_client -connect expired.badssl.com:443 2>&1 | grep -q 'Verify return code: 0'"
fi

# gnutls-cli test
if command -v gnutls-cli &> /dev/null; then
    run_test "gnutls-cli" "echo Q | timeout 5 gnutls-cli --port 443 expired.badssl.com 2>&1 | grep -q 'Session ID:'"
fi

# Test library functions directly
echo -e "${YELLOW}=== Testing Library Functions ===${NC}"

# Create a simple C test program
cat > /tmp/test_lib.c << 'EOF'
#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 1;
    
    // Test OpenSSL
    long (*ssl_result)(void*) = dlsym(handle, "SSL_get_verify_result");
    if (ssl_result) {
        long result = ssl_result(NULL);
        printf("SSL_get_verify_result: %ld (expected 0)\n", result);
        if (result != 0) return 1;
    }
    
    // Test GnuTLS
    int (*gnutls_verify)(void*, unsigned int*) = dlsym(handle, "gnutls_certificate_verify_peers2");
    if (gnutls_verify) {
        unsigned int status = 999;
        int ret = gnutls_verify(NULL, &status);
        printf("gnutls_certificate_verify_peers2: ret=%d status=%u (expected 0,0)\n", ret, status);
        if (ret != 0 || status != 0) return 1;
    }
    
    // Test NSS
    int (*nss_auth)(void*, void*, void*) = dlsym(handle, "SSL_AuthCertificateHook");
    if (nss_auth) {
        printf("NSS SSL_AuthCertificateHook: found (bypass active)\n");
    }
    
    return 0;
}
EOF

if cc -o /tmp/test_lib /tmp/test_lib.c -ldl 2>/dev/null; then
    run_test "Library function bypass" "/tmp/test_lib"
    rm -f /tmp/test_lib /tmp/test_lib.c
fi

# Test backtrace functionality
echo -e "${YELLOW}=== Testing Backtrace Support ===${NC}"

# Check libc type
if ldd --version 2>&1 | grep -q musl; then
    echo "Detected musl libc"
    if ldconfig -p 2>/dev/null | grep -q libexecinfo || [ -f /usr/lib/libexecinfo.so ]; then
        echo "libexecinfo is available"
    else
        echo "libexecinfo not found - backtrace may not be available"
    fi
else
    echo "Detected glibc - native backtrace support"
fi

# Summary
echo
echo "=== Test Summary ==="
echo "Total tests: $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi