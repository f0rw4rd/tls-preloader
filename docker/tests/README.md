# TLS Preloader Test Framework

This directory contains a modular test framework for the TLS verification bypass library.

## Structure

- **test_common.h** - Shared header with test framework definitions
- **test_common.c** - Common test utilities and helper functions
- **test_basic_ssl.c** - Basic SSL/TLS certificate verification tests
- **test_curl_getinfo.c** - Tests for curl_easy_getinfo SSL verification
- **test_doh.c** - DNS-over-HTTPS (DoH) verification tests
- **test_ocsp.c** - OCSP stapling verification tests
- **test_concurrent.c** - Multi-threaded concurrent connection tests
- **run_tests.sh** - Main test runner script

## Building

```bash
# Build all tests
make

# Build specific test
make test_basic_ssl

# Clean build artifacts
make clean
```

## Running Tests

### Run all tests
```bash
./run_tests.sh
```

### Run without concurrent tests (for resource-limited environments)
```bash
./run_tests.sh --no-concurrent
```

### Run individual tests
```bash
LD_PRELOAD=../libtlsnoverify.so ./test_basic_ssl
LD_PRELOAD=../libtlsnoverify.so ./test_concurrent
```

### Run via Makefile
```bash
# Run all tests
make test

# Run specific test
make test-basic_ssl
make test-concurrent
```

## Test Framework Features

### Common Test Functions
- `test_init()` - Initialize test environment
- `test_cleanup()` - Clean up test environment
- `print_test_result()` - Print formatted test results
- `print_test_summary()` - Print test summary statistics

### CURL Helpers
- `create_curl_handle()` - Create pre-configured CURL handle
- `perform_curl_request()` - Perform HTTP request and check result
- `verify_ssl_result()` - Verify SSL certificate result
- `test_url()` - Test a specific URL
- `test_url_with_options()` - Test URL with custom CURL options

### Multi-threading Support
- `run_concurrent_requests()` - Run multiple concurrent requests
- `thread_worker()` - Worker function for threaded tests
- Performance measurement and stress testing capabilities

### Test Result Types
- `TEST_PASS` - Test passed successfully
- `TEST_FAIL` - Test failed
- `TEST_SKIP` - Test was skipped
- `TEST_ERROR` - Test encountered an error

## Adding New Tests

1. Create a new test file (e.g., `test_myfeature.c`)
2. Include `test_common.h`
3. Implement test functions returning `test_result_t`
4. Create a `main()` function that runs the tests
5. Add the test to `TEST_PROGS` in Makefile
6. Add it to `run_tests.sh`

### Example Test

```c
#include "test_common.h"

test_result_t test_my_feature(void) {
    TEST_LOG("Testing my feature");
    
    // Your test code here
    if (some_condition) {
        return TEST_PASS;
    } else {
        return TEST_FAIL;
    }
}

int main(void) {
    test_init();
    
    test_result_t result = test_my_feature();
    print_test_result("my_feature", result, NULL);
    
    test_cleanup();
    return (result == TEST_PASS) ? 0 : 1;
}
```

## Test Coverage

The test suite covers:
- Certificate expiration
- Hostname verification
- Self-signed certificates
- Untrusted root certificates
- Revoked certificates
- Missing certificate fields
- Incomplete certificate chains
- DNS-over-HTTPS verification
- OCSP stapling
- Concurrent connections
- Performance under load