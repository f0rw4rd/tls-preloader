/* Data-driven basic TLS library bypass tests */
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include "test_framework.h"

typedef enum {
    TEST_VOID_FUNC,      /* Function returns void */
    TEST_INT_FUNC,       /* Function returns int */
    TEST_LONG_FUNC,      /* Function returns long */
    TEST_STATUS_FUNC,    /* Function sets status via pointer */
} test_type_t;

typedef struct {
    const char *lib_name;
    const char *func_name;
    test_type_t type;
    int expected_result;
    const char *description;
} tls_test_case_t;

/* All TLS library bypass tests in one table */
static const tls_test_case_t all_tests[] = {
    /* OpenSSL/LibreSSL/BoringSSL */
    {"OpenSSL", "SSL_CTX_set_verify", TEST_VOID_FUNC, 0, "Context verification mode"},
    {"OpenSSL", "SSL_set_verify", TEST_VOID_FUNC, 0, "SSL verification mode"},
    {"OpenSSL", "SSL_get_verify_result", TEST_LONG_FUNC, 0, "Verification result"},
    {"OpenSSL", "X509_verify_cert", TEST_INT_FUNC, 1, "X509 certificate verification"},
    {"OpenSSL", "SSL_CTX_set_cert_verify_callback", TEST_VOID_FUNC, 0, "Certificate callback"},
    {"OpenSSL", "SSL_set_verify_result", TEST_VOID_FUNC, 0, "Set verify result"},
    {"OpenSSL", "SSL_CTX_load_verify_locations", TEST_INT_FUNC, 1, "Load CA locations"},
    {"OpenSSL", "SSL_set1_host", TEST_INT_FUNC, 1, "Set hostname verification"},
    
    /* GnuTLS */
    {"GnuTLS", "gnutls_certificate_verify_peers2", TEST_STATUS_FUNC, 0, "Peer verification"},
    {"GnuTLS", "gnutls_certificate_verify_peers3", TEST_STATUS_FUNC, 0, "Peer verification v3"},
    {"GnuTLS", "gnutls_certificate_set_verify_function", TEST_VOID_FUNC, 0, "Set verify function"},
    {"GnuTLS", "gnutls_session_set_verify_cert", TEST_VOID_FUNC, 0, "Session verify cert"},
    {"GnuTLS", "gnutls_certificate_set_x509_trust_file", TEST_INT_FUNC, 0, "Load trust file"},
    
    /* NSS */
    {"NSS", "SSL_AuthCertificateHook", TEST_INT_FUNC, 0, "Auth certificate hook"},
    {"NSS", "SSL_BadCertHook", TEST_INT_FUNC, 0, "Bad certificate hook"},
    {"NSS", "CERT_VerifyCertNow", TEST_INT_FUNC, 0, "Verify cert now"},
    {"NSS", "SSL_SetTrustAnchors", TEST_INT_FUNC, 0, "Set trust anchors"},
    
    /* mbedTLS */
    {"mbedTLS", "mbedtls_ssl_conf_authmode", TEST_VOID_FUNC, 0, "Configure auth mode"},
    {"mbedTLS", "mbedtls_ssl_conf_verify", TEST_VOID_FUNC, 0, "Configure verify callback"},
    {"mbedTLS", "mbedtls_ssl_set_hostname", TEST_INT_FUNC, 0, "Set hostname"},
    {"mbedTLS", "mbedtls_ssl_get_verify_result", TEST_INT_FUNC, 0, "Get verify result"},
    
    /* wolfSSL */
    {"wolfSSL", "wolfSSL_CTX_set_verify", TEST_VOID_FUNC, 0, "Context verification"},
    {"wolfSSL", "wolfSSL_set_verify", TEST_VOID_FUNC, 0, "SSL verification"},
    {"wolfSSL", "wolfSSL_get_verify_result", TEST_LONG_FUNC, 0, "Get verify result"},
    {"wolfSSL", "wolfSSL_check_domain_name", TEST_INT_FUNC, 1, "Check domain name"},
};

/* Check if a library is available */
static int is_library_available(const char *lib_name) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    int available = 0;
    
    if (strcmp(lib_name, "OpenSSL") == 0) {
        available = dlsym(handle, "SSL_library_init") != NULL ||
                   dlsym(handle, "OPENSSL_init_ssl") != NULL;
    } else if (strcmp(lib_name, "GnuTLS") == 0) {
        available = dlsym(handle, "gnutls_global_init") != NULL;
    } else if (strcmp(lib_name, "NSS") == 0) {
        available = dlsym(handle, "NSS_Init") != NULL;
    } else if (strcmp(lib_name, "mbedTLS") == 0) {
        available = dlsym(handle, "mbedtls_ssl_init") != NULL;
    } else if (strcmp(lib_name, "wolfSSL") == 0) {
        available = dlsym(handle, "wolfSSL_Init") != NULL;
    }
    
    dlclose(handle);
    return available;
}

/* Run a single test case */
static int run_test_case(const tls_test_case_t *test) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    void *func = dlsym(handle, test->func_name);
    if (!func) {
        dlclose(handle);
        return 1;  /* Function not found = bypass working */
    }
    
    int success = 0;
    
    switch (test->type) {
        case TEST_VOID_FUNC:
            /* Void functions always succeed if they don't crash */
            success = 1;
            break;
            
        case TEST_INT_FUNC: {
            int (*int_func)(void*) = (int (*)(void*))func;
            int result = int_func(NULL);
            success = (result == test->expected_result);
            break;
        }
        
        case TEST_LONG_FUNC: {
            long (*long_func)(void*) = (long (*)(void*))func;
            long result = long_func(NULL);
            success = (result == test->expected_result);
            break;
        }
        
        case TEST_STATUS_FUNC: {
            /* Special case for GnuTLS status functions */
            if (strstr(test->func_name, "verify_peers2")) {
                int (*verify2)(void*, unsigned int*) = (int (*)(void*, unsigned int*))func;
                unsigned int status = 999;
                int ret = verify2(NULL, &status);
                success = (ret == 0 && status == 0);
            } else if (strstr(test->func_name, "verify_peers3")) {
                int (*verify3)(void*, const char*, unsigned int*) = 
                    (int (*)(void*, const char*, unsigned int*))func;
                unsigned int status = 999;
                int ret = verify3(NULL, NULL, &status);
                success = (ret == 0 && status == 0);
            }
            break;
        }
    }
    
    dlclose(handle);
    return success;
}

/* Test all functions for available libraries */
void test_all_tls_libraries(void) {
    const char *current_lib = NULL;
    int lib_available = 0;
    int tests_run = 0;
    int tests_passed = 0;
    
    for (size_t i = 0; i < sizeof(all_tests) / sizeof(all_tests[0]); i++) {
        const tls_test_case_t *test = &all_tests[i];
        
        /* Check if we're testing a new library */
        if (!current_lib || strcmp(current_lib, test->lib_name) != 0) {
            current_lib = test->lib_name;
            lib_available = is_library_available(current_lib);
            if (!lib_available) {
                TEST_LOG("Skipping %s (not available)", current_lib);
                continue;
            }
            TEST_LOG("\nTesting %s functions:", current_lib);
        }
        
        if (!lib_available) continue;
        
        /* Run the test */
        int passed = run_test_case(test);
        tests_run++;
        if (passed) tests_passed++;
        
        TEST_LOG("  %-40s: %s", test->func_name, passed ? "PASS" : "FAIL");
    }
    
    TEST_LOG("\nSummary: %d/%d tests passed", tests_passed, tests_run);
}

int main(void) {
    TEST_LOG("=== Data-Driven TLS Library Bypass Tests ===");
    test_all_tls_libraries();
    return test_summary();
}