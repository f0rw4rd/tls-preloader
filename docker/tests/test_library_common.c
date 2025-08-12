/* Common library testing implementation */
#include "test_library_common.h"
#include <dlfcn.h>

/* Test if library function exists */
int test_library_function_exists(const char *func_name) {
    void *func = dlsym_bypass(func_name);
    if (func) {
        TEST_LOG("%s found - bypass active", func_name);
        return TEST_PASS;
    }
    TEST_LOG("%s not found", func_name);
    return TEST_SKIP;
}

/* Test if library function returns expected value */
int test_library_function_returns(const char *func_name, int expected) {
    /* Special handling for GnuTLS functions that need proper parameters */
    if (strstr(func_name, "gnutls_certificate_verify_peers")) {
        if (strcmp(func_name, "gnutls_certificate_verify_peers2") == 0) {
            typedef int (*gnutls_verify2_func_t)(void *, unsigned int *);
            gnutls_verify2_func_t func = (gnutls_verify2_func_t)dlsym_bypass(func_name);
            
            if (!func) {
                TEST_LOG("%s not found", func_name);
                return TEST_SKIP;
            }
            
            unsigned int status = 0xFFFFFFFF;  /* Non-zero to test bypass */
            int result = func(NULL, &status);
            if (result == expected && status == 0) {
                TEST_LOG("%s returned %d with status=0 (expected %d)", func_name, result, expected);
                return TEST_PASS;
            }
            
            TEST_ERROR("%s returned %d with status=%u (expected %d with status=0)", 
                       func_name, result, status, expected);
            return TEST_FAIL;
        } else if (strcmp(func_name, "gnutls_certificate_verify_peers3") == 0) {
            typedef int (*gnutls_verify3_func_t)(void *, const char *, unsigned int *);
            gnutls_verify3_func_t func = (gnutls_verify3_func_t)dlsym_bypass(func_name);
            
            if (!func) {
                TEST_LOG("%s not found", func_name);
                return TEST_SKIP;
            }
            
            unsigned int status = 0xFFFFFFFF;  /* Non-zero to test bypass */
            int result = func(NULL, "test.example.com", &status);
            if (result == expected && status == 0) {
                TEST_LOG("%s returned %d with status=0 (expected %d)", func_name, result, expected);
                return TEST_PASS;
            }
            
            TEST_ERROR("%s returned %d with status=%u (expected %d with status=0)", 
                       func_name, result, status, expected);
            return TEST_FAIL;
        }
    }
    
    /* Default behavior for other functions */
    typedef int (*func_ptr_t)(void *);
    func_ptr_t func = (func_ptr_t)dlsym_bypass(func_name);
    
    if (!func) {
        TEST_LOG("%s not found", func_name);
        return TEST_SKIP;
    }
    
    int result = func(NULL);
    if (result == expected) {
        TEST_LOG("%s returned %d (expected %d)", func_name, result, expected);
        return TEST_PASS;
    }
    
    TEST_ERROR("%s returned %d (expected %d)", func_name, result, expected);
    return TEST_FAIL;
}

/* Test if library bypass is active */
int test_library_bypass_active(const char *func_name, void *test_arg) {
    void *func = dlsym_bypass(func_name);
    if (!func) {
        return TEST_SKIP;
    }
    
    /* Function exists, bypass should be active */
    TEST_LOG("%s bypass active", func_name);
    return TEST_PASS;
}

/* Test library version */
int test_library_version(const char *version_func, const char *min_version) {
    typedef const char* (*version_func_t)(void);
    version_func_t get_version = (version_func_t)dlsym_bypass(version_func);
    
    if (!get_version) {
        TEST_LOG("Version function %s not found", version_func);
        return TEST_SKIP;
    }
    
    const char *version = get_version();
    if (!version) {
        TEST_LOG("Failed to get version");
        return TEST_SKIP;
    }
    
    TEST_LOG("Library version: %s", version);
    return TEST_PASS;
}

/* Run library tests */
int run_library_tests(const char *lib_name, lib_test_case_t *tests, int num_tests) {
    int i;
    int failed = 0;
    
    printf("\n=== Testing %s ===\n", lib_name);
    
    for (i = 0; i < num_tests; i++) {
        int result = TEST_SKIP;
        
        switch (tests[i].type) {
            case LIB_TEST_FUNCTION_EXISTS:
                result = test_library_function_exists(tests[i].function_name);
                break;
            case LIB_TEST_FUNCTION_RETURNS:
                result = test_library_function_returns(tests[i].function_name, tests[i].expected_value);
                break;
            case LIB_TEST_FUNCTION_BYPASS:
                result = test_library_bypass_active(tests[i].function_name, tests[i].test_arg);
                break;
            default:
                TEST_ERROR("Unknown test type: %d", tests[i].type);
                result = TEST_ERROR;
        }
        
        if (result == TEST_FAIL) {
            failed++;
        }
        
        /* Print result */
        const char *status = result == TEST_PASS ? "PASS" : 
                           result == TEST_FAIL ? "FAIL" : 
                           result == TEST_SKIP ? "SKIP" : "ERROR";
        printf("  %-40s [%s]\n", tests[i].name, status);
    }
    
    return failed > 0 ? TEST_FAIL : TEST_PASS;
}

/* Common OpenSSL bypass test */
int test_openssl_bypass(void) {
    lib_test_case_t tests[] = {
        {"SSL_CTX_set_verify", "SSL_CTX_set_verify", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"SSL_set_verify", "SSL_set_verify", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"SSL_CTX_set_cert_verify_callback", "SSL_CTX_set_cert_verify_callback", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"X509_verify_cert", "X509_verify_cert", LIB_TEST_FUNCTION_RETURNS, 1, NULL},
        {"X509_STORE_CTX_set_error", "X509_STORE_CTX_set_error", LIB_TEST_FUNCTION_EXISTS, 0, NULL}
    };
    
    return run_library_tests("OpenSSL", tests, sizeof(tests)/sizeof(tests[0]));
}

/* Common GnuTLS bypass test */
int test_gnutls_bypass(void) {
    lib_test_case_t tests[] = {
        {"gnutls_certificate_verify_peers2", "gnutls_certificate_verify_peers2", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"gnutls_certificate_verify_peers3", "gnutls_certificate_verify_peers3", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"gnutls_session_set_verify_cert", "gnutls_session_set_verify_cert", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"gnutls_certificate_set_verify_function", "gnutls_certificate_set_verify_function", LIB_TEST_FUNCTION_EXISTS, 0, NULL}
    };
    
    return run_library_tests("GnuTLS", tests, sizeof(tests)/sizeof(tests[0]));
}

/* Common mbedTLS bypass test */
int test_mbedtls_bypass(void) {
    lib_test_case_t tests[] = {
        {"mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_authmode", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"mbedtls_ssl_get_verify_result", "mbedtls_ssl_get_verify_result", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"mbedtls_ssl_set_hostname", "mbedtls_ssl_set_hostname", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"mbedtls_x509_crt_verify", "mbedtls_x509_crt_verify", LIB_TEST_FUNCTION_RETURNS, 0, NULL}
    };
    
    return run_library_tests("mbedTLS", tests, sizeof(tests)/sizeof(tests[0]));
}

/* Common wolfSSL bypass test */
int test_wolfssl_bypass(void) {
    lib_test_case_t tests[] = {
        {"wolfSSL_CTX_set_verify", "wolfSSL_CTX_set_verify", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"wolfSSL_set_verify", "wolfSSL_set_verify", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"wolfSSL_check_domain_name", "wolfSSL_check_domain_name", LIB_TEST_FUNCTION_RETURNS, 1, NULL},
        {"wolfSSL_CTX_load_verify_locations", "wolfSSL_CTX_load_verify_locations", LIB_TEST_FUNCTION_EXISTS, 0, NULL}
    };
    
    return run_library_tests("wolfSSL", tests, sizeof(tests)/sizeof(tests[0]));
}

/* Common NSS bypass test */
int test_nss_bypass(void) {
    lib_test_case_t tests[] = {
        {"SSL_AuthCertificateHook", "SSL_AuthCertificateHook", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"SSL_BadCertHook", "SSL_BadCertHook", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"CERT_VerifyCertNow", "CERT_VerifyCertNow", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"CERT_VerifyCert", "CERT_VerifyCert", LIB_TEST_FUNCTION_RETURNS, 0, NULL},
        {"CERT_VerifyCertificate", "CERT_VerifyCertificate", LIB_TEST_FUNCTION_EXISTS, 0, NULL},
        {"SSL_SetTrustAnchors", "SSL_SetTrustAnchors", LIB_TEST_FUNCTION_EXISTS, 0, NULL}
    };
    
    return run_library_tests("NSS", tests, sizeof(tests)/sizeof(tests[0]));
}