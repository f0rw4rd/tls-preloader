/* Test library version detection and compatibility */
#include "test_common.h"
#include <dlfcn.h>

/* Version detection functions */
const char* detect_openssl_version(void) {
    void *handle;
    const char* (*version_func)(void);
    static char version_str[256] = "unknown";
    
    /* Try OpenSSL version functions */
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return version_str;
    
    /* Try OpenSSL_version (OpenSSL 1.1.0+) */
    version_func = dlsym(handle, "OpenSSL_version");
    if (version_func) {
        const char *ver = version_func();
        if (ver) {
            strncpy(version_str, ver, sizeof(version_str) - 1);
            version_str[sizeof(version_str) - 1] = '\0';
            dlclose(handle);
            return version_str;
        }
    }
    
    /* Try SSLeay_version (OpenSSL 1.0.x) */
    version_func = dlsym(handle, "SSLeay_version");
    if (version_func) {
        const char *ver = version_func();
        if (ver) {
            strncpy(version_str, ver, sizeof(version_str) - 1);
            version_str[sizeof(version_str) - 1] = '\0';
            dlclose(handle);
            return version_str;
        }
    }
    
    dlclose(handle);
    return version_str;
}

const char* detect_gnutls_version(void) {
    void *handle;
    const char* (*version_func)(const char*);
    static char version_str[256] = "unknown";
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return version_str;
    
    version_func = dlsym(handle, "gnutls_check_version");
    if (version_func) {
        const char *ver = version_func(NULL);
        if (ver) {
            snprintf(version_str, sizeof(version_str), "GnuTLS %s", ver);
            dlclose(handle);
            return version_str;
        }
    }
    
    dlclose(handle);
    return version_str;
}

const char* detect_nss_version(void) {
    void *handle;
    const char* (*version_func)(void);
    static char version_str[256] = "unknown";
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return version_str;
    
    version_func = dlsym(handle, "NSS_GetVersion");
    if (version_func) {
        const char *ver = version_func();
        if (ver) {
            snprintf(version_str, sizeof(version_str), "NSS %s", ver);
            dlclose(handle);
            return version_str;
        }
    }
    
    dlclose(handle);
    return version_str;
}

const char* detect_mbedtls_version(void) {
    void *handle;
    void (*version_func)(char*);
    static char version_str[256] = "unknown";
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return version_str;
    
    version_func = dlsym(handle, "mbedtls_version_get_string");
    if (version_func) {
        static char ver_buf[32];
        version_func(ver_buf);
        snprintf(version_str, sizeof(version_str), "mbedTLS %s", ver_buf);
        dlclose(handle);
        return version_str;
    }
    
    dlclose(handle);
    return version_str;
}

/* Test version detection */
test_result_t test_detect_versions(void) {
    int found_any = 0;
    
    TEST_LOG("Detecting TLS library versions:");
    
    /* Check OpenSSL */
    if (dlsym(NULL, "SSL_CTX_new")) {
        const char *ver = detect_openssl_version();
        TEST_LOG("  OpenSSL: %s", ver);
        found_any = 1;
    }
    
    /* Check GnuTLS */
    if (dlsym(NULL, "gnutls_init")) {
        const char *ver = detect_gnutls_version();
        TEST_LOG("  GnuTLS: %s", ver);
        found_any = 1;
    }
    
    /* Check NSS */
    if (dlsym(NULL, "NSS_Init")) {
        const char *ver = detect_nss_version();
        TEST_LOG("  NSS: %s", ver);
        found_any = 1;
    }
    
    /* Check mbedTLS */
    if (dlsym(NULL, "mbedtls_ssl_init")) {
        const char *ver = detect_mbedtls_version();
        TEST_LOG("  mbedTLS: %s", ver);
        found_any = 1;
    }
    
    return found_any ? TEST_PASS : TEST_SKIP;
}

/* Test version-specific features */
test_result_t test_openssl_version_specific(void) {
    void *handle;
    int is_openssl_3 = 0;
    int is_openssl_1_1 = 0;
    int is_openssl_1_0 = 0;
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* Detect OpenSSL version */
    if (dlsym(handle, "OPENSSL_version_major")) {
        is_openssl_3 = 1;
        TEST_LOG("Detected OpenSSL 3.x");
    } else if (dlsym(handle, "OpenSSL_version")) {
        is_openssl_1_1 = 1;
        TEST_LOG("Detected OpenSSL 1.1.x");
    } else if (dlsym(handle, "SSLeay_version")) {
        is_openssl_1_0 = 1;
        TEST_LOG("Detected OpenSSL 1.0.x");
    } else {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Test version-specific functions */
    if (is_openssl_3) {
        /* OpenSSL 3.x specific */
        if (dlsym(handle, "SSL_CTX_set_cert_verify_callback")) {
            TEST_LOG("  ✓ SSL_CTX_set_cert_verify_callback available");
        }
    }
    
    if (is_openssl_1_1 || is_openssl_3) {
        /* OpenSSL 1.1+ specific */
        if (dlsym(handle, "SSL_CTX_set_custom_verify")) {
            TEST_LOG("  ✓ SSL_CTX_set_custom_verify available (BoringSSL)");
        }
    }
    
    dlclose(handle);
    return TEST_PASS;
}

test_result_t test_gnutls_version_specific(void) {
    void *handle;
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    if (!dlsym(handle, "gnutls_init")) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("Testing GnuTLS version-specific features:");
    
    /* GnuTLS 3.4.6+ features */
    if (dlsym(handle, "gnutls_session_set_verify_cert")) {
        TEST_LOG("  ✓ gnutls_session_set_verify_cert available (3.4.6+)");
    } else {
        TEST_LOG("  - gnutls_session_set_verify_cert not available (< 3.4.6)");
    }
    
    /* GnuTLS 3.x features */
    if (dlsym(handle, "gnutls_certificate_set_verify_function")) {
        TEST_LOG("  ✓ gnutls_certificate_set_verify_function available");
    }
    
    dlclose(handle);
    return TEST_PASS;
}

test_result_t test_mbedtls_version_specific(void) {
    void *handle;
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    if (!dlsym(handle, "mbedtls_ssl_init")) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("Testing mbedTLS version-specific features:");
    
    /* mbedTLS 3.x features */
    if (dlsym(handle, "mbedtls_ssl_conf_verify")) {
        TEST_LOG("  ✓ mbedtls_ssl_conf_verify available");
    }
    
    /* Check for hostname verification (important for 3.6.0+) */
    if (dlsym(handle, "mbedtls_ssl_set_hostname")) {
        TEST_LOG("  ✓ mbedtls_ssl_set_hostname available");
    }
    
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_case_t tests[] = {
        {"detect_versions", "Detect TLS library versions", test_detect_versions, 5},
        {"openssl_version", "Test OpenSSL version-specific features", test_openssl_version_specific, 5},
        {"gnutls_version", "Test GnuTLS version-specific features", test_gnutls_version_specific, 5},
        {"mbedtls_version", "Test mbedTLS version-specific features", test_mbedtls_version_specific, 5}
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0, failed = 0, skipped = 0;
    int i;
    
    test_init();
    
    printf("\n=== TLS Library Version Detection Tests ===\n");
    
    for (i = 0; i < num_tests; i++) {
        print_test_header(tests[i].description);
        test_result_t result = tests[i].test_func();
        print_test_result(tests[i].name, result, NULL);
        
        switch (result) {
            case TEST_PASS:
                passed++;
                break;
            case TEST_FAIL:
                failed++;
                break;
            case TEST_SKIP:
                skipped++;
                break;
            default:
                failed++;
                break;
        }
    }
    
    print_test_summary(num_tests, passed, failed, skipped);
    test_cleanup();
    
    return (failed > 0) ? 1 : 0;
}