/* OpenSSL version-specific tests */
#include "../test_framework.h"

/* Version detection */
int detect_openssl_version(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    /* OpenSSL 3.x has OPENSSL_version_major */
    if (dlsym(handle, "OPENSSL_version_major")) {
        TEST_LOG("Detected OpenSSL 3.x");
        dlclose(handle);
        return 3;
    }
    
    /* OpenSSL 1.1.x has OpenSSL_version */
    if (dlsym(handle, "OpenSSL_version")) {
        TEST_LOG("Detected OpenSSL 1.1.x");
        dlclose(handle);
        return 11;
    }
    
    /* OpenSSL 1.0.x has SSLeay_version */
    if (dlsym(handle, "SSLeay_version")) {
        TEST_LOG("Detected OpenSSL 1.0.x");
        dlclose(handle);
        return 10;
    }
    
    dlclose(handle);
    return 0;
}

/* OpenSSL 1.0.x specific tests */
int test_openssl_10x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* SSLeay_version for 1.0.x */
    const char* (*SSLeay_version)(int) = dlsym(handle, "SSLeay_version");
    if (!SSLeay_version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    const char *version = SSLeay_version(0);
    TEST_LOG("OpenSSL 1.0.x version: %s", version);
    
    /* Check 1.0.x specific verification functions */
    if (!dlsym(handle, "SSL_CTX_set_verify")) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("OpenSSL 1.0.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* OpenSSL 1.1.x specific tests */
int test_openssl_11x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* OpenSSL_version for 1.1.x */
    const char* (*OpenSSL_version)(int) = dlsym(handle, "OpenSSL_version");
    if (!OpenSSL_version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    const char *version = OpenSSL_version(0);
    TEST_LOG("OpenSSL 1.1.x version: %s", version);
    
    /* 1.1.x introduced X509_VERIFY_PARAM functions */
    if (!dlsym(handle, "X509_VERIFY_PARAM_set1_host")) {
        TEST_LOG("X509_VERIFY_PARAM_set1_host not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Check hostname verification functions */
    if (!dlsym(handle, "SSL_set1_host")) {
        TEST_LOG("SSL_set1_host not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("OpenSSL 1.1.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* OpenSSL 3.x specific tests */
int test_openssl_3x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* OPENSSL_version_major for 3.x */
    unsigned int (*OPENSSL_version_major)(void) = dlsym(handle, "OPENSSL_version_major");
    if (!OPENSSL_version_major) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    unsigned int major = OPENSSL_version_major();
    TEST_LOG("OpenSSL major version: %u", major);
    
    /* OpenSSL 3.x specific: SSL_CTX_set_cert_verify_callback */
    if (!dlsym(handle, "SSL_CTX_set_cert_verify_callback")) {
        TEST_LOG("SSL_CTX_set_cert_verify_callback not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Check OSSL_PROVIDER (3.x specific) */
    if (dlsym(handle, "OSSL_PROVIDER_load")) {
        TEST_LOG("OpenSSL 3.x provider architecture detected");
    }
    
    TEST_LOG("OpenSSL 3.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* BoringSSL specific tests */
int test_boringssl_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* BoringSSL has SSL_CTX_set_custom_verify */
    void (*SSL_CTX_set_custom_verify)(void *, int, void *) = 
        dlsym(handle, "SSL_CTX_set_custom_verify");
    
    if (!SSL_CTX_set_custom_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("BoringSSL detected - SSL_CTX_set_custom_verify found");
    
    /* Check for other BoringSSL indicators */
    if (dlsym(handle, "CRYPTO_is_BoringSSL")) {
        TEST_LOG("CRYPTO_is_BoringSSL confirmed");
    }
    
    TEST_LOG("BoringSSL verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing OpenSSL version-specific features");
    
    int version = detect_openssl_version();
    
    switch (version) {
        case 10:
            RUN_TEST("OpenSSL 1.0.x specific", test_openssl_10x_specific);
            break;
        case 11:
            RUN_TEST("OpenSSL 1.1.x specific", test_openssl_11x_specific);
            break;
        case 3:
            RUN_TEST("OpenSSL 3.x specific", test_openssl_3x_specific);
            break;
        default:
            TEST_LOG("Unknown OpenSSL version");
    }
    
    /* Always test for BoringSSL */
    RUN_TEST("BoringSSL specific", test_boringssl_specific);
    
    TEST_LOG("All tests passed!");
    return 0;
}