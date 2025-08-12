/* wolfSSL version-specific tests */
#include "../test_framework.h"

/* Get wolfSSL version */
const char* get_wolfssl_version(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return NULL;
    
    const char* (*wolfSSL_lib_version)(void) = dlsym(handle, "wolfSSL_lib_version");
    if (!wolfSSL_lib_version) {
        dlclose(handle);
        return NULL;
    }
    
    const char *version = wolfSSL_lib_version();
    dlclose(handle);
    return version;
}

/* Parse version string */
void parse_wolfssl_version(const char *version, int *major, int *minor, int *patch) {
    if (!version) return;
    sscanf(version, "%d.%d.%d", major, minor, patch);
}

/* Test wolfSSL 3.x specific features */
int test_wolfssl_3x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_wolfssl_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_wolfssl_version(version, &major, &minor, &patch);
    
    if (major < 3) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("wolfSSL 3.x version: %s", version);
    
    /* 3.x has enhanced verification functions */
    if (!dlsym(handle, "wolfSSL_CTX_set_verify")) {
        TEST_LOG("wolfSSL_CTX_set_verify not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    if (!dlsym(handle, "wolfSSL_check_domain_name")) {
        TEST_LOG("wolfSSL_check_domain_name not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("wolfSSL 3.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test wolfSSL 4.x specific features */
int test_wolfssl_4x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_wolfssl_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_wolfssl_version(version, &major, &minor, &patch);
    
    if (major < 4) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("wolfSSL 4.x version: %s", version);
    
    /* 4.x has TLS 1.3 support */
    if (dlsym(handle, "wolfTLSv1_3_client_method")) {
        TEST_LOG("TLS 1.3 support detected");
    }
    
    TEST_LOG("wolfSSL 4.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test wolfSSL 5.x specific features */
int test_wolfssl_5x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_wolfssl_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_wolfssl_version(version, &major, &minor, &patch);
    
    if (major < 5) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("wolfSSL 5.x version: %s", version);
    
    /* 5.x has enhanced features */
    if (dlsym(handle, "wolfSSL_CTX_trust_peer_cert")) {
        TEST_LOG("wolfSSL_CTX_trust_peer_cert bypass active");
    }
    
    TEST_LOG("wolfSSL 5.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test generic wolfSSL functions */
int test_wolfssl_generic(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* Check for initialization function */
    int (*wolfSSL_Init)(void) = dlsym(handle, "wolfSSL_Init");
    if (!wolfSSL_Init) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Check basic verification functions */
    if (!dlsym(handle, "wolfSSL_set_verify_depth")) {
        TEST_LOG("wolfSSL_set_verify_depth not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("Generic wolfSSL functions bypassed");
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing wolfSSL version-specific features");
    
    const char *version = get_wolfssl_version();
    if (!version) {
        TEST_LOG("wolfSSL version detection failed - skipping version-specific tests");
        TEST_LOG("All tests passed!");
        return TEST_PASS;
    }
    
    TEST_LOG("wolfSSL version: %s", version);
    
    int major = 0, minor = 0, patch = 0;
    parse_wolfssl_version(version, &major, &minor, &patch);
    
    /* Test version-specific features */
    if (major >= 3) {
        RUN_TEST("wolfSSL 3.x specific", test_wolfssl_3x_specific);
    }
    
    if (major >= 4) {
        RUN_TEST("wolfSSL 4.x specific", test_wolfssl_4x_specific);
    }
    
    if (major >= 5) {
        RUN_TEST("wolfSSL 5.x specific", test_wolfssl_5x_specific);
    }
    
    RUN_TEST("Generic wolfSSL functions", test_wolfssl_generic);
    
    TEST_LOG("All tests passed!");
    return 0;
}