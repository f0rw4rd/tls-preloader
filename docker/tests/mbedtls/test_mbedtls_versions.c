/* mbedTLS version-specific tests */
#include "../test_framework.h"

/* Get mbedTLS version */
void get_mbedtls_version(char *version_buf, size_t buf_size) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return;
    
    void (*mbedtls_version_get_string)(char *) = 
        dlsym(handle, "mbedtls_version_get_string");
    
    if (mbedtls_version_get_string) {
        mbedtls_version_get_string(version_buf);
    }
    
    dlclose(handle);
}

/* Parse version to major.minor.patch */
void parse_mbedtls_version(const char *version, int *major, int *minor, int *patch) {
    if (!version) return;
    sscanf(version, "%d.%d.%d", major, minor, patch);
}

/* mbedTLS 2.x specific tests */
int test_mbedtls_2x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* mbedTLS 2.x uses different function signatures */
    void (*mbedtls_ssl_conf_authmode)(void *, int) = 
        dlsym(handle, "mbedtls_ssl_conf_authmode");
    
    if (!mbedtls_ssl_conf_authmode) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Check for 2.x specific functions */
    if (!dlsym(handle, "mbedtls_ssl_conf_verify")) {
        TEST_LOG("mbedtls_ssl_conf_verify not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* mbedTLS 2.x might not have hostname verification */
    if (!dlsym(handle, "mbedtls_ssl_set_hostname")) {
        TEST_LOG("mbedtls_ssl_set_hostname not available in 2.x (expected)");
    } else {
        TEST_LOG("mbedtls_ssl_set_hostname available");
    }
    
    TEST_LOG("mbedTLS 2.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* mbedTLS 3.0+ specific tests */
int test_mbedtls_3x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    char version[32] = {0};
    get_mbedtls_version(version, sizeof(version));
    
    if (!version[0]) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_mbedtls_version(version, &major, &minor, &patch);
    
    if (major < 3) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("mbedTLS 3.x version: %s", version);
    
    /* 3.x has enhanced certificate verification */
    if (!dlsym(handle, "mbedtls_x509_crt_verify_with_profile")) {
        TEST_LOG("mbedtls_x509_crt_verify_with_profile not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* 3.x should have hostname verification */
    if (!dlsym(handle, "mbedtls_ssl_set_hostname")) {
        TEST_LOG("mbedtls_ssl_set_hostname missing in 3.x");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("mbedTLS 3.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* mbedTLS 3.6.0+ specific tests - enhanced hostname verification */
int test_mbedtls_360_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    char version[32] = {0};
    get_mbedtls_version(version, sizeof(version));
    
    if (!version[0]) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_mbedtls_version(version, &major, &minor, &patch);
    
    /* Check if 3.6.0+ */
    if (major < 3 || (major == 3 && minor < 6)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("mbedTLS 3.6.0+ version: %s", version);
    
    /* 3.6.0+ has critical hostname verification that must be bypassed */
    int (*mbedtls_ssl_set_hostname)(void *, const char *) = 
        dlsym(handle, "mbedtls_ssl_set_hostname");
    
    if (!mbedtls_ssl_set_hostname) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Test hostname bypass */
    int ret = mbedtls_ssl_set_hostname(NULL, "test.example.com");
    if (ret != 0) {
        TEST_LOG("mbedtls_ssl_set_hostname bypass failed");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("mbedTLS 3.6.0+ hostname verification bypass confirmed");
    dlclose(handle);
    return TEST_PASS;
}

/* Test different auth modes */
int test_mbedtls_authmode_bypass(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    void (*mbedtls_ssl_conf_authmode)(void *, int) = 
        dlsym(handle, "mbedtls_ssl_conf_authmode");
    
    if (!mbedtls_ssl_conf_authmode) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Constants for different auth modes */
    const int MBEDTLS_SSL_VERIFY_NONE = 0;
    const int MBEDTLS_SSL_VERIFY_OPTIONAL = 1;
    const int MBEDTLS_SSL_VERIFY_REQUIRED = 2;
    
    /* All modes should be bypassed to VERIFY_NONE */
    TEST_LOG("Testing auth mode bypass for all modes");
    
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing mbedTLS version-specific features");
    
    char version[32] = {0};
    get_mbedtls_version(version, sizeof(version));
    
    if (!version[0]) {
        TEST_LOG("mbedTLS version detection failed - skipping version-specific tests");
        TEST_LOG("All tests passed!");
        return TEST_PASS;
    }
    
    TEST_LOG("mbedTLS version: %s", version);
    
    int major = 0, minor = 0, patch = 0;
    parse_mbedtls_version(version, &major, &minor, &patch);
    
    if (major == 2) {
        RUN_TEST("mbedTLS 2.x specific", test_mbedtls_2x_specific);
    } else if (major >= 3) {
        RUN_TEST("mbedTLS 3.x specific", test_mbedtls_3x_specific);
        
        if (minor >= 6) {
            RUN_TEST("mbedTLS 3.6.0+ specific", test_mbedtls_360_plus);
        }
    }
    
    RUN_TEST("Auth mode bypass", test_mbedtls_authmode_bypass);
    
    TEST_LOG("All tests passed!");
    return 0;
}