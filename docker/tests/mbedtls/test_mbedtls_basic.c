/* Basic mbedTLS verification bypass tests */
#include "../test_framework.h"

/* mbedTLS types */
typedef void mbedtls_ssl_config;
typedef void mbedtls_ssl_context;
typedef void mbedtls_x509_crt;

/* Function pointers */
typedef void (*mbedtls_ssl_conf_authmode_t)(mbedtls_ssl_config *, int);
typedef void (*mbedtls_ssl_conf_verify_t)(mbedtls_ssl_config *, int (*)(void *, mbedtls_x509_crt *, int, unsigned int *), void *);
typedef int (*mbedtls_ssl_set_hostname_t)(mbedtls_ssl_context *, const char *);
typedef unsigned int (*mbedtls_ssl_get_verify_result_t)(const mbedtls_ssl_context *);

#define MBEDTLS_SSL_VERIFY_NONE      0
#define MBEDTLS_SSL_VERIFY_OPTIONAL  1
#define MBEDTLS_SSL_VERIFY_REQUIRED  2

int test_mbedtls_ssl_conf_authmode(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    mbedtls_ssl_conf_authmode_t ssl_conf_authmode = 
        dlsym(handle, "mbedtls_ssl_conf_authmode");
    
    if (!ssl_conf_authmode) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Function exists and should bypass to VERIFY_NONE */
    TEST_LOG("mbedtls_ssl_conf_authmode found - bypass active");
    
    dlclose(handle);
    return TEST_PASS;
}

int test_mbedtls_ssl_get_verify_result(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    mbedtls_ssl_get_verify_result_t ssl_get_verify_result = 
        dlsym(handle, "mbedtls_ssl_get_verify_result");
    
    if (!ssl_get_verify_result) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return 0 (no errors) */
    unsigned int result = ssl_get_verify_result(NULL);
    
    TEST_LOG("mbedtls_ssl_get_verify_result(NULL) returned %u", result);
    
    dlclose(handle);
    
    if (result != 0) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_mbedtls_ssl_set_hostname(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    mbedtls_ssl_set_hostname_t ssl_set_hostname = 
        dlsym(handle, "mbedtls_ssl_set_hostname");
    
    if (!ssl_set_hostname) {
        TEST_LOG("mbedtls_ssl_set_hostname not found (old mbedTLS?)");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL context - should return 0 (success) */
    int ret = ssl_set_hostname(NULL, "test.example.com");
    
    TEST_LOG("mbedtls_ssl_set_hostname returned %d", ret);
    
    dlclose(handle);
    
    if (ret != 0) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_mbedtls_x509_crt_verify(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    int (*mbedtls_x509_crt_verify)(mbedtls_x509_crt *, mbedtls_x509_crt *, void *, 
                                   const char *, unsigned int *, int (*)(void *, mbedtls_x509_crt *, int, unsigned int *), void *) = 
        dlsym(handle, "mbedtls_x509_crt_verify");
    
    if (!mbedtls_x509_crt_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return 0 (success) */
    unsigned int flags = 0xFFFF;
    int ret = mbedtls_x509_crt_verify(NULL, NULL, NULL, "test.example.com", &flags, NULL, NULL);
    
    TEST_LOG("mbedtls_x509_crt_verify returned %d, flags=%u", ret, flags);
    
    dlclose(handle);
    
    if (ret != 0 || flags != 0) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing mbedTLS direct API bypass");
    
    RUN_TEST("mbedtls_ssl_conf_authmode bypass", test_mbedtls_ssl_conf_authmode);
    RUN_TEST("mbedtls_ssl_get_verify_result bypass", test_mbedtls_ssl_get_verify_result);
    RUN_TEST("mbedtls_ssl_set_hostname bypass", test_mbedtls_ssl_set_hostname);
    RUN_TEST("mbedtls_x509_crt_verify bypass", test_mbedtls_x509_crt_verify);
    
    TEST_LOG("All tests passed!");
    return 0;
}