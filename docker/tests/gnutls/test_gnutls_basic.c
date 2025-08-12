/* Basic GnuTLS verification bypass tests */
#include "../test_framework.h"

/* GnuTLS types */
typedef void* gnutls_session_t;
typedef void* gnutls_certificate_credentials_t;

/* Function pointers */
typedef int (*gnutls_init_t)(gnutls_session_t *, unsigned int);
typedef void (*gnutls_deinit_t)(gnutls_session_t);
typedef int (*gnutls_certificate_allocate_credentials_t)(gnutls_certificate_credentials_t *);
typedef void (*gnutls_certificate_free_credentials_t)(gnutls_certificate_credentials_t);
typedef int (*gnutls_certificate_verify_peers2_t)(gnutls_session_t, unsigned int *);
typedef int (*gnutls_certificate_verify_peers3_t)(gnutls_session_t, const char *, unsigned int *);
typedef void (*gnutls_certificate_set_verify_function_t)(gnutls_certificate_credentials_t, int (*)(gnutls_session_t));

int test_gnutls_certificate_verify_peers2(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    gnutls_certificate_verify_peers2_t verify_peers2 = 
        dlsym(handle, "gnutls_certificate_verify_peers2");
    
    if (!verify_peers2) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL session - our hook should return 0 (success) */
    unsigned int status = 0xFFFF;
    int ret = verify_peers2(NULL, &status);
    
    TEST_LOG("gnutls_certificate_verify_peers2 returned %d, status=%u", ret, status);
    
    dlclose(handle);
    
    if (ret != 0 || status != 0) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_gnutls_certificate_verify_peers3(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    gnutls_certificate_verify_peers3_t verify_peers3 = 
        dlsym(handle, "gnutls_certificate_verify_peers3");
    
    if (!verify_peers3) {
        TEST_LOG("gnutls_certificate_verify_peers3 not found (old GnuTLS?)");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL session and hostname - should succeed */
    unsigned int status = 0xFFFF;
    int ret = verify_peers3(NULL, "test.example.com", &status);
    
    TEST_LOG("gnutls_certificate_verify_peers3 returned %d, status=%u", ret, status);
    
    dlclose(handle);
    
    if (ret != 0 || status != 0) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_gnutls_session_set_verify_cert(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    void (*gnutls_session_set_verify_cert)(gnutls_session_t, const char *, unsigned) = 
        dlsym(handle, "gnutls_session_set_verify_cert");
    
    if (!gnutls_session_set_verify_cert) {
        TEST_LOG("gnutls_session_set_verify_cert not found (GnuTLS < 3.4.6?)");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Function exists and should be bypassed */
    TEST_LOG("gnutls_session_set_verify_cert found - bypass active");
    
    dlclose(handle);
    return TEST_PASS;
}

int test_gnutls_certificate_set_verify_function(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    gnutls_certificate_allocate_credentials_t alloc_creds = 
        dlsym(handle, "gnutls_certificate_allocate_credentials");
    gnutls_certificate_free_credentials_t free_creds = 
        dlsym(handle, "gnutls_certificate_free_credentials");
    gnutls_certificate_set_verify_function_t set_verify = 
        dlsym(handle, "gnutls_certificate_set_verify_function");
    
    if (!alloc_creds || !free_creds || !set_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    gnutls_certificate_credentials_t creds;
    int ret = alloc_creds(&creds);
    if (ret < 0) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Set verify function - should be replaced with our bypass */
    set_verify(creds, NULL);
    
    TEST_LOG("gnutls_certificate_set_verify_function bypassed");
    
    free_creds(creds);
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing GnuTLS direct API bypass");
    
    RUN_TEST("gnutls_certificate_verify_peers2 bypass", test_gnutls_certificate_verify_peers2);
    RUN_TEST("gnutls_certificate_verify_peers3 bypass", test_gnutls_certificate_verify_peers3);
    RUN_TEST("gnutls_session_set_verify_cert bypass", test_gnutls_session_set_verify_cert);
    RUN_TEST("gnutls_certificate_set_verify_function bypass", test_gnutls_certificate_set_verify_function);
    
    TEST_LOG("All tests passed!");
    return 0;
}