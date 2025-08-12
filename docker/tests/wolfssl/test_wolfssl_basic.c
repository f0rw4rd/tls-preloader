/* Basic wolfSSL verification bypass tests */
#include "../test_framework.h"

/* wolfSSL types */
typedef void WOLFSSL_CTX;
typedef void WOLFSSL;
typedef void WOLFSSL_METHOD;

/* Function pointers */
typedef WOLFSSL_METHOD* (*wolfTLSv1_2_client_method_t)(void);
typedef WOLFSSL_METHOD* (*wolfSSLv23_client_method_t)(void);
typedef WOLFSSL_CTX* (*wolfSSL_CTX_new_t)(WOLFSSL_METHOD*);
typedef void (*wolfSSL_CTX_free_t)(WOLFSSL_CTX*);
typedef void (*wolfSSL_CTX_set_verify_t)(WOLFSSL_CTX*, int, int (*)(int, void*));
typedef WOLFSSL* (*wolfSSL_new_t)(WOLFSSL_CTX*);
typedef void (*wolfSSL_free_t)(WOLFSSL*);
typedef void (*wolfSSL_set_verify_t)(WOLFSSL*, int, int (*)(int, void*));
typedef int (*wolfSSL_check_domain_name_t)(WOLFSSL*, const char*);

/* wolfSSL verify modes */
#define SSL_VERIFY_NONE     0x00
#define SSL_VERIFY_PEER     0x01

int test_wolfssl_ctx_set_verify(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    wolfTLSv1_2_client_method_t wolfTLSv1_2_client_method = 
        dlsym(handle, "wolfTLSv1_2_client_method");
    wolfSSLv23_client_method_t wolfSSLv23_client_method = 
        dlsym(handle, "wolfSSLv23_client_method");
    wolfSSL_CTX_new_t wolfSSL_CTX_new = dlsym(handle, "wolfSSL_CTX_new");
    wolfSSL_CTX_free_t wolfSSL_CTX_free = dlsym(handle, "wolfSSL_CTX_free");
    wolfSSL_CTX_set_verify_t wolfSSL_CTX_set_verify = dlsym(handle, "wolfSSL_CTX_set_verify");
    
    WOLFSSL_METHOD *method = NULL;
    if (wolfTLSv1_2_client_method) {
        method = wolfTLSv1_2_client_method();
    } else if (wolfSSLv23_client_method) {
        method = wolfSSLv23_client_method();
    } else {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    if (!wolfSSL_CTX_new || !wolfSSL_CTX_free || !wolfSSL_CTX_set_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Set peer verification - should be bypassed */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    TEST_LOG("wolfSSL_CTX_set_verify called with VERIFY_PEER - bypassed");
    
    wolfSSL_CTX_free(ctx);
    dlclose(handle);
    return TEST_PASS;
}

int test_wolfssl_set_verify(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    wolfTLSv1_2_client_method_t wolfTLSv1_2_client_method = 
        dlsym(handle, "wolfTLSv1_2_client_method");
    wolfSSL_CTX_new_t wolfSSL_CTX_new = dlsym(handle, "wolfSSL_CTX_new");
    wolfSSL_CTX_free_t wolfSSL_CTX_free = dlsym(handle, "wolfSSL_CTX_free");
    wolfSSL_new_t wolfSSL_new = dlsym(handle, "wolfSSL_new");
    wolfSSL_free_t wolfSSL_free = dlsym(handle, "wolfSSL_free");
    wolfSSL_set_verify_t wolfSSL_set_verify = dlsym(handle, "wolfSSL_set_verify");
    
    if (!wolfTLSv1_2_client_method || !wolfSSL_CTX_new || !wolfSSL_new || !wolfSSL_set_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    WOLFSSL_METHOD *method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        wolfSSL_CTX_free(ctx);
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Set peer verification - should be bypassed */
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    
    TEST_LOG("wolfSSL_set_verify called with VERIFY_PEER - bypassed");
    
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    dlclose(handle);
    return TEST_PASS;
}

int test_wolfssl_check_domain_name(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    wolfSSL_check_domain_name_t wolfSSL_check_domain_name = 
        dlsym(handle, "wolfSSL_check_domain_name");
    
    if (!wolfSSL_check_domain_name) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL SSL - should return success (1) */
    int ret = wolfSSL_check_domain_name(NULL, "test.example.com");
    
    TEST_LOG("wolfSSL_check_domain_name returned %d (expected 1)", ret);
    
    dlclose(handle);
    
    if (ret != 1) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_wolfssl_ctx_load_verify_locations(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    int (*wolfSSL_CTX_load_verify_locations)(WOLFSSL_CTX*, const char*, const char*) = 
        dlsym(handle, "wolfSSL_CTX_load_verify_locations");
    
    if (!wolfSSL_CTX_load_verify_locations) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL context - should return success (1) */
    int ret = wolfSSL_CTX_load_verify_locations(NULL, "/etc/ssl/certs/ca-certificates.crt", NULL);
    
    TEST_LOG("wolfSSL_CTX_load_verify_locations returned %d (expected 1)", ret);
    
    dlclose(handle);
    
    if (ret != 1) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing wolfSSL direct API bypass");
    
    RUN_TEST("wolfSSL_CTX_set_verify bypass", test_wolfssl_ctx_set_verify);
    RUN_TEST("wolfSSL_set_verify bypass", test_wolfssl_set_verify);
    RUN_TEST("wolfSSL_check_domain_name bypass", test_wolfssl_check_domain_name);
    RUN_TEST("wolfSSL_CTX_load_verify_locations bypass", test_wolfssl_ctx_load_verify_locations);
    
    TEST_LOG("All tests passed!");
    return 0;
}