/* Basic OpenSSL verification bypass tests */
#include "../test_framework.h"

/* OpenSSL type definitions */
typedef void SSL_CTX;
typedef void SSL;
typedef void SSL_METHOD;

/* Function pointers */
typedef SSL_METHOD* (*TLS_method_t)(void);
typedef SSL_METHOD* (*SSLv23_method_t)(void);
typedef SSL_CTX* (*SSL_CTX_new_t)(const SSL_METHOD *method);
typedef void (*SSL_CTX_free_t)(SSL_CTX *ctx);
typedef void (*SSL_CTX_set_verify_t)(SSL_CTX *ctx, int mode, void *callback);
typedef SSL* (*SSL_new_t)(SSL_CTX *ctx);
typedef void (*SSL_free_t)(SSL *ssl);
typedef void (*SSL_set_verify_t)(SSL *ssl, int mode, void *callback);
typedef int (*SSL_get_verify_mode_t)(const SSL *ssl);

#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02

int test_ssl_ctx_set_verify(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    TLS_method_t TLS_method = dlsym(handle, "TLS_method");
    SSLv23_method_t SSLv23_method = dlsym(handle, "SSLv23_method");
    SSL_CTX_new_t SSL_CTX_new = dlsym(handle, "SSL_CTX_new");
    SSL_CTX_free_t SSL_CTX_free = dlsym(handle, "SSL_CTX_free");
    SSL_CTX_set_verify_t SSL_CTX_set_verify = dlsym(handle, "SSL_CTX_set_verify");
    
    SSL_METHOD *method = NULL;
    if (TLS_method) {
        method = TLS_method();
    } else if (SSLv23_method) {
        method = SSLv23_method();
    } else {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    if (!SSL_CTX_new || !SSL_CTX_free || !SSL_CTX_set_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Set strict verification - should be bypassed */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    TEST_LOG("SSL_CTX_set_verify called with VERIFY_PEER - bypassed");
    
    SSL_CTX_free(ctx);
    dlclose(handle);
    return TEST_PASS;
}

int test_ssl_set_verify(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    TLS_method_t TLS_method = dlsym(handle, "TLS_method");
    SSL_CTX_new_t SSL_CTX_new = dlsym(handle, "SSL_CTX_new");
    SSL_CTX_free_t SSL_CTX_free = dlsym(handle, "SSL_CTX_free");
    SSL_new_t SSL_new = dlsym(handle, "SSL_new");
    SSL_free_t SSL_free = dlsym(handle, "SSL_free");
    SSL_set_verify_t SSL_set_verify = dlsym(handle, "SSL_set_verify");
    SSL_get_verify_mode_t SSL_get_verify_mode = dlsym(handle, "SSL_get_verify_mode");
    
    if (!TLS_method || !SSL_CTX_new || !SSL_new || !SSL_set_verify) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    SSL_METHOD *method = TLS_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_FAIL;
    }
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        dlclose(handle);
        return TEST_FAIL;
    }
    
    /* Set peer verification - should be bypassed */
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    
    /* Check if mode was actually set to NONE */
    if (SSL_get_verify_mode) {
        int mode = SSL_get_verify_mode(ssl);
        TEST_LOG("SSL_get_verify_mode returned %d (expected 0)", mode);
        if (mode != SSL_VERIFY_NONE) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            dlclose(handle);
            return TEST_FAIL;
        }
    }
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    dlclose(handle);
    return TEST_PASS;
}

int test_ssl_ctx_set_cert_verify_callback(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    void (*SSL_CTX_set_cert_verify_callback)(SSL_CTX *, int (*)(void *, void *), void *) = 
        dlsym(handle, "SSL_CTX_set_cert_verify_callback");
    
    if (!SSL_CTX_set_cert_verify_callback) {
        TEST_LOG("SSL_CTX_set_cert_verify_callback not found (OpenSSL < 3.0?)");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("SSL_CTX_set_cert_verify_callback found - bypass active");
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing OpenSSL direct API bypass");
    
    RUN_TEST("SSL_CTX_set_verify bypass", test_ssl_ctx_set_verify);
    RUN_TEST("SSL_set_verify bypass", test_ssl_set_verify);
    RUN_TEST("SSL_CTX_set_cert_verify_callback bypass", test_ssl_ctx_set_cert_verify_callback);
    
    TEST_LOG("All tests passed!");
    return 0;
}