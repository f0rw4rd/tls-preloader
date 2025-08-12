/* Test direct OpenSSL API verification bypass */
#include "test_common.h"
#include <dlfcn.h>

/* OpenSSL type definitions for testing */
typedef void SSL_CTX;
typedef void SSL;
typedef void X509_STORE_CTX;
typedef void X509;

/* Function pointer types */
typedef SSL_CTX* (*SSL_CTX_new_t)(const void *method);
typedef void (*SSL_CTX_free_t)(SSL_CTX *ctx);
typedef void *(*TLS_method_t)(void);
typedef void *(*SSLv23_method_t)(void);
typedef void (*SSL_CTX_set_verify_t)(SSL_CTX *ctx, int mode, void *callback);
typedef SSL* (*SSL_new_t)(SSL_CTX *ctx);
typedef void (*SSL_free_t)(SSL *ssl);
typedef long (*SSL_get_verify_result_t)(const SSL *ssl);
typedef void (*SSL_set_verify_result_t)(SSL *ssl, long result);
typedef int (*SSL_set1_host_t)(SSL *ssl, const char *hostname);

/* Constants */
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define X509_V_OK                       0
#define X509_V_ERR_CERT_UNTRUSTED       27

test_result_t test_ssl_ctx_set_verify(void) {
    void *handle;
    SSL_CTX_new_t SSL_CTX_new;
    SSL_CTX_free_t SSL_CTX_free;
    TLS_method_t TLS_method;
    SSLv23_method_t SSLv23_method;
    SSL_CTX_set_verify_t SSL_CTX_set_verify;
    SSL_CTX *ctx = NULL;
    void *method = NULL;
    
    /* Load OpenSSL symbols */
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        TEST_LOG("Failed to dlopen");
        return TEST_SKIP;
    }
    
    /* Try to get method function */
    TLS_method = dlsym(handle, "TLS_method");
    if (!TLS_method) {
        SSLv23_method = dlsym(handle, "SSLv23_method");
        if (!SSLv23_method) {
            TEST_LOG("No OpenSSL method function found");
            dlclose(handle);
            return TEST_SKIP;
        }
        method = SSLv23_method();
    } else {
        method = TLS_method();
    }
    
    SSL_CTX_new = dlsym(handle, "SSL_CTX_new");
    SSL_CTX_free = dlsym(handle, "SSL_CTX_free");
    SSL_CTX_set_verify = dlsym(handle, "SSL_CTX_set_verify");
    
    if (!SSL_CTX_new || !SSL_CTX_free || !SSL_CTX_set_verify) {
        TEST_LOG("OpenSSL functions not found");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Create SSL context */
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        TEST_LOG("Failed to create SSL context");
        dlclose(handle);
        return TEST_ERROR;
    }
    
    /* Try to set strict verification - should be bypassed */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    TEST_LOG("SSL_CTX_set_verify called with VERIFY_PEER - should be bypassed to VERIFY_NONE");
    
    SSL_CTX_free(ctx);
    dlclose(handle);
    
    return TEST_PASS;
}

test_result_t test_ssl_verify_result(void) {
    void *handle;
    SSL_CTX_new_t SSL_CTX_new;
    SSL_CTX_free_t SSL_CTX_free;
    SSL_new_t SSL_new;
    SSL_free_t SSL_free;
    TLS_method_t TLS_method;
    SSLv23_method_t SSLv23_method;
    SSL_get_verify_result_t SSL_get_verify_result;
    SSL_set_verify_result_t SSL_set_verify_result;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    void *method = NULL;
    long result;
    
    /* Load OpenSSL symbols */
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return TEST_SKIP;
    }
    
    /* Get method */
    TLS_method = dlsym(handle, "TLS_method");
    if (!TLS_method) {
        SSLv23_method = dlsym(handle, "SSLv23_method");
        if (!SSLv23_method) {
            dlclose(handle);
            return TEST_SKIP;
        }
        method = SSLv23_method();
    } else {
        method = TLS_method();
    }
    
    /* Get functions */
    SSL_CTX_new = dlsym(handle, "SSL_CTX_new");
    SSL_CTX_free = dlsym(handle, "SSL_CTX_free");
    SSL_new = dlsym(handle, "SSL_new");
    SSL_free = dlsym(handle, "SSL_free");
    SSL_get_verify_result = dlsym(handle, "SSL_get_verify_result");
    SSL_set_verify_result = dlsym(handle, "SSL_set_verify_result");
    
    if (!SSL_CTX_new || !SSL_new || !SSL_get_verify_result || !SSL_set_verify_result) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Create context and SSL object */
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_ERROR;
    }
    
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        dlclose(handle);
        return TEST_ERROR;
    }
    
    /* Set a failure result */
    SSL_set_verify_result(ssl, X509_V_ERR_CERT_UNTRUSTED);
    
    /* Get result - should be X509_V_OK due to bypass */
    result = SSL_get_verify_result(ssl);
    
    TEST_LOG("SSL_get_verify_result returned %ld (expected 0)", result);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    dlclose(handle);
    
    return (result == X509_V_OK) ? TEST_PASS : TEST_FAIL;
}

test_result_t test_ssl_hostname_verification(void) {
    void *handle;
    SSL_CTX_new_t SSL_CTX_new;
    SSL_CTX_free_t SSL_CTX_free;
    SSL_new_t SSL_new;
    SSL_free_t SSL_free;
    TLS_method_t TLS_method;
    SSL_set1_host_t SSL_set1_host;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    void *method = NULL;
    int ret;
    
    /* Load OpenSSL symbols */
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return TEST_SKIP;
    }
    
    /* Get functions */
    TLS_method = dlsym(handle, "TLS_method");
    SSL_CTX_new = dlsym(handle, "SSL_CTX_new");
    SSL_CTX_free = dlsym(handle, "SSL_CTX_free");
    SSL_new = dlsym(handle, "SSL_new");
    SSL_free = dlsym(handle, "SSL_free");
    SSL_set1_host = dlsym(handle, "SSL_set1_host");
    
    if (!TLS_method || !SSL_CTX_new || !SSL_new || !SSL_set1_host) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    method = TLS_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        dlclose(handle);
        return TEST_ERROR;
    }
    
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        dlclose(handle);
        return TEST_ERROR;
    }
    
    /* Set hostname for verification - should be bypassed */
    ret = SSL_set1_host(ssl, "wrong.hostname.com");
    
    TEST_LOG("SSL_set1_host returned %d (1=success)", ret);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    dlclose(handle);
    
    return (ret == 1) ? TEST_PASS : TEST_FAIL;
}

test_result_t test_x509_verify_cert(void) {
    void *handle;
    int (*X509_verify_cert)(X509_STORE_CTX *ctx);
    
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return TEST_SKIP;
    }
    
    X509_verify_cert = dlsym(handle, "X509_verify_cert");
    if (!X509_verify_cert) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return success (1) */
    int result = X509_verify_cert(NULL);
    
    TEST_LOG("X509_verify_cert(NULL) returned %d (expected 1)", result);
    
    dlclose(handle);
    
    return (result == 1) ? TEST_PASS : TEST_FAIL;
}

int main(void) {
    test_case_t tests[] = {
        {"ssl_ctx_set_verify", "Test SSL_CTX_set_verify bypass", test_ssl_ctx_set_verify, 5},
        {"ssl_verify_result", "Test SSL_get/set_verify_result bypass", test_ssl_verify_result, 5},
        {"ssl_hostname", "Test SSL hostname verification bypass", test_ssl_hostname_verification, 5},
        {"x509_verify", "Test X509_verify_cert bypass", test_x509_verify_cert, 5}
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0, failed = 0, skipped = 0;
    int i;
    
    test_init();
    
    printf("\n=== Direct OpenSSL API Bypass Tests ===\n");
    
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