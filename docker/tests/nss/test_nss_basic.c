/* Basic NSS verification bypass tests */
#include "../test_framework.h"

/* NSS types and constants */
typedef int SECStatus;
#define SECSuccess 0
#define SECFailure -1

/* Function pointers */
typedef SECStatus (*SSL_AuthCertificateHook_t)(void*, SECStatus (*)(void*, void*, int, int), void*);
typedef SECStatus (*SSL_BadCertHook_t)(void*, SECStatus (*)(void*, void*), void*);
typedef SECStatus (*CERT_VerifyCertNow_t)(void*, void*, int, void*, void*);
typedef SECStatus (*CERT_VerifyCert_t)(void*, void*, int, int, long long, void*, void*);
typedef SECStatus (*SSL_SetTrustAnchors_t)(void*, void*);

int test_ssl_auth_certificate_hook(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    SSL_AuthCertificateHook_t SSL_AuthCertificateHook = 
        dlsym(handle, "SSL_AuthCertificateHook");
    
    if (!SSL_AuthCertificateHook) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    SECStatus ret = SSL_AuthCertificateHook(NULL, NULL, NULL);
    
    TEST_LOG("SSL_AuthCertificateHook returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_ssl_bad_cert_hook(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    SSL_BadCertHook_t SSL_BadCertHook = dlsym(handle, "SSL_BadCertHook");
    
    if (!SSL_BadCertHook) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    SECStatus ret = SSL_BadCertHook(NULL, NULL, NULL);
    
    TEST_LOG("SSL_BadCertHook returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_cert_verify_cert_now(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    CERT_VerifyCertNow_t CERT_VerifyCertNow = dlsym(handle, "CERT_VerifyCertNow");
    
    if (!CERT_VerifyCertNow) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    SECStatus ret = CERT_VerifyCertNow(NULL, NULL, 1, NULL, NULL);
    
    TEST_LOG("CERT_VerifyCertNow returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_cert_verify_cert(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    CERT_VerifyCert_t CERT_VerifyCert = dlsym(handle, "CERT_VerifyCert");
    
    if (!CERT_VerifyCert) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    SECStatus ret = CERT_VerifyCert(NULL, NULL, 1, 0, 0, NULL, NULL);
    
    TEST_LOG("CERT_VerifyCert returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_cert_verify_certificate(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    SECStatus (*CERT_VerifyCertificate)(void*, void*, int, int, long long, void*, void*, int*) = 
        dlsym(handle, "CERT_VerifyCertificate");
    
    if (!CERT_VerifyCertificate) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    int usages = 0;
    SECStatus ret = CERT_VerifyCertificate(NULL, NULL, 1, 0, 0, NULL, NULL, &usages);
    
    TEST_LOG("CERT_VerifyCertificate returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_ssl_set_trust_anchors(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    SSL_SetTrustAnchors_t SSL_SetTrustAnchors = dlsym(handle, "SSL_SetTrustAnchors");
    
    if (!SSL_SetTrustAnchors) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Call with NULL - should return SECSuccess */
    SECStatus ret = SSL_SetTrustAnchors(NULL, NULL);
    
    TEST_LOG("SSL_SetTrustAnchors returned %d (expected 0)", ret);
    
    dlclose(handle);
    
    if (ret != SECSuccess) {
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing NSS direct API bypass");
    
    RUN_TEST("SSL_AuthCertificateHook bypass", test_ssl_auth_certificate_hook);
    RUN_TEST("SSL_BadCertHook bypass", test_ssl_bad_cert_hook);
    RUN_TEST("CERT_VerifyCertNow bypass", test_cert_verify_cert_now);
    RUN_TEST("CERT_VerifyCert bypass", test_cert_verify_cert);
    RUN_TEST("CERT_VerifyCertificate bypass", test_cert_verify_certificate);
    RUN_TEST("SSL_SetTrustAnchors bypass", test_ssl_set_trust_anchors);
    
    TEST_LOG("All tests passed!");
    return 0;
}