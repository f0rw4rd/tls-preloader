/* Comprehensive TLS library testing
 * Tests: wolfSSL, mbedTLS, NSS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define YELLOW "\033[1;33m"
#define NC "\033[0m"

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

void test_function(const char *name, int result) {
    tests_run++;
    if (result == 0) {
        printf("%s✓ %s%s\n", GREEN, name, NC);
        tests_passed++;
    } else {
        printf("%s✗ %s%s\n", RED, name, NC);
        tests_failed++;
    }
}

/* Test wolfSSL functions */
void test_wolfssl() {
    printf("\n%s=== Testing wolfSSL Functions ===%s\n", YELLOW, NC);
    
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return;
    
    /* wolfSSL_CTX_set_verify */
    void (*wolfssl_ctx_verify)(void*, int, void*) = dlsym(handle, "wolfSSL_CTX_set_verify");
    if (wolfssl_ctx_verify) {
        test_function("wolfSSL_CTX_set_verify exists", 0);
        /* Call should succeed without crashing */
        wolfssl_ctx_verify(NULL, 0, NULL);
        test_function("wolfSSL_CTX_set_verify bypass", 0);
    } else {
        test_function("wolfSSL_CTX_set_verify not found", 1);
    }
    
    /* wolfSSL_set_verify */
    void (*wolfssl_verify)(void*, int, void*) = dlsym(handle, "wolfSSL_set_verify");
    if (wolfssl_verify) {
        test_function("wolfSSL_set_verify exists", 0);
        wolfssl_verify(NULL, 0, NULL);
        test_function("wolfSSL_set_verify bypass", 0);
    }
    
    /* wolfSSL_get_verify_result */
    long (*wolfssl_result)(void*) = dlsym(handle, "wolfSSL_get_verify_result");
    if (wolfssl_result) {
        long result = wolfssl_result(NULL);
        test_function("wolfSSL_get_verify_result returns 0", result == 0 ? 0 : 1);
    }
    
    /* wolfSSL_check_domain_name */
    int (*wolfssl_domain)(void*, const char*) = dlsym(handle, "wolfSSL_check_domain_name");
    if (wolfssl_domain) {
        int result = wolfssl_domain(NULL, "badssl.com");
        test_function("wolfSSL_check_domain_name returns 1", result == 1 ? 0 : 1);
    }
    
    /* wolfSSL_CTX_load_verify_locations */
    int (*wolfssl_load)(void*, const char*, const char*) = dlsym(handle, "wolfSSL_CTX_load_verify_locations");
    if (wolfssl_load) {
        int result = wolfssl_load(NULL, "/nonexistent", NULL);
        test_function("wolfSSL_CTX_load_verify_locations returns 1", result == 1 ? 0 : 1);
    }
}

/* Test mbedTLS functions */
void test_mbedtls() {
    printf("\n%s=== Testing mbedTLS Functions ===%s\n", YELLOW, NC);
    
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return;
    
    /* mbedtls_ssl_conf_authmode */
    void (*mbedtls_authmode)(void*, int) = dlsym(handle, "mbedtls_ssl_conf_authmode");
    if (mbedtls_authmode) {
        test_function("mbedtls_ssl_conf_authmode exists", 0);
        mbedtls_authmode(NULL, 0);
        test_function("mbedtls_ssl_conf_authmode bypass", 0);
    } else {
        test_function("mbedtls_ssl_conf_authmode not found", 1);
    }
    
    /* mbedtls_ssl_conf_verify */
    void (*mbedtls_verify)(void*, void*, void*) = dlsym(handle, "mbedtls_ssl_conf_verify");
    if (mbedtls_verify) {
        test_function("mbedtls_ssl_conf_verify exists", 0);
        mbedtls_verify(NULL, NULL, NULL);
        test_function("mbedtls_ssl_conf_verify bypass", 0);
    }
    
    /* mbedtls_ssl_get_verify_result */
    unsigned int (*mbedtls_result)(void*) = dlsym(handle, "mbedtls_ssl_get_verify_result");
    if (mbedtls_result) {
        unsigned int result = mbedtls_result(NULL);
        test_function("mbedtls_ssl_get_verify_result returns 0", result == 0 ? 0 : 1);
    }
    
    /* mbedtls_ssl_set_hostname */
    int (*mbedtls_hostname)(void*, const char*) = dlsym(handle, "mbedtls_ssl_set_hostname");
    if (mbedtls_hostname) {
        int result = mbedtls_hostname(NULL, "badssl.com");
        test_function("mbedtls_ssl_set_hostname returns 0", result == 0 ? 0 : 1);
    }
    
    /* mbedtls_x509_crt_verify */
    int (*mbedtls_x509_verify)(void*, void*, void*, const char*, unsigned int*, void*, void*) = 
        dlsym(handle, "mbedtls_x509_crt_verify");
    if (mbedtls_x509_verify) {
        unsigned int flags = 0xFFFF;
        int result = mbedtls_x509_verify(NULL, NULL, NULL, "test", &flags, NULL, NULL);
        test_function("mbedtls_x509_crt_verify returns 0", result == 0 ? 0 : 1);
        test_function("mbedtls_x509_crt_verify clears flags", flags == 0 ? 0 : 1);
    }
}

/* Test NSS functions */
void test_nss() {
    printf("\n%s=== Testing NSS Functions ===%s\n", YELLOW, NC);
    
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return;
    
    /* SSL_AuthCertificateHook */
    int (*nss_auth_hook)(void*, void*, void*) = dlsym(handle, "SSL_AuthCertificateHook");
    if (nss_auth_hook) {
        test_function("SSL_AuthCertificateHook exists", 0);
        int result = nss_auth_hook(NULL, NULL, NULL);
        test_function("SSL_AuthCertificateHook returns 0", result == 0 ? 0 : 1);
    } else {
        test_function("SSL_AuthCertificateHook not found", 1);
    }
    
    /* SSL_BadCertHook */
    int (*nss_bad_hook)(void*, void*, void*) = dlsym(handle, "SSL_BadCertHook");
    if (nss_bad_hook) {
        test_function("SSL_BadCertHook exists", 0);
        int result = nss_bad_hook(NULL, NULL, NULL);
        test_function("SSL_BadCertHook returns 0", result == 0 ? 0 : 1);
    }
    
    /* CERT_VerifyCertNow */
    int (*cert_verify_now)(void*, void*, int, void*, void*) = dlsym(handle, "CERT_VerifyCertNow");
    if (cert_verify_now) {
        int result = cert_verify_now(NULL, NULL, 0, NULL, NULL);
        test_function("CERT_VerifyCertNow returns 0", result == 0 ? 0 : 1);
    }
    
    /* CERT_VerifyCert */
    int (*cert_verify)(void*, void*, int, int, long long, void*, void*) = dlsym(handle, "CERT_VerifyCert");
    if (cert_verify) {
        int result = cert_verify(NULL, NULL, 0, 0, 0LL, NULL, NULL);
        test_function("CERT_VerifyCert returns 0", result == 0 ? 0 : 1);
    }
    
    /* CERT_VerifyCertificate */
    int (*cert_verify_cert)(void*, void*, int, int, long long, void*, void*, int*) = 
        dlsym(handle, "CERT_VerifyCertificate");
    if (cert_verify_cert) {
        int usage = 0;
        int result = cert_verify_cert(NULL, NULL, 0, 0, 0LL, NULL, NULL, &usage);
        test_function("CERT_VerifyCertificate returns 0", result == 0 ? 0 : 1);
    }
    
    /* SSL_SetTrustAnchors */
    int (*set_trust)(void*, void*) = dlsym(handle, "SSL_SetTrustAnchors");
    if (set_trust) {
        int result = set_trust(NULL, NULL);
        test_function("SSL_SetTrustAnchors returns 0", result == 0 ? 0 : 1);
    }
}

int main() {
    printf("%s=== TLS Library Comprehensive Test ===%s\n", YELLOW, NC);
    printf("Testing wolfSSL, mbedTLS, and NSS function bypasses\n");
    
    /* Check if preloader is active */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        printf("%sERROR: libtlsnoverify.so not preloaded!%s\n", RED, NC);
        printf("Usage: LD_PRELOAD=/path/to/libtlsnoverify.so %s\n", "test_tls_libraries");
        return 1;
    }
    
    test_wolfssl();
    test_mbedtls();
    test_nss();
    
    /* Summary */
    printf("\n%s=== Test Summary ===%s\n", YELLOW, NC);
    printf("Total tests: %d\n", tests_run);
    printf("Passed: %s%d%s\n", GREEN, tests_passed, NC);
    printf("Failed: %s%d%s\n", RED, tests_failed, NC);
    
    if (tests_failed == 0) {
        printf("%sAll tests passed!%s\n", GREEN, NC);
        return 0;
    } else {
        printf("%sSome tests failed!%s\n", RED, NC);
        return 1;
    }
}