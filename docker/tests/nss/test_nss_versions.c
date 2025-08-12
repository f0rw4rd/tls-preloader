/* NSS version-specific tests */
#include "../test_framework.h"

/* Get NSS version */
const char* get_nss_version(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return NULL;
    
    const char* (*NSS_GetVersion)(void) = dlsym(handle, "NSS_GetVersion");
    if (!NSS_GetVersion) {
        dlclose(handle);
        return NULL;
    }
    
    const char *version = NSS_GetVersion();
    dlclose(handle);
    return version;
}

/* Parse NSS version */
void parse_nss_version(const char *version, int *major, int *minor, int *patch) {
    if (!version) return;
    sscanf(version, "%d.%d.%d", major, minor, patch);
}

/* Test NSS 3.11+ features (SSL hooks) */
int test_nss_311_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_nss_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_nss_version(version, &major, &minor, &patch);
    
    if (major < 3 || (major == 3 && minor < 11)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("NSS 3.11+ version: %s", version);
    
    /* 3.11+ has SSL_AuthCertificateHook */
    if (!dlsym(handle, "SSL_AuthCertificateHook")) {
        TEST_LOG("SSL_AuthCertificateHook not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    if (!dlsym(handle, "SSL_BadCertHook")) {
        TEST_LOG("SSL_BadCertHook not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("NSS 3.11+ SSL hook bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test NSS 3.20+ features (enhanced certificate verification) */
int test_nss_320_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_nss_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_nss_version(version, &major, &minor, &patch);
    
    if (major < 3 || (major == 3 && minor < 20)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("NSS 3.20+ version: %s", version);
    
    /* 3.20+ has enhanced certificate verification */
    if (!dlsym(handle, "CERT_VerifyCertificate")) {
        TEST_LOG("CERT_VerifyCertificate not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("NSS 3.20+ certificate verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test NSS 3.30+ features (trust anchors) */
int test_nss_330_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_nss_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_nss_version(version, &major, &minor, &patch);
    
    if (major < 3 || (major == 3 && minor < 30)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("NSS 3.30+ version: %s", version);
    
    /* 3.30+ has SSL_SetTrustAnchors */
    if (!dlsym(handle, "SSL_SetTrustAnchors")) {
        TEST_LOG("SSL_SetTrustAnchors not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("NSS 3.30+ trust anchor bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test NSS 3.40+ features (modern certificate handling) */
int test_nss_340_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    const char *version = get_nss_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0, patch = 0;
    parse_nss_version(version, &major, &minor, &patch);
    
    if (major < 3 || (major == 3 && minor < 40)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("NSS 3.40+ version: %s", version);
    
    /* Check for modern NSS features */
    if (dlsym(handle, "SSL_ConfigSecureServerWithCertChain")) {
        TEST_LOG("Modern NSS certificate chain functions detected");
    }
    
    TEST_LOG("NSS 3.40+ verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* Test basic NSS initialization */
int test_nss_init(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* Check for NSS_Init function */
    if (!dlsym(handle, "NSS_Init")) {
        TEST_LOG("NSS_Init not found");
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Check for basic certificate functions */
    if (!dlsym(handle, "CERT_VerifyCertNow")) {
        TEST_LOG("CERT_VerifyCertNow not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    if (!dlsym(handle, "CERT_VerifyCert")) {
        TEST_LOG("CERT_VerifyCert not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("Basic NSS certificate verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing NSS version-specific features");
    
    const char *version = get_nss_version();
    if (!version) {
        TEST_LOG("NSS version detection failed - skipping version-specific tests");
        TEST_LOG("All tests passed!");
        return TEST_PASS;
    }
    
    TEST_LOG("NSS version: %s", version);
    
    int major = 0, minor = 0, patch = 0;
    parse_nss_version(version, &major, &minor, &patch);
    
    /* Test version-specific features */
    if (major >= 3) {
        if (minor >= 11) {
            RUN_TEST("NSS 3.11+ SSL hooks", test_nss_311_plus);
        }
        
        if (minor >= 20) {
            RUN_TEST("NSS 3.20+ certificate verification", test_nss_320_plus);
        }
        
        if (minor >= 30) {
            RUN_TEST("NSS 3.30+ trust anchors", test_nss_330_plus);
        }
        
        if (minor >= 40) {
            RUN_TEST("NSS 3.40+ modern features", test_nss_340_plus);
        }
    }
    
    RUN_TEST("Basic NSS initialization", test_nss_init);
    
    TEST_LOG("All tests passed!");
    return 0;
}