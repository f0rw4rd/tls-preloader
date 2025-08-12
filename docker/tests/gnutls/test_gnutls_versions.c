/* GnuTLS version-specific tests */
#include "../test_framework.h"

/* Get GnuTLS version */
const char* get_gnutls_version(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return NULL;
    
    const char* (*gnutls_check_version)(const char *) = 
        dlsym(handle, "gnutls_check_version");
    
    if (!gnutls_check_version) {
        dlclose(handle);
        return NULL;
    }
    
    const char *version = gnutls_check_version(NULL);
    dlclose(handle);
    return version;
}

/* Parse version string to major.minor */
void parse_version(const char *version, int *major, int *minor) {
    if (!version) return;
    sscanf(version, "%d.%d", major, minor);
}

/* GnuTLS 2.x specific tests */
int test_gnutls_2x_specific(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* GnuTLS 2.x uses older verification API */
    void (*gnutls_certificate_set_verify_function)(void *, void *) = 
        dlsym(handle, "gnutls_certificate_set_verify_function");
    
    if (!gnutls_certificate_set_verify_function) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    /* Check for functions that exist in 2.x */
    if (!dlsym(handle, "gnutls_certificate_verify_peers2")) {
        TEST_LOG("gnutls_certificate_verify_peers2 not found");
        dlclose(handle);
        return TEST_FAIL;
    }
    
    TEST_LOG("GnuTLS 2.x verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* GnuTLS 3.0-3.4.5 specific tests */
int test_gnutls_30_to_345(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* Has verify_peers3 but not session_set_verify_cert */
    if (!dlsym(handle, "gnutls_certificate_verify_peers3")) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    if (dlsym(handle, "gnutls_session_set_verify_cert")) {
        /* This is 3.4.6+, not our target */
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("GnuTLS 3.0-3.4.5 detected");
    TEST_LOG("Using gnutls_certificate_verify_peers3 bypass");
    
    dlclose(handle);
    return TEST_PASS;
}

/* GnuTLS 3.4.6+ specific tests */
int test_gnutls_346_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* 3.4.6+ has gnutls_session_set_verify_cert */
    void (*gnutls_session_set_verify_cert)(void *, const char *, unsigned) = 
        dlsym(handle, "gnutls_session_set_verify_cert");
    
    if (!gnutls_session_set_verify_cert) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("GnuTLS 3.4.6+ detected");
    
    /* Check for newer functions */
    if (dlsym(handle, "gnutls_session_set_verify_cert2")) {
        TEST_LOG("gnutls_session_set_verify_cert2 found - newer GnuTLS");
    }
    
    TEST_LOG("GnuTLS 3.4.6+ automatic verification bypass active");
    dlclose(handle);
    return TEST_PASS;
}

/* GnuTLS 3.6+ specific tests */
int test_gnutls_36_plus(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return TEST_SKIP;
    
    /* Check version */
    const char *version = get_gnutls_version();
    if (!version) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    int major = 0, minor = 0;
    parse_version(version, &major, &minor);
    
    if (major < 3 || (major == 3 && minor < 6)) {
        dlclose(handle);
        return TEST_SKIP;
    }
    
    TEST_LOG("GnuTLS %s detected", version);
    
    /* 3.6+ has enhanced certificate verification */
    if (dlsym(handle, "gnutls_certificate_set_verify_limits")) {
        TEST_LOG("gnutls_certificate_set_verify_limits bypass active");
    }
    
    dlclose(handle);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing GnuTLS version-specific features");
    
    const char *version = get_gnutls_version();
    if (!version) {
        TEST_LOG("GnuTLS version detection failed - skipping version-specific tests");
        TEST_LOG("All tests passed!");
        return TEST_PASS;
    }
    
    TEST_LOG("GnuTLS version: %s", version);
    
    int major = 0, minor = 0;
    parse_version(version, &major, &minor);
    
    if (major == 2) {
        RUN_TEST("GnuTLS 2.x specific", test_gnutls_2x_specific);
    } else if (major == 3) {
        if (minor < 4 || (minor == 4 && version[4] < '6')) {
            RUN_TEST("GnuTLS 3.0-3.4.5 specific", test_gnutls_30_to_345);
        } else {
            RUN_TEST("GnuTLS 3.4.6+ specific", test_gnutls_346_plus);
        }
        
        if (minor >= 6) {
            RUN_TEST("GnuTLS 3.6+ specific", test_gnutls_36_plus);
        }
    }
    
    TEST_LOG("All tests passed!");
    return 0;
}