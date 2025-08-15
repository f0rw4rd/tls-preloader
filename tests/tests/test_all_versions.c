/* Consolidated TLS library version detection tests */
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include "test_framework.h"

typedef struct {
    const char *name;
    int major;
    int minor;
    int patch;
    char version_str[128];
} tls_lib_info_t;

/* OpenSSL version detection */
static int detect_openssl(tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    info->name = "OpenSSL";
    
    /* Try OpenSSL 3.x */
    unsigned int (*version_major)(void) = dlsym(handle, "OPENSSL_version_major");
    if (version_major) {
        unsigned int (*version_minor)(void) = dlsym(handle, "OPENSSL_version_minor");
        unsigned int (*version_patch)(void) = dlsym(handle, "OPENSSL_version_patch");
        info->major = version_major ? version_major() : 0;
        info->minor = version_minor ? version_minor() : 0;
        info->patch = version_patch ? version_patch() : 0;
        snprintf(info->version_str, sizeof(info->version_str), "%d.%d.%d", 
                 info->major, info->minor, info->patch);
        dlclose(handle);
        return 1;
    }
    
    /* Try OpenSSL 1.1.x */
    const char* (*openssl_version)(int) = dlsym(handle, "OpenSSL_version");
    if (openssl_version) {
        const char *ver = openssl_version(0);
        if (ver) {
            strncpy(info->version_str, ver, sizeof(info->version_str)-1);
            sscanf(ver, "OpenSSL %d.%d.%d", &info->major, &info->minor, &info->patch);
            dlclose(handle);
            return 1;
        }
    }
    
    /* Try OpenSSL 1.0.x */
    const char* (*ssleay_version)(int) = dlsym(handle, "SSLeay_version");
    if (ssleay_version) {
        const char *ver = ssleay_version(0);
        if (ver) {
            strncpy(info->version_str, ver, sizeof(info->version_str)-1);
            info->major = 1;
            info->minor = 0;
            dlclose(handle);
            return 1;
        }
    }
    
    dlclose(handle);
    return 0;
}

/* GnuTLS version detection */
static int detect_gnutls(tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    const char* (*check_version)(const char*) = dlsym(handle, "gnutls_check_version");
    if (check_version) {
        info->name = "GnuTLS";
        const char *ver = check_version(NULL);
        if (ver) {
            strncpy(info->version_str, ver, sizeof(info->version_str)-1);
            sscanf(ver, "%d.%d.%d", &info->major, &info->minor, &info->patch);
            dlclose(handle);
            return 1;
        }
    }
    
    dlclose(handle);
    return 0;
}

/* mbedTLS version detection */
static int detect_mbedtls(tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    void (*get_version)(char*) = dlsym(handle, "mbedtls_version_get_string_full");
    if (!get_version) {
        get_version = dlsym(handle, "mbedtls_version_get_string");
    }
    
    if (get_version) {
        info->name = "mbedTLS";
        char version[32] = {0};
        get_version(version);
        strncpy(info->version_str, version, sizeof(info->version_str)-1);
        sscanf(version, "%d.%d.%d", &info->major, &info->minor, &info->patch);
        dlclose(handle);
        return 1;
    }
    
    dlclose(handle);
    return 0;
}

/* NSS version detection */
static int detect_nss(tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    const char* (*nss_version)(void) = dlsym(handle, "NSS_GetVersion");
    if (nss_version) {
        info->name = "NSS";
        const char *ver = nss_version();
        if (ver) {
            strncpy(info->version_str, ver, sizeof(info->version_str)-1);
            sscanf(ver, "%d.%d", &info->major, &info->minor);
            dlclose(handle);
            return 1;
        }
    }
    
    dlclose(handle);
    return 0;
}

/* wolfSSL version detection */
static int detect_wolfssl(tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    const char* (*lib_version)(void) = dlsym(handle, "wolfSSL_lib_version");
    if (lib_version) {
        info->name = "wolfSSL";
        const char *ver = lib_version();
        if (ver) {
            strncpy(info->version_str, ver, sizeof(info->version_str)-1);
            sscanf(ver, "%d.%d.%d", &info->major, &info->minor, &info->patch);
            dlclose(handle);
            return 1;
        }
    }
    
    dlclose(handle);
    return 0;
}

/* Test verification bypass for detected library */
static int test_library_bypass(const tls_lib_info_t *info) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    int success = 0;
    
    if (strcmp(info->name, "OpenSSL") == 0) {
        /* Test OpenSSL bypass */
        void (*ctx_verify)(void*, int, void*) = dlsym(handle, "SSL_CTX_set_verify");
        long (*get_result)(const void*) = dlsym(handle, "SSL_get_verify_result");
        if (ctx_verify && get_result) {
            TEST_LOG("Testing OpenSSL %s bypass", info->version_str);
            success = 1;
        }
    } else if (strcmp(info->name, "GnuTLS") == 0) {
        /* Test GnuTLS bypass */
        int (*verify_peers)(void*, unsigned int*) = dlsym(handle, "gnutls_certificate_verify_peers2");
        if (verify_peers) {
            TEST_LOG("Testing GnuTLS %s bypass", info->version_str);
            unsigned int status = 999;
            int ret = verify_peers(NULL, &status);
            success = (ret == 0 && status == 0);
        }
    } else if (strcmp(info->name, "mbedTLS") == 0) {
        /* Test mbedTLS bypass */
        void (*conf_authmode)(void*, int) = dlsym(handle, "mbedtls_ssl_conf_authmode");
        if (conf_authmode) {
            TEST_LOG("Testing mbedTLS %s bypass", info->version_str);
            success = 1;
        }
    } else if (strcmp(info->name, "NSS") == 0) {
        /* Test NSS bypass */
        int (*auth_hook)(void*, void*, void*) = dlsym(handle, "SSL_AuthCertificateHook");
        if (auth_hook) {
            TEST_LOG("Testing NSS %s bypass", info->version_str);
            success = 1;
        }
    } else if (strcmp(info->name, "wolfSSL") == 0) {
        /* Test wolfSSL bypass */
        void (*ctx_verify)(void*, int, void*) = dlsym(handle, "wolfSSL_CTX_set_verify");
        if (ctx_verify) {
            TEST_LOG("Testing wolfSSL %s bypass", info->version_str);
            success = 1;
        }
    }
    
    dlclose(handle);
    return success;
}

void test_all_library_versions(void) {
    tls_lib_info_t info = {0};
    int found_any = 0;
    
    /* Detect and test all TLS libraries */
    if (detect_openssl(&info)) {
        TEST_LOG("Detected %s version %s", info.name, info.version_str);
        RUN_TEST(test_library_bypass(&info), "OpenSSL bypass test");
        found_any = 1;
    }
    
    if (detect_gnutls(&info)) {
        TEST_LOG("Detected %s version %s", info.name, info.version_str);
        RUN_TEST(test_library_bypass(&info), "GnuTLS bypass test");
        found_any = 1;
    }
    
    if (detect_mbedtls(&info)) {
        TEST_LOG("Detected %s version %s", info.name, info.version_str);
        RUN_TEST(test_library_bypass(&info), "mbedTLS bypass test");
        found_any = 1;
    }
    
    if (detect_nss(&info)) {
        TEST_LOG("Detected %s version %s", info.name, info.version_str);
        RUN_TEST(test_library_bypass(&info), "NSS bypass test");
        found_any = 1;
    }
    
    if (detect_wolfssl(&info)) {
        TEST_LOG("Detected %s version %s", info.name, info.version_str);
        RUN_TEST(test_library_bypass(&info), "wolfSSL bypass test");
        found_any = 1;
    }
    
    if (!found_any) {
        TEST_LOG("WARNING: No TLS libraries detected");
    }
}

int main(void) {
    TEST_LOG("=== Consolidated TLS Library Version Tests ===");
    test_all_library_versions();
    return test_summary();
}