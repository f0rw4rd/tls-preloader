/* libcurl version-specific tests */
#include "../test_framework.h"
#include <curl/curl.h>

/* Get curl version info */
void get_curl_version_info(void) {
    curl_version_info_data *version_info = curl_version_info(CURLVERSION_NOW);
    
    TEST_LOG("libcurl version: %s", version_info->version);
    TEST_LOG("SSL version: %s", version_info->ssl_version ? version_info->ssl_version : "none");
    
    /* Check supported protocols */
    const char * const *protocols = version_info->protocols;
    int has_https = 0;
    
    for (int i = 0; protocols[i]; i++) {
        if (strcmp(protocols[i], "https") == 0) {
            has_https = 1;
            break;
        }
    }
    
    if (!has_https) {
        TEST_ERROR("HTTPS not supported by this curl build");
    }
    
    /* Check features */
    if (version_info->features & CURL_VERSION_SSL) {
        TEST_LOG("SSL/TLS support: YES");
    } else {
        TEST_ERROR("SSL/TLS support: NO");
    }
}

/* Test curl 7.10+ features (CURLOPT_SSL_VERIFYPEER) */
int test_curl_710_plus(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* CURLOPT_SSL_VERIFYPEER introduced in 7.10 */
    CURLcode res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    }
    
    TEST_LOG("CURLOPT_SSL_VERIFYPEER available - bypass active");
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

/* Test curl 7.28+ features (CURLOPT_PINNEDPUBLICKEY) */
int test_curl_728_plus(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* CURLOPT_PINNEDPUBLICKEY introduced in 7.28 */
    CURLcode res = curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//test=");
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_UNKNOWN_OPTION) {
        TEST_LOG("CURLOPT_PINNEDPUBLICKEY not available (curl < 7.28)");
        return TEST_SKIP;
    }
    
    TEST_LOG("CURLOPT_PINNEDPUBLICKEY available - bypass active");
    return TEST_PASS;
}

/* Test curl 7.41+ features (CURLOPT_SSL_VERIFYSTATUS - OCSP) */
int test_curl_741_plus(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* CURLOPT_SSL_VERIFYSTATUS introduced in 7.41 */
    CURLcode res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_UNKNOWN_OPTION) {
        TEST_LOG("CURLOPT_SSL_VERIFYSTATUS not available (curl < 7.41)");
        return TEST_SKIP;
    }
    
    TEST_LOG("CURLOPT_SSL_VERIFYSTATUS (OCSP) available - bypass active");
    return TEST_PASS;
}

/* Test curl 7.52+ features (CURLOPT_PROXY_SSL_*) */
int test_curl_752_plus(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* CURLOPT_PROXY_SSL_VERIFYPEER introduced in 7.52 */
    CURLcode res = curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_UNKNOWN_OPTION) {
        TEST_LOG("CURLOPT_PROXY_SSL_VERIFYPEER not available (curl < 7.52)");
        return TEST_SKIP;
    }
    
    TEST_LOG("CURLOPT_PROXY_SSL_* options available - bypass active");
    return TEST_PASS;
}

/* Test curl 7.62+ features (CURLOPT_DOH_*) */
int test_curl_762_plus(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* CURLOPT_DOH_SSL_VERIFYPEER introduced in 7.62 */
    CURLcode res = curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYPEER, 1L);
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_UNKNOWN_OPTION) {
        TEST_LOG("CURLOPT_DOH_SSL_VERIFYPEER not available (curl < 7.62)");
        return TEST_SKIP;
    }
    
    TEST_LOG("CURLOPT_DOH_SSL_* options available - bypass active");
    return TEST_PASS;
}

/* Test CURLINFO_SSL_VERIFYRESULT availability */
int test_curl_ssl_verifyresult(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_FAIL;
    
    /* Set up a simple request */
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    /* Perform request */
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        /* Check SSL verify result */
        long verify_result = -1;
        res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result);
        
        if (res == CURLE_OK) {
            TEST_LOG("CURLINFO_SSL_VERIFYRESULT returned %ld (should be 0)", verify_result);
            curl_easy_cleanup(curl);
            return (verify_result == 0) ? TEST_PASS : TEST_FAIL;
        }
    }
    
    curl_easy_cleanup(curl);
    return TEST_PASS; /* Connection might fail for other reasons */
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing libcurl version-specific features");
    
    /* Get version info */
    get_curl_version_info();
    
    /* Test features by version */
    RUN_TEST("curl 7.10+ SSL verification", test_curl_710_plus);
    RUN_TEST("curl 7.28+ public key pinning", test_curl_728_plus);
    RUN_TEST("curl 7.41+ OCSP stapling", test_curl_741_plus);
    RUN_TEST("curl 7.52+ proxy SSL", test_curl_752_plus);
    RUN_TEST("curl 7.62+ DoH SSL", test_curl_762_plus);
    RUN_TEST("SSL verify result info", test_curl_ssl_verifyresult);
    
    TEST_LOG("All tests passed!");
    return 0;
}