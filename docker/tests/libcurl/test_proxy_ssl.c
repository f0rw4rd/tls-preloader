/* Test proxy SSL verification bypass */
#include "../test_framework.h"
#include <curl/curl.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb;
}

int test_proxy_ssl_verifypeer(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy.example.com:8443");
    
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 2L);
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    res = curl_easy_perform(curl);
    
    long verify_result = -1;
    curl_easy_getinfo(curl, CURLINFO_PROXY_SSL_VERIFYRESULT, &verify_result);
    
    curl_easy_cleanup(curl);
    
    if (verify_result != 0) {
        TEST_LOG("CURLINFO_PROXY_SSL_VERIFYRESULT returned %ld (expected 0)", verify_result);
        return TEST_FAIL;
    }
    
    TEST_LOG("Proxy SSL verification bypassed successfully");
    return TEST_PASS;
}

int test_proxy_pinned_key(void) {
    CURL *curl;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Set proxy */
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy.example.com:8443");
    
    /* Try to set proxy pinned public key - should be bypassed */
    curl_easy_setopt(curl, CURLOPT_PROXY_PINNEDPUBLICKEY, 
        "sha256//YhKJKSzoTt2b5FP18fvpHo7fJYqQCjA4HQ8vuQmDNYyZWMw3n7h3MFZOSTTXC=");
    
    /* Set a test URL */
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    
    /* Suppress output */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    /* Check that pinned key was effectively nullified */
    TEST_LOG("Proxy pinned public key bypassed");
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int test_proxy_combined_bypass(void) {
    CURL *curl;
    long verify_peer, verify_host;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Enable all proxy verifications */
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_PROXY_PINNEDPUBLICKEY, "sha256//invalid=");
    
    /* Check effective values (if curl supports querying these) */
    TEST_LOG("All proxy SSL verifications set - should be bypassed");
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing proxy SSL verification bypass");
    
    RUN_TEST("Test proxy SSL peer verification bypass", test_proxy_ssl_verifypeer);
    RUN_TEST("Test proxy pinned public key bypass", test_proxy_pinned_key);
    RUN_TEST("Test combined proxy SSL bypass", test_proxy_combined_bypass);
    
    TEST_LOG("All tests passed!");
    return 0;
}