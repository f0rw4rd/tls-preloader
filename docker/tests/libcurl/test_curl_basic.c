/* Basic libcurl SSL verification bypass tests */
#include "../test_framework.h"
#include <curl/curl.h>

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb; /* Discard data */
}

int test_ssl_verifypeer_bypass(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to init curl");
        return TEST_FAIL;
    }
    
    /* Try to enable SSL verification - should be bypassed */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    /* Test against self-signed cert */
    curl_easy_setopt(curl, CURLOPT_URL, "https://self-signed.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform failed: %s", curl_easy_strerror(res));
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_ssl_verifyhost_bypass(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to init curl");
        return TEST_FAIL;
    }
    
    /* Test hostname mismatch */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_URL, "https://wrong.host.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform failed: %s", curl_easy_strerror(res));
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int test_expired_cert_bypass(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to init curl");
        return TEST_FAIL;
    }
    
    /* Test expired certificate */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, "https://expired.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform failed: %s", curl_easy_strerror(res));
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing libcurl SSL verification bypass");
    
    RUN_TEST("SSL peer verification bypass", test_ssl_verifypeer_bypass);
    RUN_TEST("SSL host verification bypass", test_ssl_verifyhost_bypass);
    RUN_TEST("Expired certificate bypass", test_expired_cert_bypass);
    
    TEST_LOG("All tests passed!");
    return 0;
}