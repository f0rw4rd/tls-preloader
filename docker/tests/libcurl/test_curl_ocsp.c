/* Test OCSP stapling verification */
#include "../test_framework.h"
#include <curl/curl.h>

/* Helper function for write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb; /* Just discard the data */
}

int test_ocsp_basic(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Test URL */
    curl_easy_setopt(curl, CURLOPT_URL, "https://expired.badssl.com/");
    
    /* Try to enable OCSP stapling verification (our library should bypass this) */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    
    /* Also test with peer and host verification */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    TEST_LOG("Testing with OCSP stapling verification enabled");
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    } else {
        TEST_LOG("Request succeeded despite OCSP verification settings");
    }
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int test_ocsp_with_options(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Test URL with self-signed cert */
    curl_easy_setopt(curl, CURLOPT_URL, "https://self-signed.badssl.com/");
    
    /* Enable all verification options */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);  /* Enable OCSP */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);    /* Enable peer verification */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);    /* Enable hostname verification */
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    TEST_LOG("Testing OCSP with self-signed cert");
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    } else {
        TEST_LOG("Request succeeded despite all verification options");
    }
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing OCSP stapling verification");
    
    RUN_TEST("Test basic OCSP verification bypass", test_ocsp_basic);
    RUN_TEST("Test OCSP with multiple options", test_ocsp_with_options);
    
    TEST_LOG("All tests passed!");
    return 0;
}