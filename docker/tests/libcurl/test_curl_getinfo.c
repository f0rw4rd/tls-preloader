/* Test curl_easy_getinfo SSL verification result */
#include "../test_framework.h"
#include <curl/curl.h>

/* Helper function for write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb; /* Just discard the data */
}

int test_ssl_verify_result(void) {
    CURL *curl;
    CURLcode res;
    long verify_result;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://expired.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    }
    
    res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result);
    if (res == CURLE_OK) {
        if (verify_result == 0) {
            TEST_LOG("SSL verification result: %ld (success)", verify_result);
        } else {
            TEST_LOG("SSL verification reported error: %ld", verify_result);
            curl_easy_cleanup(curl);
            return TEST_FAIL;
        }
    } else {
        TEST_LOG("Failed to get SSL verify result");
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    }
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int test_ssl_verify_result_multiple(void) {
    const char *test_urls[] = {
        "https://expired.badssl.com/",
        "https://wrong.host.badssl.com/",
        "https://self-signed.badssl.com/",
        "https://untrusted-root.badssl.com/"
    };
    int num_urls = sizeof(test_urls) / sizeof(test_urls[0]);
    int i;
    
    for (i = 0; i < num_urls; i++) {
        CURL *curl;
        CURLcode res;
        long verify_result;
        
        curl = curl_easy_init();
        if (!curl) {
            TEST_LOG("Failed to initialize curl for %s", test_urls[i]);
            continue;
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, test_urls[i]);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result);
            if (res == CURLE_OK && verify_result != 0) {
                TEST_LOG("%s: SSL verify result should be 0, got %ld", test_urls[i], verify_result);
                curl_easy_cleanup(curl);
                return TEST_FAIL;
            }
        }
        
        curl_easy_cleanup(curl);
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing curl_easy_getinfo SSL verification");
    
    RUN_TEST("Test CURLINFO_SSL_VERIFYRESULT", test_ssl_verify_result);
    RUN_TEST("Test multiple SSL verify results", test_ssl_verify_result_multiple);
    
    TEST_LOG("All tests passed!");
    return 0;
}