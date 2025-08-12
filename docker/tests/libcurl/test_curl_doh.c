/* Test DNS-over-HTTPS (DoH) SSL verification */
#include "../test_framework.h"
#include <curl/curl.h>

/* Helper function for write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb; /* Just discard the data */
}

int test_doh_basic(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Regular HTTPS request */
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    
    /* Configure DNS-over-HTTPS */
    curl_easy_setopt(curl, CURLOPT_DOH_URL, "https://cloudflare-dns.com/dns-query");
    
    /* Try to enable DoH SSL verification (our library should bypass this) */
    curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYHOST, 2L);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    
    TEST_LOG("Testing DNS-over-HTTPS with SSL verification enabled");
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        TEST_LOG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return TEST_FAIL;
    } else {
        TEST_LOG("DoH request succeeded despite verification settings");
    }
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int test_doh_multiple_resolvers(void) {
    const char *doh_urls[] = {
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query"
    };
    int num_resolvers = sizeof(doh_urls) / sizeof(doh_urls[0]);
    int i;
    
    for (i = 0; i < num_resolvers; i++) {
        CURL *curl;
        CURLcode res;
        
        curl = curl_easy_init();
        if (!curl) {
            TEST_LOG("Failed to initialize curl for %s", doh_urls[i]);
            continue;
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
        curl_easy_setopt(curl, CURLOPT_DOH_URL, doh_urls[i]);
        curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        
        TEST_LOG("Testing DoH resolver: %s", doh_urls[i]);
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            TEST_LOG("Failed with %s: %s", doh_urls[i], curl_easy_strerror(res));
            /* Don't fail the overall test if a resolver is unreachable */
            if (res != CURLE_COULDNT_RESOLVE_HOST && res != CURLE_OPERATION_TIMEDOUT) {
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
    
    TEST_LOG("Testing DNS-over-HTTPS SSL verification");
    
    RUN_TEST("Test basic DoH verification bypass", test_doh_basic);
    RUN_TEST("Test multiple DoH resolvers", test_doh_multiple_resolvers);
    
    TEST_LOG("All tests passed!");
    return 0;
}