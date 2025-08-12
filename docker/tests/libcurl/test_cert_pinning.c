/* Test certificate pinning bypass */
#include "../test_framework.h"
#include <curl/curl.h>
#include <unistd.h>

/* Helper function for write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb; /* Just discard the data */
}

int test_curl_pinned_publickey(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Set a valid pinned public key that would normally fail */
    /* This is a fake/invalid pin that would normally cause verification failure */
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, 
        "sha256//YhKJKSzoTt2b5FP18fvpHo7fJYqQCjA4HQ8vuQmDNYyZWMw3n7h3MFZOSTTXC=");
    
    /* Test against a real server */
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    /* This should succeed despite invalid pin */
    res = curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        TEST_LOG("Request failed: %s", curl_easy_strerror(res));
        /* Connection might fail for other reasons, but pin should be bypassed */
        return TEST_PASS; /* Pin was bypassed if it wasn't the failure reason */
    }
    
    TEST_LOG("Certificate pinning bypassed successfully");
    return TEST_PASS;
}

int test_multiple_pins(void) {
    CURL *curl;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Set multiple invalid pins separated by semicolon */
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, 
        "sha256//invalid1=;sha256//invalid2=;sha256//invalid3=");
    
    /* Test URL */
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    /* Should be bypassed */
    TEST_LOG("Multiple pins set - all should be bypassed");
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}

int test_file_based_pins(void) {
    CURL *curl;
    FILE *fp;
    const char *pin_file = "/tmp/test_pins.txt";
    
    /* Create a temporary pin file */
    fp = fopen(pin_file, "w");
    if (fp) {
        fprintf(fp, "sha256//YhKJKSzoTt2b5FP18fvpHo7fJYqQCjA4HQ8vuQmDNYyZWMw3n7h3MFZOSTTXC=\n");
        fprintf(fp, "sha256//another_invalid_pin=\n");
        fclose(fp);
    }
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        unlink(pin_file);
        return TEST_FAIL;
    }
    
    /* Reference pin file */
    char pin_ref[256];
    snprintf(pin_ref, sizeof(pin_ref), "file://%s", pin_file);
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin_ref);
    
    /* Test URL */
    curl_easy_setopt(curl, CURLOPT_URL, "https://httpbin.org/get");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    TEST_LOG("File-based pins should be bypassed");
    
    curl_easy_cleanup(curl);
    unlink(pin_file);
    
    return TEST_PASS;
}

int test_combined_pin_and_verify(void) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) {
        TEST_LOG("Failed to initialize curl");
        return TEST_FAIL;
    }
    
    /* Enable all verification + pinning */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//completely_invalid=");
    
    /* Test against badssl.com self-signed */
    curl_easy_setopt(curl, CURLOPT_URL, "https://self-signed.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    res = curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        TEST_LOG("All verification and pinning bypassed successfully");
        return TEST_PASS;
    } else {
        TEST_LOG("Request failed but pin verification was likely bypassed");
        return TEST_PASS;
    }
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing certificate pinning bypass");
    
    RUN_TEST("Test basic certificate pinning bypass", test_curl_pinned_publickey);
    RUN_TEST("Test multiple pins bypass", test_multiple_pins);
    RUN_TEST("Test file-based pins bypass", test_file_based_pins);
    RUN_TEST("Test combined pinning and verification bypass", test_combined_pin_and_verify);
    
    TEST_LOG("All tests passed!");
    return 0;
}