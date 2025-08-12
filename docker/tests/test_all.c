/* Consolidated test runner for all TLS bypass tests */
#include "test_runner.h"
#include "test_library_common.h"

/* libcurl specific tests */
#ifdef HAS_CURL
#include <curl/curl.h>

static int test_curl_ssl_verify(void) {
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_SKIP;
    
    /* Test SSL peer verification bypass */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_URL, "https://self-signed.badssl.com/");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        TEST_LOG("SSL verification bypassed successfully");
        return TEST_PASS;
    }
    
    TEST_ERROR("curl error: %s", curl_easy_strerror(res));
    return TEST_FAIL;
}

static int test_curl_features(void) {
    curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);
    TEST_LOG("libcurl version: %s", info->version);
    TEST_LOG("SSL version: %s", info->ssl_version ? info->ssl_version : "none");
    
    /* Test various curl options exist */
    CURL *curl = curl_easy_init();
    if (!curl) return TEST_SKIP;
    
    /* Test pinning options */
    #ifdef CURLOPT_PINNEDPUBLICKEY
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//test");
    TEST_LOG("Certificate pinning support: YES");
    #endif
    
    /* Test OCSP options */
    #ifdef CURLOPT_SSL_VERIFYSTATUS
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    TEST_LOG("OCSP stapling support: YES");
    #endif
    
    /* Test DoH options */
    #ifdef CURLOPT_DOH_URL
    curl_easy_setopt(curl, CURLOPT_DOH_URL, "https://1.1.1.1/dns-query");
    TEST_LOG("DNS-over-HTTPS support: YES");
    #endif
    
    curl_easy_cleanup(curl);
    return TEST_PASS;
}
#endif

/* Run all library bypass tests */
static int test_all_libraries(void) {
    int failed = 0;
    
    /* Test each library */
    if (test_openssl_bypass() != TEST_PASS) failed++;
    if (test_gnutls_bypass() != TEST_PASS) failed++;
    if (test_mbedtls_bypass() != TEST_PASS) failed++;
    if (test_wolfssl_bypass() != TEST_PASS) failed++;
    if (test_nss_bypass() != TEST_PASS) failed++;
    
    return failed > 0 ? TEST_FAIL : TEST_PASS;
}

/* Run command-line tool tests */
static int test_command_tools(void) {
    cmd_result_t result;
    int failed = 0;
    
    const char *test_sites[] = {
        "self-signed.badssl.com",
        "expired.badssl.com",
        "untrusted-root.badssl.com"
    };
    
    /* Test curl */
    if (run_command("which curl >/dev/null 2>&1", &result) == 0) {
        TEST_LOG("Testing curl command-line tool");
        for (int i = 0; i < 3; i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "curl -s -o /dev/null https://%s/", test_sites[i]);
            if (run_command_timeout(cmd, 10, &result) == 0) {
                TEST_LOG("curl: %s OK", test_sites[i]);
            } else {
                failed++;
            }
        }
    }
    
    /* Test wget */
    if (run_command("which wget >/dev/null 2>&1", &result) == 0) {
        TEST_LOG("Testing wget command-line tool");
        for (int i = 0; i < 3; i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "wget -q -O /dev/null --timeout=10 https://%s/", test_sites[i]);
            run_command_timeout(cmd, 10, &result);
            TEST_LOG("wget: %s (exit %d)", test_sites[i], result.exit_code);
        }
    }
    
    /* Test openssl s_client */
    if (run_command("which openssl >/dev/null 2>&1", &result) == 0) {
        TEST_LOG("Testing openssl s_client");
        for (int i = 0; i < 3; i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "printf 'Q\\n' | timeout 10 openssl s_client -connect %s:443 >/dev/null 2>&1", test_sites[i]);
            run_command(cmd, &result);
            TEST_LOG("openssl: %s completed", test_sites[i]);
        }
    }
    
    /* Test gnutls-cli */
    if (run_command("which gnutls-cli >/dev/null 2>&1", &result) == 0) {
        TEST_LOG("Testing gnutls-cli");
        for (int i = 0; i < 3; i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "echo | timeout 10 gnutls-cli -p 443 %s >/dev/null 2>&1", test_sites[i]);
            run_command(cmd, &result);
            TEST_LOG("gnutls-cli: %s completed", test_sites[i]);
        }
    }
    
    return failed > 0 ? TEST_FAIL : TEST_PASS;
}

/* Main test runner */
int main(void) {
    /* Enable debug logging for TLS bypass library */
    setenv("TLS_NOVERIFY_DEBUG", "1", 1);
    
    test_init();
    
    TEST_LOG("TLS Verification Bypass Test Suite");
    TEST_LOG("===================================");
    TEST_LOG("Debug mode enabled (TLS_NOVERIFY_DEBUG=1)");
    
    /* Check LD_PRELOAD */
    if (!g_ld_preload || !strstr(g_ld_preload, "libtlsnoverify.so")) {
        TEST_ERROR("LD_PRELOAD not set or missing libtlsnoverify.so");
        TEST_ERROR("Usage: LD_PRELOAD=/path/to/libtlsnoverify.so %s", "test_all");
        return 1;
    }
    
    int failed = 0;
    
    /* Run library API tests */
    TEST_LOG("\nTesting Library APIs");
    TEST_LOG("====================");
    if (test_all_libraries() != TEST_PASS) {
        failed++;
    }
    
    #ifdef HAS_CURL
    /* Run libcurl specific tests */
    TEST_LOG("\nTesting libcurl");
    TEST_LOG("===============");
    RUN_TEST("libcurl SSL verification", test_curl_ssl_verify);
    RUN_TEST("libcurl features", test_curl_features);
    #endif
    
    /* Run command-line tool tests */
    TEST_LOG("\nTesting Command-Line Tools");
    TEST_LOG("==========================");
    if (test_command_tools() != TEST_PASS) {
        failed++;
    }
    
    test_cleanup();
    
    return failed > 0 ? 1 : 0;
}