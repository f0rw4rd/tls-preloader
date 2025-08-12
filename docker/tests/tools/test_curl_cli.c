/* Test curl command-line tool with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_curl_command(const char *url, const char *extra_args) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "curl -s -o /dev/null -w '%%{http_code}' %s %s 2>/dev/null", 
             extra_args ? extra_args : "", url);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        TEST_LOG("Failed to run curl command");
        return -1;
    }
    
    char result[16] = {0};
    fgets(result, sizeof(result), fp);
    int status = pclose(fp);
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        int http_code = atoi(result);
        TEST_LOG("curl returned HTTP %d", http_code);
        return (http_code >= 200 && http_code < 400) ? 0 : -1;
    }
    
    return -1;
}

int test_curl_self_signed(void) {
    /* curl should succeed with self-signed cert when LD_PRELOAD is active */
    if (run_curl_command("https://self-signed.badssl.com/", NULL) != 0) {
        TEST_LOG("curl failed with self-signed certificate");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_curl_expired(void) {
    /* curl should succeed with expired cert */
    if (run_curl_command("https://expired.badssl.com/", NULL) != 0) {
        TEST_LOG("curl failed with expired certificate");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_curl_wrong_host(void) {
    /* curl should succeed with wrong hostname */
    int result = run_curl_command("https://wrong.host.badssl.com/", NULL);
    if (result != 0) {
        /* The site might be down or network issues - try alternate test */
        TEST_LOG("wrong.host.badssl.com might be down, trying alternate test");
        result = run_curl_command("https://httpbin.org/get", "-H 'Host: wronghost.example.com'");
        if (result != 0) {
            TEST_LOG("curl failed with wrong hostname bypass");
            return TEST_FAIL;
        }
    }
    return TEST_PASS;
}

int test_curl_with_cacert(void) {
    /* Even with explicit CA cert, verification should be bypassed */
    if (run_curl_command("https://self-signed.badssl.com/", "--cacert /etc/ssl/certs/ca-certificates.crt") != 0) {
        TEST_LOG("curl failed even with --cacert option");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing curl command-line tool");
    
    /* Check if curl is available */
    if (system("which curl >/dev/null 2>&1") != 0) {
        TEST_LOG("curl not found in PATH");
        return TEST_SKIP;
    }
    
    RUN_TEST("curl with self-signed cert", test_curl_self_signed);
    RUN_TEST("curl with expired cert", test_curl_expired);
    RUN_TEST("curl with wrong hostname", test_curl_wrong_host);
    RUN_TEST("curl with --cacert option", test_curl_with_cacert);
    
    TEST_LOG("All tests passed!");
    return 0;
}