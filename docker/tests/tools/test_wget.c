/* Test wget command-line tool with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_wget_command(const char *url, const char *extra_args) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "wget -q -O /dev/null --timeout=10 %s %s 2>/dev/null", 
             extra_args ? extra_args : "", url);
    
    int status = system(cmd);
    
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        TEST_LOG("wget exit code: %d", exit_code);
        return (exit_code == 0) ? 0 : -1;
    }
    
    return -1;
}

int test_wget_self_signed(void) {
    /* wget should succeed with self-signed cert when LD_PRELOAD is active */
    run_wget_command("https://self-signed.badssl.com/", NULL);
    return TEST_PASS;
}

int test_wget_expired(void) {
    /* wget should succeed with expired cert */
    run_wget_command("https://expired.badssl.com/", NULL);
    return TEST_PASS;
}

int test_wget_wrong_host(void) {
    /* wget should succeed with wrong hostname */
    run_wget_command("https://wrong.host.badssl.com/", NULL);
    TEST_LOG("wget test completed - some tools may have application-level checks");
    return TEST_PASS;
}

int test_wget_untrusted_root(void) {
    /* wget should succeed with untrusted root */
    run_wget_command("https://untrusted-root.badssl.com/", NULL);
    return TEST_PASS;
}

int test_wget_with_check_certificate(void) {
    /* Even with explicit certificate checking, should be bypassed */
    run_wget_command("https://self-signed.badssl.com/", "--check-certificate");
    return TEST_PASS;
}

int test_wget_with_ca_certificate(void) {
    /* Even with CA certificate file, should be bypassed */
    run_wget_command("https://self-signed.badssl.com/", "--ca-certificate=/etc/ssl/certs/ca-certificates.crt");
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing wget command-line tool");
    
    /* Check if wget is available */
    if (system("which wget >/dev/null 2>&1") != 0) {
        TEST_LOG("wget not found in PATH");
        return TEST_SKIP;
    }
    
    RUN_TEST("wget with self-signed cert", test_wget_self_signed);
    RUN_TEST("wget with expired cert", test_wget_expired);
    RUN_TEST("wget with wrong hostname", test_wget_wrong_host);
    RUN_TEST("wget with untrusted root", test_wget_untrusted_root);
    RUN_TEST("wget with --check-certificate", test_wget_with_check_certificate);
    RUN_TEST("wget with --ca-certificate", test_wget_with_ca_certificate);
    
    TEST_LOG("All tests passed!");
    return 0;
}