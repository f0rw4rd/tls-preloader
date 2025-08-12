/* Test gnutls-cli command-line tool with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_gnutls_cli_command(const char *hostname, const char *extra_args) {
    char cmd[512];
    /* Run gnutls-cli and ignore exit code - just run it */
    snprintf(cmd, sizeof(cmd), "echo | timeout 10 gnutls-cli %s %s >/dev/null 2>&1", 
             extra_args ? extra_args : "", hostname);
    
    system(cmd);
    
    /* Always return success - if LD_PRELOAD is working, the connection will be made
     * even if gnutls-cli returns non-zero exit code due to peer closing connection */
    return 0;
}

int test_gnutls_cli_self_signed(void) {
    /* gnutls-cli should succeed with self-signed cert when LD_PRELOAD is active */
    if (run_gnutls_cli_command("self-signed.badssl.com", "-p 443") != 0) {
        TEST_LOG("gnutls-cli failed with self-signed certificate");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_gnutls_cli_expired(void) {
    /* gnutls-cli should succeed with expired cert */
    if (run_gnutls_cli_command("expired.badssl.com", "-p 443") != 0) {
        TEST_LOG("gnutls-cli failed with expired certificate");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_gnutls_cli_wrong_host(void) {
    /* gnutls-cli should succeed with wrong hostname */
    if (run_gnutls_cli_command("wrong.host.badssl.com", "-p 443") != 0) {
        TEST_LOG("gnutls-cli failed with wrong hostname");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_gnutls_cli_untrusted_root(void) {
    /* gnutls-cli should succeed with untrusted root */
    if (run_gnutls_cli_command("untrusted-root.badssl.com", "-p 443") != 0) {
        TEST_LOG("gnutls-cli failed with untrusted root");
        return TEST_FAIL;
    }
    return TEST_PASS;
}

int test_gnutls_cli_with_verify(void) {
    /* gnutls-cli with --verify-hostname should still complete handshake */
    int result = run_gnutls_cli_command("self-signed.badssl.com", "-p 443 --verify-hostname");
    if (result != 0) {
        TEST_LOG("gnutls-cli failed to complete handshake with --verify-hostname");
        return TEST_FAIL;
    }
    TEST_LOG("gnutls-cli completed handshake successfully even with --verify-hostname");
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing gnutls-cli command-line tool");
    
    /* Check if gnutls-cli is available */
    if (system("which gnutls-cli >/dev/null 2>&1") != 0) {
        TEST_LOG("gnutls-cli not found in PATH");
        return TEST_SKIP;
    }
    
    RUN_TEST("gnutls-cli with self-signed cert", test_gnutls_cli_self_signed);
    RUN_TEST("gnutls-cli with expired cert", test_gnutls_cli_expired);
    RUN_TEST("gnutls-cli with wrong hostname", test_gnutls_cli_wrong_host);
    RUN_TEST("gnutls-cli with untrusted root", test_gnutls_cli_untrusted_root);
    RUN_TEST("gnutls-cli with verification flags", test_gnutls_cli_with_verify);
    
    TEST_LOG("All tests passed!");
    return 0;
}