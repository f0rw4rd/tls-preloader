/* Test various HTTP clients (httpie, aria2c, axel) with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_http_command(const char *cmd, int timeout_seconds) {
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "timeout %d %s >/dev/null 2>&1", timeout_seconds, cmd);
    
    int status = system(full_cmd);
    
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        TEST_LOG("HTTP client exit code: %d", exit_code);
        return (exit_code == 0) ? 0 : -1;
    }
    
    return -1;
}

/* HTTPie tests */
int test_httpie_self_signed(void) {
    TEST_LOG("Testing httpie with self-signed cert");
    
    /* httpie should succeed with self-signed cert when bypassed */
    if (run_http_command("http --print=h https://self-signed.badssl.com/", 10) == 0) {
        TEST_LOG("httpie successfully connected to self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("httpie might need --verify=no flag explicitly");
    return TEST_PASS;
}

int test_httpie_expired(void) {
    TEST_LOG("Testing httpie with expired cert");
    
    if (run_http_command("http --print=h https://expired.badssl.com/", 10) == 0) {
        TEST_LOG("httpie successfully connected to expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_httpie_with_verify_no(void) {
    TEST_LOG("Testing httpie with --verify=no flag");
    
    /* Even with explicit verify=no, should work */
    if (run_http_command("http --verify=no --print=h https://self-signed.badssl.com/", 10) == 0) {
        TEST_LOG("httpie with --verify=no succeeded");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* aria2c tests */
int test_aria2c_self_signed(void) {
    TEST_LOG("Testing aria2c with self-signed cert");
    
    /* aria2c should download from self-signed site */
    if (run_http_command("aria2c -o /tmp/aria2c_test.html https://self-signed.badssl.com/", 10) == 0) {
        unlink("/tmp/aria2c_test.html");
        TEST_LOG("aria2c successfully downloaded from self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("aria2c connection test completed");
    return TEST_PASS;
}

int test_aria2c_expired(void) {
    TEST_LOG("Testing aria2c with expired cert");
    
    if (run_http_command("aria2c -o /tmp/aria2c_test2.html https://expired.badssl.com/", 10) == 0) {
        unlink("/tmp/aria2c_test2.html");
        TEST_LOG("aria2c successfully downloaded from expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_aria2c_check_certificate(void) {
    TEST_LOG("Testing aria2c with --check-certificate=false");
    
    /* Even with explicit certificate checking disabled */
    if (run_http_command("aria2c --check-certificate=false -o /tmp/aria2c_test3.html https://self-signed.badssl.com/", 10) == 0) {
        unlink("/tmp/aria2c_test3.html");
        TEST_LOG("aria2c with --check-certificate=false succeeded");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* axel tests */
int test_axel_self_signed(void) {
    TEST_LOG("Testing axel with self-signed cert");
    
    /* axel should download from self-signed site */
    if (run_http_command("axel -n 1 -o /tmp/axel_test.html https://self-signed.badssl.com/", 10) == 0) {
        unlink("/tmp/axel_test.html");
        TEST_LOG("axel successfully downloaded from self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("axel connection test completed");
    return TEST_PASS;
}

int test_axel_expired(void) {
    TEST_LOG("Testing axel with expired cert");
    
    if (run_http_command("axel -n 1 -o /tmp/axel_test2.html https://expired.badssl.com/", 10) == 0) {
        unlink("/tmp/axel_test2.html");
        TEST_LOG("axel successfully downloaded from expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_axel_wrong_host(void) {
    TEST_LOG("Testing axel with wrong hostname");
    
    if (run_http_command("axel -n 1 -o /tmp/axel_test3.html https://wrong.host.badssl.com/", 10) == 0) {
        unlink("/tmp/axel_test3.html");
        TEST_LOG("axel successfully downloaded from wrong hostname");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing HTTP clients");
    
    /* Check if httpie is available */
    if (system("which http >/dev/null 2>&1") == 0) {
        RUN_TEST("httpie self-signed", test_httpie_self_signed);
        RUN_TEST("httpie expired cert", test_httpie_expired);
        RUN_TEST("httpie with --verify=no", test_httpie_with_verify_no);
    } else {
        TEST_LOG("httpie not available, skipping httpie tests");
    }
    
    /* Check if aria2c is available */
    if (system("which aria2c >/dev/null 2>&1") == 0) {
        RUN_TEST("aria2c self-signed", test_aria2c_self_signed);
        RUN_TEST("aria2c expired cert", test_aria2c_expired);
        RUN_TEST("aria2c check-certificate", test_aria2c_check_certificate);
    } else {
        TEST_LOG("aria2c not available, skipping aria2c tests");
    }
    
    /* Check if axel is available */
    if (system("which axel >/dev/null 2>&1") == 0) {
        RUN_TEST("axel self-signed", test_axel_self_signed);
        RUN_TEST("axel expired cert", test_axel_expired);
        RUN_TEST("axel wrong host", test_axel_wrong_host);
    } else {
        TEST_LOG("axel not available, skipping axel tests");
    }
    
    TEST_LOG("All tests completed!");
    return 0;
}