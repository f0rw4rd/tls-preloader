/* Basic SSL/TLS verification tests */
#include "test_common.h"

/* Test expired certificate */
test_result_t test_expired_cert(void) {
    return test_url("https://expired.badssl.com/", "expired certificate");
}

/* Test wrong hostname */
test_result_t test_wrong_hostname(void) {
    return test_url("https://wrong.host.badssl.com/", "wrong hostname");
}

/* Test self-signed certificate */
test_result_t test_self_signed(void) {
    return test_url("https://self-signed.badssl.com/", "self-signed certificate");
}

/* Test untrusted root */
test_result_t test_untrusted_root(void) {
    return test_url("https://untrusted-root.badssl.com/", "untrusted root");
}

/* Test revoked certificate */
test_result_t test_revoked_cert(void) {
    return test_url("https://revoked.badssl.com/", "revoked certificate");
}

/* Test no common name */
test_result_t test_no_common_name(void) {
    return test_url("https://no-common-name.badssl.com/", "no common name");
}

/* Test no subject */
test_result_t test_no_subject(void) {
    return test_url("https://no-subject.badssl.com/", "no subject");
}

/* Test incomplete chain */
test_result_t test_incomplete_chain(void) {
    return test_url("https://incomplete-chain.badssl.com/", "incomplete chain");
}

/* Test valid certificate */
test_result_t test_valid_cert(void) {
    return test_url("https://badssl.com/", "valid certificate");
}

/* Run all basic SSL tests */
int main(void) {
    test_case_t tests[] = {
        {"expired_cert", "Test expired certificate", test_expired_cert, 10},
        {"wrong_hostname", "Test wrong hostname", test_wrong_hostname, 10},
        {"self_signed", "Test self-signed certificate", test_self_signed, 10},
        {"untrusted_root", "Test untrusted root", test_untrusted_root, 10},
        {"revoked_cert", "Test revoked certificate", test_revoked_cert, 10},
        {"no_common_name", "Test no common name", test_no_common_name, 10},
        {"no_subject", "Test no subject", test_no_subject, 10},
        {"incomplete_chain", "Test incomplete chain", test_incomplete_chain, 10},
        {"valid_cert", "Test valid certificate", test_valid_cert, 10}
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0, failed = 0, skipped = 0;
    int i;
    
    test_init();
    
    printf("\n=== Basic SSL/TLS Verification Tests ===\n");
    
    for (i = 0; i < num_tests; i++) {
        test_result_t result = tests[i].test_func();
        
        switch (result) {
            case TEST_PASS:
                passed++;
                break;
            case TEST_FAIL:
                failed++;
                break;
            case TEST_SKIP:
                skipped++;
                break;
            default:
                failed++;
                break;
        }
    }
    
    print_test_summary(num_tests, passed, failed, skipped);
    test_cleanup();
    
    return (failed > 0) ? 1 : 0;
}