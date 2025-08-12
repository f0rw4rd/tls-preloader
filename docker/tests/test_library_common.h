/* Common library testing framework */
#ifndef TEST_LIBRARY_COMMON_H
#define TEST_LIBRARY_COMMON_H

#include "test_runner.h"

/* Library test types */
typedef enum {
    LIB_TEST_FUNCTION_EXISTS,
    LIB_TEST_FUNCTION_RETURNS,
    LIB_TEST_FUNCTION_BYPASS,
    LIB_TEST_VERSION_CHECK
} lib_test_type_t;

/* Library test case */
typedef struct {
    const char *name;
    const char *function_name;
    lib_test_type_t type;
    int expected_value;
    void *test_arg;
} lib_test_case_t;

/* Library info */
typedef struct {
    const char *name;
    const char *version_func;
    const char *min_version;
} lib_info_t;

/* Common test functions */
int test_library_function_exists(const char *func_name);
int test_library_function_returns(const char *func_name, int expected);
int test_library_bypass_active(const char *func_name, void *test_arg);
int test_library_version(const char *version_func, const char *min_version);

/* Test runners */
int run_library_tests(const char *lib_name, lib_test_case_t *tests, int num_tests);
int run_version_specific_tests(lib_info_t *lib_info, test_func_t *version_tests, int num_tests);

/* Common bypass test implementations */
int test_openssl_bypass(void);
int test_gnutls_bypass(void);
int test_mbedtls_bypass(void);
int test_wolfssl_bypass(void);
int test_nss_bypass(void);

#endif /* TEST_LIBRARY_COMMON_H */