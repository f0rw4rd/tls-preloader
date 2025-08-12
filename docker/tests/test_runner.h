/* Consolidated test runner framework */
#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

/* Test result codes */
typedef enum {
    TEST_PASS = 0,
    TEST_FAIL = 1,
    TEST_SKIP = 77,
    TEST_ERROR = 99
} test_result_t;

/* Test function signature */
typedef int (*test_func_t)(void);

/* Test case structure */
typedef struct {
    const char *name;
    test_func_t func;
    int enabled;
} test_case_t;

/* Test suite structure */
typedef struct {
    const char *name;
    test_case_t *tests;
    int num_tests;
    void (*setup)(void);
    void (*teardown)(void);
} test_suite_t;

/* Command execution result */
typedef struct {
    int exit_code;
    char output[4096];
    char error[1024];
} cmd_result_t;

/* Global test context */
extern int g_verbose;
extern const char *g_ld_preload;

/* Logging macros */
#define TEST_LOG(fmt, ...) \
    do { \
        printf("[TEST] " fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } while(0)

#define TEST_ERROR(fmt, ...) \
    do { \
        fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)

#define TEST_DEBUG(fmt, ...) \
    do { \
        if (g_verbose) { \
            printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
            fflush(stdout); \
        } \
    } while(0)

/* Test execution helpers */
#define RUN_TEST(name, func) run_single_test(name, func)
#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            TEST_ERROR("Assertion failed: %s", #cond); \
            return TEST_FAIL; \
        } \
    } while(0)

#define ASSERT_EQUAL(a, b) \
    do { \
        if ((a) != (b)) { \
            TEST_ERROR("Assertion failed: %s != %s", #a, #b); \
            return TEST_FAIL; \
        } \
    } while(0)

/* Function declarations */
int run_single_test(const char *name, test_func_t func);
int run_test_suite(test_suite_t *suite);
int run_command(const char *cmd, cmd_result_t *result);
int run_command_timeout(const char *cmd, int timeout_secs, cmd_result_t *result);
void *dlsym_bypass(const char *symbol);
int check_library_function(const char *func_name);
void test_init(void);
void test_cleanup(void);

#endif /* TEST_RUNNER_H */