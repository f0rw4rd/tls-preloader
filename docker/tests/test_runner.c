/* Consolidated test runner implementation */
#include "test_runner.h"
#include <time.h>
#include <signal.h>
#include <sys/types.h>

/* Global variables */
int g_verbose = 0;
const char *g_ld_preload = NULL;

/* Test statistics */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

/* Initialize test environment */
void test_init(void) {
    /* Check for LD_PRELOAD */
    g_ld_preload = getenv("LD_PRELOAD");
    if (g_ld_preload) {
        TEST_LOG("LD_PRELOAD=%s", g_ld_preload);
    }
    
    /* Check for verbose mode */
    if (getenv("TEST_VERBOSE")) {
        g_verbose = 1;
    }
    
    /* Initialize random seed */
    srand(time(NULL));
}

/* Clean up test environment */
void test_cleanup(void) {
    /* Print summary */
    printf("\n");
    printf("===========================================\n");
    printf("Test Summary:\n");
    printf("  Total:   %d\n", tests_run);
    printf("  Passed:  %d\n", tests_passed);
    printf("  Failed:  %d\n", tests_failed);
    printf("  Skipped: %d\n", tests_skipped);
    printf("===========================================\n");
}

/* Run a single test */
int run_single_test(const char *name, test_func_t func) {
    int result;
    
    printf("\n=== %s ===\n", name);
    fflush(stdout);
    
    tests_run++;
    result = func();
    
    switch (result) {
        case TEST_PASS:
            TEST_LOG("Test passed: %s", name);
            tests_passed++;
            break;
        case TEST_FAIL:
            TEST_ERROR("Test failed: %s", name);
            tests_failed++;
            break;
        case TEST_SKIP:
            TEST_LOG("Test skipped: %s", name);
            tests_skipped++;
            break;
        default:
            TEST_ERROR("Test error: %s (code=%d)", name, result);
            tests_failed++;
            result = TEST_FAIL;
    }
    
    return result;
}

/* Run a test suite */
int run_test_suite(test_suite_t *suite) {
    int i;
    int suite_failed = 0;
    
    printf("\n");
    printf("===========================================\n");
    printf("%s\n", suite->name);
    printf("===========================================\n");
    
    /* Run setup if provided */
    if (suite->setup) {
        suite->setup();
    }
    
    /* Run each test */
    for (i = 0; i < suite->num_tests; i++) {
        if (!suite->tests[i].enabled) {
            continue;
        }
        
        if (run_single_test(suite->tests[i].name, suite->tests[i].func) == TEST_FAIL) {
            suite_failed = 1;
            /* Continue running other tests */
        }
    }
    
    /* Run teardown if provided */
    if (suite->teardown) {
        suite->teardown();
    }
    
    return suite_failed ? TEST_FAIL : TEST_PASS;
}

/* Run a command and capture output */
int run_command(const char *cmd, cmd_result_t *result) {
    FILE *fp;
    char buffer[256];
    
    /* Clear result */
    memset(result, 0, sizeof(cmd_result_t));
    
    /* Run command and capture output */
    fp = popen(cmd, "r");
    if (!fp) {
        snprintf(result->error, sizeof(result->error), "popen failed: %s", strerror(errno));
        result->exit_code = -1;
        return -1;
    }
    
    /* Read output */
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strlen(result->output) + strlen(buffer) < sizeof(result->output) - 1) {
            strcat(result->output, buffer);
        }
    }
    
    /* Get exit code */
    int status = pclose(fp);
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else {
        result->exit_code = -1;
        snprintf(result->error, sizeof(result->error), "Command did not exit normally");
    }
    
    TEST_DEBUG("Command: %s", cmd);
    TEST_DEBUG("Exit code: %d", result->exit_code);
    if (g_verbose && strlen(result->output) > 0) {
        TEST_DEBUG("Output: %s", result->output);
    }
    
    return result->exit_code;
}

/* Run command with timeout */
int run_command_timeout(const char *cmd, int timeout_secs, cmd_result_t *result) {
    char timeout_cmd[1024];
    snprintf(timeout_cmd, sizeof(timeout_cmd), "timeout %d %s", timeout_secs, cmd);
    return run_command(timeout_cmd, result);
}

/* Get function pointer with dlsym, bypassing interception */
void *dlsym_bypass(const char *symbol) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return NULL;
    }
    
    void *func = dlsym(handle, symbol);
    dlclose(handle);
    return func;
}

/* Check if a library function exists */
int check_library_function(const char *func_name) {
    void *func = dlsym_bypass(func_name);
    if (func) {
        TEST_DEBUG("Found function: %s", func_name);
        return 1;
    }
    TEST_DEBUG("Function not found: %s", func_name);
    return 0;
}