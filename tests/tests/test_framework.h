/* Shared test framework for all TLS library tests */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>

/* Test result codes */
#define TEST_PASS 0
#define TEST_FAIL 1
#define TEST_SKIP 2

/* Logging macros */
#define TEST_LOG(...) do { \
    printf("[TEST] "); \
    printf(__VA_ARGS__); \
    printf("\n"); \
    fflush(stdout); \
} while(0)

#define TEST_ERROR(...) do { \
    fprintf(stderr, "[ERROR] "); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    exit(TEST_FAIL); \
} while(0)

/* Test execution macro - fails on first error */
#define RUN_TEST(name, func) do { \
    printf("\n=== %s ===\n", name); \
    int result = func(); \
    if (result == TEST_FAIL) { \
        TEST_ERROR("Test failed: %s", name); \
    } else if (result == TEST_SKIP) { \
        TEST_LOG("Test skipped: %s", name); \
    } else { \
        TEST_LOG("Test passed: %s", name); \
    } \
} while(0)

/* Version detection helpers */
static inline int check_function_exists(const char *func_name) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    void *func = dlsym(handle, func_name);
    dlclose(handle);
    
    return func != NULL;
}

/* Initialize test environment */
static inline void test_init(void) {
    /* Set unbuffered output */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    /* Check if preload library is active */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        TEST_ERROR("LD_PRELOAD not set correctly. Library not loaded.");
    }
    
    TEST_LOG("Test framework initialized");
    TEST_LOG("LD_PRELOAD=%s", preload);
}

#endif /* TEST_FRAMEWORK_H */