#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* Test result codes */
typedef enum {
    TEST_PASS = 0,
    TEST_FAIL = 1,
    TEST_SKIP = 2,
    TEST_ERROR = 3
} test_result_t;

/* Test case structure */
typedef struct {
    const char *name;
    const char *description;
    test_result_t (*test_func)(void);
    int timeout_seconds;
} test_case_t;

/* Thread test structure */
typedef struct {
    const char *url;
    int thread_id;
    test_result_t result;
    char error_msg[256];
    double duration_ms;
} thread_test_data_t;

/* Common test functions */
void test_init(void);
void test_cleanup(void);
void print_test_header(const char *test_name);
void print_test_result(const char *test_name, test_result_t result, const char *error_msg);
void print_test_summary(int total, int passed, int failed, int skipped);

/* CURL helpers */
CURL* create_curl_handle(void);
test_result_t perform_curl_request(const char *url, long *http_code, char **error_msg);
test_result_t verify_ssl_result(CURL *curl);

/* Multi-threading test helpers */
test_result_t run_concurrent_requests(const char *url, int num_threads, double *avg_time_ms);
void* thread_worker(void *arg);

/* URL test helpers */
test_result_t test_url(const char *url, const char *description);
test_result_t test_url_with_options(const char *url, const char *description, 
                                   CURLoption *options, void **values, int num_options);

/* Timing helpers */
double get_time_ms(void);
void sleep_ms(int milliseconds);

/* Memory write callback for curl */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);

/* Test data structure for response */
typedef struct {
    char *data;
    size_t size;
} response_data_t;

/* Convenience macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: %s\n", message); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_LOG(format, ...) \
    fprintf(stdout, "[TEST] " format "\n", ##__VA_ARGS__)

#define TEST_ERROR(format, ...) \
    fprintf(stderr, "[ERROR] " format "\n", ##__VA_ARGS__)

#endif /* TEST_COMMON_H */