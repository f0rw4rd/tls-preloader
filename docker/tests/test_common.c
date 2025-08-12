#include "test_common.h"
#include <sys/time.h>
#include <unistd.h>

/* Initialize test environment */
void test_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    TEST_LOG("Test framework initialized");
}

/* Cleanup test environment */
void test_cleanup(void) {
    curl_global_cleanup();
    TEST_LOG("Test framework cleaned up");
}

/* Print test header */
void print_test_header(const char *test_name) {
    printf("\n=== %s ===\n", test_name);
}

/* Print test result */
void print_test_result(const char *test_name, test_result_t result, const char *error_msg) {
    const char *status;
    switch (result) {
        case TEST_PASS:
            status = "✓ PASSED";
            break;
        case TEST_FAIL:
            status = "✗ FAILED";
            break;
        case TEST_SKIP:
            status = "- SKIPPED";
            break;
        case TEST_ERROR:
            status = "! ERROR";
            break;
        default:
            status = "? UNKNOWN";
    }
    
    printf("%-50s %s", test_name, status);
    if (error_msg && strlen(error_msg) > 0) {
        printf(" (%s)", error_msg);
    }
    printf("\n");
}

/* Print test summary */
void print_test_summary(int total, int passed, int failed, int skipped) {
    printf("\n========== Test Summary ==========\n");
    printf("Total:   %d\n", total);
    printf("Passed:  %d\n", passed);
    printf("Failed:  %d\n", failed);
    printf("Skipped: %d\n", skipped);
    printf("==================================\n");
}

/* Create a configured CURL handle */
CURL* create_curl_handle(void) {
    CURL *curl = curl_easy_init();
    if (curl) {
        /* Set common options */
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
        
        /* Disable verbose output by default */
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        
        /* Set user agent */
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "TLS-Test-Client/1.0");
    }
    return curl;
}

/* Memory write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_data_t *mem = (response_data_t *)userp;
    
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        /* Out of memory */
        return 0;
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

/* Perform a CURL request */
test_result_t perform_curl_request(const char *url, long *http_code, char **error_msg) {
    CURL *curl;
    CURLcode res;
    response_data_t response = {0};
    static char error_buffer[256];
    
    curl = create_curl_handle();
    if (!curl) {
        if (error_msg) *error_msg = "Failed to create CURL handle";
        return TEST_ERROR;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        snprintf(error_buffer, sizeof(error_buffer), "curl error: %s", curl_easy_strerror(res));
        if (error_msg) *error_msg = error_buffer;
        curl_easy_cleanup(curl);
        if (response.data) free(response.data);
        return TEST_FAIL;
    }
    
    if (http_code) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    }
    
    curl_easy_cleanup(curl);
    if (response.data) free(response.data);
    
    return TEST_PASS;
}

/* Verify SSL result from curl handle */
test_result_t verify_ssl_result(CURL *curl) {
    long verify_result;
    CURLcode res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_result);
    
    if (res != CURLE_OK) {
        TEST_ERROR("Failed to get SSL verify result");
        return TEST_ERROR;
    }
    
    if (verify_result != 0) {
        TEST_ERROR("SSL verification failed with code: %ld", verify_result);
        return TEST_FAIL;
    }
    
    return TEST_PASS;
}

/* Test a URL */
test_result_t test_url(const char *url, const char *description) {
    long http_code;
    char *error_msg = NULL;
    test_result_t result;
    
    TEST_LOG("Testing %s: %s", description, url);
    
    result = perform_curl_request(url, &http_code, &error_msg);
    
    if (result == TEST_PASS && (http_code < 200 || http_code >= 300)) {
        static char http_error[128];
        snprintf(http_error, sizeof(http_error), "HTTP %ld", http_code);
        error_msg = http_error;
        result = TEST_FAIL;
    }
    
    print_test_result(description, result, error_msg);
    return result;
}

/* Test a URL with custom options */
test_result_t test_url_with_options(const char *url, const char *description, 
                                   CURLoption *options, void **values, int num_options) {
    CURL *curl;
    CURLcode res;
    response_data_t response = {0};
    test_result_t result = TEST_PASS;
    long http_code;
    int i;
    
    curl = create_curl_handle();
    if (!curl) {
        print_test_result(description, TEST_ERROR, "Failed to create CURL handle");
        return TEST_ERROR;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    
    /* Apply custom options */
    for (i = 0; i < num_options; i++) {
        curl_easy_setopt(curl, options[i], values[i]);
    }
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        result = TEST_FAIL;
        print_test_result(description, result, curl_easy_strerror(res));
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code < 200 || http_code >= 300) {
            char msg[64];
            snprintf(msg, sizeof(msg), "HTTP %ld", http_code);
            result = TEST_FAIL;
            print_test_result(description, result, msg);
        } else {
            print_test_result(description, result, NULL);
        }
    }
    
    curl_easy_cleanup(curl);
    if (response.data) free(response.data);
    
    return result;
}

/* Get current time in milliseconds */
double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

/* Sleep for milliseconds */
void sleep_ms(int milliseconds) {
    usleep(milliseconds * 1000);
}

/* Thread worker function */
void* thread_worker(void *arg) {
    thread_test_data_t *data = (thread_test_data_t *)arg;
    double start_time, end_time;
    char *error_msg = NULL;
    long http_code;
    
    start_time = get_time_ms();
    
    data->result = perform_curl_request(data->url, &http_code, &error_msg);
    
    end_time = get_time_ms();
    data->duration_ms = end_time - start_time;
    
    if (error_msg) {
        strncpy(data->error_msg, error_msg, sizeof(data->error_msg) - 1);
        data->error_msg[sizeof(data->error_msg) - 1] = '\0';
    }
    
    return NULL;
}

/* Run concurrent requests */
test_result_t run_concurrent_requests(const char *url, int num_threads, double *avg_time_ms) {
    pthread_t *threads;
    thread_test_data_t *thread_data;
    int i;
    test_result_t overall_result = TEST_PASS;
    double total_time = 0;
    int successful_threads = 0;
    
    threads = malloc(num_threads * sizeof(pthread_t));
    thread_data = calloc(num_threads, sizeof(thread_test_data_t));
    
    if (!threads || !thread_data) {
        if (threads) free(threads);
        if (thread_data) free(thread_data);
        return TEST_ERROR;
    }
    
    /* Initialize thread data */
    for (i = 0; i < num_threads; i++) {
        thread_data[i].url = url;
        thread_data[i].thread_id = i;
        thread_data[i].result = TEST_ERROR;
    }
    
    /* Create threads */
    for (i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]) != 0) {
            TEST_ERROR("Failed to create thread %d", i);
            overall_result = TEST_ERROR;
        }
    }
    
    /* Wait for threads to complete */
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        
        if (thread_data[i].result == TEST_PASS) {
            successful_threads++;
            total_time += thread_data[i].duration_ms;
        } else {
            overall_result = TEST_FAIL;
            TEST_ERROR("Thread %d failed: %s", i, thread_data[i].error_msg);
        }
    }
    
    if (avg_time_ms && successful_threads > 0) {
        *avg_time_ms = total_time / successful_threads;
    }
    
    free(threads);
    free(thread_data);
    
    return overall_result;
}