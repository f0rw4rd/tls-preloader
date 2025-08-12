/* Test concurrent SSL connections */
#include "test_common.h"

test_result_t test_concurrent_basic(void) {
    double avg_time_ms;
    test_result_t result;
    int num_threads = 10;
    
    TEST_LOG("Running %d concurrent requests to expired.badssl.com", num_threads);
    
    result = run_concurrent_requests("https://expired.badssl.com/", num_threads, &avg_time_ms);
    
    if (result == TEST_PASS) {
        TEST_LOG("All threads completed successfully. Average time: %.2f ms", avg_time_ms);
    }
    
    return result;
}

test_result_t test_concurrent_mixed(void) {
    const char *urls[] = {
        "https://expired.badssl.com/",
        "https://wrong.host.badssl.com/",
        "https://self-signed.badssl.com/",
        "https://untrusted-root.badssl.com/",
        "https://badssl.com/"
    };
    int num_urls = sizeof(urls) / sizeof(urls[0]);
    int threads_per_url = 5;
    int i, j;
    test_result_t overall_result = TEST_PASS;
    
    TEST_LOG("Running concurrent requests to multiple URLs");
    
    for (i = 0; i < num_urls; i++) {
        double avg_time_ms;
        test_result_t result;
        
        TEST_LOG("Testing %s with %d threads", urls[i], threads_per_url);
        result = run_concurrent_requests(urls[i], threads_per_url, &avg_time_ms);
        
        if (result != TEST_PASS) {
            overall_result = TEST_FAIL;
        } else {
            TEST_LOG("  Average response time: %.2f ms", avg_time_ms);
        }
    }
    
    return overall_result;
}

test_result_t test_stress_single_url(void) {
    double avg_time_ms;
    test_result_t result;
    int num_threads = 50;  /* Stress test with many threads */
    
    TEST_LOG("Stress testing with %d concurrent threads", num_threads);
    
    result = run_concurrent_requests("https://badssl.com/", num_threads, &avg_time_ms);
    
    if (result == TEST_PASS) {
        TEST_LOG("Stress test completed. Average time: %.2f ms", avg_time_ms);
        
        /* Check if average time is reasonable */
        if (avg_time_ms > 5000) {
            TEST_ERROR("Average response time too high: %.2f ms", avg_time_ms);
            result = TEST_FAIL;
        }
    }
    
    return result;
}

/* Custom thread worker for performance test */
typedef struct {
    const char *url;
    int num_requests;
    int thread_id;
    double total_time_ms;
    int successful_requests;
} perf_thread_data_t;

void* perf_thread_worker(void *arg) {
    perf_thread_data_t *data = (perf_thread_data_t *)arg;
    int i;
    
    data->total_time_ms = 0;
    data->successful_requests = 0;
    
    for (i = 0; i < data->num_requests; i++) {
        double start_time = get_time_ms();
        long http_code;
        char *error_msg = NULL;
        
        if (perform_curl_request(data->url, &http_code, &error_msg) == TEST_PASS) {
            double end_time = get_time_ms();
            data->total_time_ms += (end_time - start_time);
            data->successful_requests++;
        }
        
        /* Small delay between requests */
        sleep_ms(10);
    }
    
    return NULL;
}

test_result_t test_performance(void) {
    int num_threads = 5;
    int requests_per_thread = 10;
    pthread_t *threads;
    perf_thread_data_t *thread_data;
    int i;
    double total_time = 0;
    int total_requests = 0;
    test_result_t result = TEST_PASS;
    
    threads = malloc(num_threads * sizeof(pthread_t));
    thread_data = calloc(num_threads, sizeof(perf_thread_data_t));
    
    if (!threads || !thread_data) {
        if (threads) free(threads);
        if (thread_data) free(thread_data);
        return TEST_ERROR;
    }
    
    TEST_LOG("Performance test: %d threads, %d requests each", num_threads, requests_per_thread);
    
    /* Initialize and start threads */
    for (i = 0; i < num_threads; i++) {
        thread_data[i].url = "https://badssl.com/";
        thread_data[i].num_requests = requests_per_thread;
        thread_data[i].thread_id = i;
        
        if (pthread_create(&threads[i], NULL, perf_thread_worker, &thread_data[i]) != 0) {
            TEST_ERROR("Failed to create thread %d", i);
            result = TEST_ERROR;
        }
    }
    
    /* Wait for completion and collect results */
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        
        total_time += thread_data[i].total_time_ms;
        total_requests += thread_data[i].successful_requests;
        
        TEST_LOG("Thread %d: %d/%d requests successful, avg time: %.2f ms",
                 i, thread_data[i].successful_requests, requests_per_thread,
                 thread_data[i].successful_requests > 0 ? 
                 thread_data[i].total_time_ms / thread_data[i].successful_requests : 0);
    }
    
    if (total_requests > 0) {
        double avg_time = total_time / total_requests;
        double requests_per_sec = 1000.0 / avg_time;
        
        TEST_LOG("Overall: %d/%d requests successful", total_requests, num_threads * requests_per_thread);
        TEST_LOG("Average response time: %.2f ms", avg_time);
        TEST_LOG("Throughput: %.2f requests/second", requests_per_sec * num_threads);
    } else {
        result = TEST_FAIL;
    }
    
    free(threads);
    free(thread_data);
    
    return result;
}

int main(void) {
    test_case_t tests[] = {
        {"concurrent_basic", "Test basic concurrent requests", test_concurrent_basic, 30},
        {"concurrent_mixed", "Test concurrent requests to different URLs", test_concurrent_mixed, 60},
        {"stress_test", "Stress test with many threads", test_stress_single_url, 60},
        {"performance", "Performance measurement test", test_performance, 120}
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0, failed = 0, skipped = 0;
    int i;
    
    test_init();
    
    printf("\n=== Concurrent SSL Connection Tests ===\n");
    
    for (i = 0; i < num_tests; i++) {
        print_test_header(tests[i].description);
        test_result_t result = tests[i].test_func();
        print_test_result(tests[i].name, result, NULL);
        
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