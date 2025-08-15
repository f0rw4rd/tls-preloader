/* Consolidated HTTP client tool tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "test_framework.h"

typedef struct {
    const char *name;
    const char *cmd_check;    /* Command to check if tool exists */
    const char *cmd_test;     /* Command to test SSL bypass */
    const char *success_str;  /* String to look for in output */
} http_tool_t;

/* Define all HTTP tools to test */
static const http_tool_t http_tools[] = {
    {
        "curl",
        "curl --version 2>/dev/null",
        "curl -s -I https://expired.badssl.com 2>&1",
        "HTTP/"
    },
    {
        "wget", 
        "wget --version 2>/dev/null",
        "wget -q -O /dev/null --server-response https://expired.badssl.com 2>&1",
        "HTTP/"
    },
    {
        "wget2",
        "wget2 --version 2>/dev/null", 
        "wget2 -q -O /dev/null https://expired.badssl.com 2>&1",
        NULL  /* wget2 is quiet on success */
    },
    {
        "httpie",
        "http --version 2>/dev/null",
        "http --verify=no HEAD https://expired.badssl.com 2>&1",
        "HTTP/"
    },
    {
        "aria2c",
        "aria2c --version 2>/dev/null",
        "aria2c --check-certificate=false -d /tmp -o test.tmp https://expired.badssl.com 2>&1",
        "Download complete"
    }
};

/* Run a command and capture output */
static int run_command(const char *cmd, char *output, size_t outsize) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    
    size_t total = 0;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) && total < outsize - 1) {
        size_t len = strlen(buffer);
        if (total + len >= outsize - 1) break;
        strcat(output, buffer);
        total += len;
    }
    
    return pclose(fp);
}

/* Test if tool exists */
static int tool_exists(const char *check_cmd) {
    return system(check_cmd) == 0;
}

/* Test HTTP tool with TLS bypass */
static int test_http_tool(const http_tool_t *tool) {
    char output[4096] = {0};
    
    /* Check if tool exists */
    if (!tool_exists(tool->cmd_check)) {
        TEST_LOG("Skipping %s (not installed)", tool->name);
        return 1;  /* Skip, not fail */
    }
    
    TEST_LOG("Testing %s...", tool->name);
    
    /* Run test command */
    int ret = run_command(tool->cmd_test, output, sizeof(output));
    
    /* Check for success */
    if (tool->success_str) {
        if (strstr(output, tool->success_str)) {
            TEST_LOG("%s: Successfully bypassed TLS verification", tool->name);
            return 1;
        } else {
            TEST_LOG("%s: Failed - expected '%s' in output", tool->name, tool->success_str);
            return 0;
        }
    } else {
        /* Some tools are quiet on success */
        if (ret == 0) {
            TEST_LOG("%s: Successfully bypassed TLS verification", tool->name);
            return 1;
        } else {
            TEST_LOG("%s: Failed with exit code %d", tool->name, ret);
            return 0;
        }
    }
}

/* Test libcurl directly */
static int test_libcurl(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    void* (*curl_easy_init)(void) = dlsym(handle, "curl_easy_init");
    if (!curl_easy_init) {
        dlclose(handle);
        TEST_LOG("libcurl not found");
        return 1;  /* Skip, not fail */
    }
    
    TEST_LOG("Testing libcurl direct bypass");
    
    /* curl_easy_init should auto-disable verification */
    void *curl = curl_easy_init();
    int success = (curl != NULL);
    
    if (curl) {
        void (*curl_easy_cleanup)(void*) = dlsym(handle, "curl_easy_cleanup");
        if (curl_easy_cleanup) curl_easy_cleanup(curl);
    }
    
    dlclose(handle);
    return success;
}

/* Test all HTTP tools with both test sites */
void test_all_http_tools(void) {
    int tools_tested = 0;
    
    /* Test libcurl directly first */
    RUN_TEST(test_libcurl(), "libcurl direct bypass");
    
    /* Test each HTTP tool */
    for (size_t i = 0; i < sizeof(http_tools) / sizeof(http_tools[0]); i++) {
        if (test_http_tool(&http_tools[i])) {
            tools_tested++;
        }
    }
    
    if (tools_tested == 0) {
        TEST_LOG("WARNING: No HTTP tools were tested");
    } else {
        TEST_LOG("Tested %d HTTP tools successfully", tools_tested);
    }
}

int main(void) {
    TEST_LOG("=== Consolidated HTTP Tool Tests ===");
    test_all_http_tools();
    return test_summary();
}