/* Test backtrace functionality across different libc implementations */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include "test_framework.h"

/* Check if we're on musl libc */
static int is_musl_libc(void) {
    /* musl doesn't define __GLIBC__ */
#ifdef __GLIBC__
    return 0;
#else
    /* Additional runtime check */
    FILE *fp = popen("ldd --version 2>&1", "r");
    if (!fp) return 0;
    
    char buffer[256];
    int is_musl = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "musl")) {
            is_musl = 1;
            break;
        }
    }
    pclose(fp);
    
    /* If ldd doesn't work, check for Alpine */
    if (!is_musl) {
        if (access("/etc/alpine-release", F_OK) == 0) {
            is_musl = 1;
        }
    }
    
    return is_musl;
#endif
}

/* Test if libexecinfo is available */
static int test_libexecinfo_available(void) {
    void *handle = dlopen("libexecinfo.so.1", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("libexecinfo.so", RTLD_LAZY);
    }
    
    if (handle) {
        void *backtrace_func = dlsym(handle, "backtrace");
        void *backtrace_symbols_func = dlsym(handle, "backtrace_symbols");
        dlclose(handle);
        return (backtrace_func && backtrace_symbols_func) ? 1 : 0;
    }
    
    return 0;
}

/* Test if native backtrace is available */
static int test_native_backtrace(void) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    void *backtrace_func = dlsym(handle, "backtrace");
    void *backtrace_symbols_func = dlsym(handle, "backtrace_symbols");
    dlclose(handle);
    
    return (backtrace_func && backtrace_symbols_func) ? 1 : 0;
}

/* Test actual backtrace functionality */
static int test_backtrace_works(void) {
    /* Set environment variables */
    setenv("TLS_NOVERIFY_DEBUG", "1", 1);
    setenv("TLS_NOVERIFY_BACKTRACE", "1", 1);
    
    /* Try to trigger a backtrace by calling a hooked function */
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return 0;
    
    /* Try OpenSSL function that should trigger backtrace */
    void (*ssl_ctx_verify)(void*, int, void*) = dlsym(handle, "SSL_CTX_set_verify");
    if (ssl_ctx_verify) {
        TEST_LOG("Calling SSL_CTX_set_verify to trigger backtrace...");
        
        /* Capture stderr to check for backtrace output */
        int saved_stderr = dup(STDERR_FILENO);
        int pipefd[2];
        pipe(pipefd);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        /* Call function to trigger backtrace */
        ssl_ctx_verify(NULL, 0, NULL);
        
        /* Read captured output */
        char buffer[4096] = {0};
        int n = read(pipefd[0], buffer, sizeof(buffer) - 1);
        close(pipefd[0]);
        
        /* Restore stderr */
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
        
        if (n > 0) {
            /* Check for backtrace markers */
            int has_backtrace = (strstr(buffer, "=== Backtrace for") != NULL ||
                                strstr(buffer, "Backtrace not supported") != NULL);
            
            if (has_backtrace) {
                TEST_LOG("Backtrace output detected");
                if (strstr(buffer, "Backtrace not supported")) {
                    TEST_LOG("Platform reports: Backtrace not supported");
                    return 0;
                }
                return 1;
            }
        }
    }
    
    dlclose(handle);
    return 0;
}

/* Main test function */
void test_backtrace_support(void) {
    int is_musl = is_musl_libc();
    int has_native = test_native_backtrace();
    int has_libexecinfo = test_libexecinfo_available();
    
    TEST_LOG("=== Backtrace Support Test ===");
    TEST_LOG("Libc type: %s", is_musl ? "musl" : "glibc/other");
    TEST_LOG("Native backtrace: %s", has_native ? "YES" : "NO");
    TEST_LOG("libexecinfo available: %s", has_libexecinfo ? "YES" : "NO");
    
    if (is_musl) {
        if (!has_native && !has_libexecinfo) {
            TEST_LOG("musl libc without libexecinfo - backtrace expected to be unavailable");
            RUN_TEST(!test_backtrace_works(), "Backtrace correctly unavailable on musl without libexecinfo");
        } else if (has_libexecinfo) {
            TEST_LOG("musl libc with libexecinfo - testing dynamic loading");
            RUN_TEST(test_backtrace_works(), "Backtrace works on musl with libexecinfo");
        }
    } else {
        if (has_native) {
            TEST_LOG("Native backtrace support detected");
            RUN_TEST(test_backtrace_works(), "Native backtrace functionality");
        } else {
            TEST_LOG("No native backtrace support");
            RUN_TEST(!test_backtrace_works(), "Backtrace correctly unavailable");
        }
    }
}

int main(void) {
    TEST_LOG("=== TLS Preloader Backtrace Test ===");
    
    /* Make sure our library is loaded */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        TEST_LOG("ERROR: libtlsnoverify.so not preloaded!");
        TEST_LOG("Run with: LD_PRELOAD=/path/to/libtlsnoverify.so %s", __FILE__);
        return 1;
    }
    
    test_backtrace_support();
    return test_summary();
}