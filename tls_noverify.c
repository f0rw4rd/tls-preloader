/* TLS certificate verification bypass
 * Platforms: Linux, FreeBSD, OpenBSD, NetBSD, Solaris, AIX, macOS
 * Libraries: OpenSSL, BoringSSL, LibreSSL, GnuTLS, NSS, mbedTLS, wolfSSL, curl
 */

/* Platform detection */
#if defined(__linux__)
    #define PLATFORM_LINUX 1
    #define _GNU_SOURCE
#elif defined(__FreeBSD__)
    #define PLATFORM_FREEBSD 1
    #define _BSD_SOURCE
#elif defined(__OpenBSD__)
    #define PLATFORM_OPENBSD 1
    #define _BSD_SOURCE
#elif defined(__NetBSD__)
    #define PLATFORM_NETBSD 1
    #define _NETBSD_SOURCE
#elif defined(__sun) || defined(sun)
    #define PLATFORM_SOLARIS 1
    #define _POSIX_C_SOURCE 200112L
    #define __EXTENSIONS__
#elif defined(_AIX)
    #define PLATFORM_AIX 1
    #define _ALL_SOURCE
#elif defined(__APPLE__)
    #define PLATFORM_MACOS 1
    #define _DARWIN_C_SOURCE
#else
    #define PLATFORM_UNKNOWN 1
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

/* Backtrace support headers */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
    #include <execinfo.h>
#endif
#if defined(__sun) || defined(sun)
    #include <ucontext.h>
#endif

/* RTLD_NEXT compatibility */
#ifndef RTLD_NEXT
    #if defined(PLATFORM_SOLARIS)
        #define RTLD_NEXT ((void *)-1L)
    #elif defined(PLATFORM_AIX)
        #define RTLD_NEXT ((void *)-4L)
    #else
        #define RTLD_NEXT ((void *)-1L)
    #endif
#endif

#ifndef __GIT_COMMIT__
    #define __GIT_COMMIT__ "unknown"
#endif

/* =========================== Thread Safety =========================== */

/* Thread safety primitives */
#if defined(PLATFORM_LINUX) && !defined(__ANDROID__)
    /* Linux: pthread mutex */
    #include <sys/syscall.h>
    #include <linux/futex.h>
    #include <pthread.h>
    #ifndef __NR_gettid
        #define __NR_gettid 186  /* x86_64 */
    #endif
    
    static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    #define LOCK() pthread_mutex_lock(&g_mutex)
    #define UNLOCK() pthread_mutex_unlock(&g_mutex)
    
#elif defined(PLATFORM_SOLARIS)
    /* Solaris: atomic ops */
    #include <atomic.h>
    #include <sched.h>
    #include <thread.h>
    
    typedef volatile uint_t portable_mutex_t;
    static portable_mutex_t g_mutex = 0;
    
    static void LOCK(void) {
        while (atomic_swap_uint(&g_mutex, 1) != 0) {
            sched_yield();
        }
        membar_enter();
    }
    
    static void UNLOCK(void) {
        membar_exit();
        atomic_swap_uint(&g_mutex, 0);
    }
    
#elif defined(PLATFORM_FREEBSD) || defined(PLATFORM_NETBSD) || defined(PLATFORM_MACOS)
    /* BSD/macOS: pthread */
    #include <pthread.h>
    
    static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    #define LOCK() pthread_mutex_lock(&g_mutex)
    #define UNLOCK() pthread_mutex_unlock(&g_mutex)
    
#elif defined(PLATFORM_OPENBSD)
    /* OpenBSD: atomics + barriers */
    #include <sys/atomic.h>
    #include <unistd.h>
    
    static volatile unsigned int g_mutex = 0;
    
    static void LOCK(void) {
        while (atomic_swap_uint(&g_mutex, 1) != 0) {
            sched_yield();
        }
        __sync_synchronize();
    }
    
    static void UNLOCK(void) {
        __sync_synchronize();
        atomic_swap_uint(&g_mutex, 0);
    }
    
#else
    /* Fallback: GCC builtins */
    #ifdef __GNUC__
        static volatile int g_mutex = 0;
        
        static void LOCK(void) {
            while (__sync_val_compare_and_swap(&g_mutex, 0, 1) != 0) {
                usleep(1);
            }
        }
        
        static void UNLOCK(void) {
            __sync_lock_release(&g_mutex);
        }
    #else
        /* No-op */
        #define LOCK() (void)0
        #define UNLOCK() (void)0
    #endif
#endif

/* =========================== Core Infrastructure =========================== */

/* SSL/TLS return codes */
#define SSL_VERIFY_NONE 0x00
#define SSL_VERIFY_OK 1
#define X509_V_OK 0x0L
#define SEC_SUCCESS 0
#define WOLFSSL_SUCCESS 1
#define MBEDTLS_SSL_VERIFY_NONE 0

/* Function pointer types */
typedef int (*ssl_verify_callback_t)(void *store_ctx, void *arg);
typedef void (*ssl_ctx_verify_func_t)(void *ctx, int mode, void *callback);
typedef int (*gnutls_verify_func_t)(void *session);
typedef int (*nss_auth_callback_t)(void *arg, void *fd, int checkSig, int isServer);
typedef int (*mbedtls_verify_callback_t)(void *p_vrfy, void *crt, int depth, unsigned int *flags);
typedef int (*curl_setopt_func_t)(void *curl, int option, ...);
typedef int (*curl_getinfo_func_t)(void *curl, int info, ...);

/* Debug logging */
static int g_debug = -1;
static int g_backtrace = -1;

/* Get thread ID portably */
static unsigned long get_thread_id(void) {
#if defined(PLATFORM_LINUX) && defined(__NR_gettid)
    /* Linux: syscall for actual thread ID */
    return (unsigned long)syscall(__NR_gettid);
#elif defined(PLATFORM_FREEBSD) || defined(PLATFORM_NETBSD) || defined(PLATFORM_MACOS)
    /* BSD/macOS: pthread_self */
    return (unsigned long)pthread_self();
#elif defined(PLATFORM_OPENBSD)
    /* OpenBSD: getthrid */
    return (unsigned long)getthrid();
#elif defined(PLATFORM_SOLARIS)
    /* Solaris: thr_self */
    thread_t tid;
    thr_self(&tid);
    return (unsigned long)tid;
#elif defined(PLATFORM_AIX)
    /* AIX: pthread_self */
    return (unsigned long)pthread_self();
#else
    /* Fallback: just return 0 */
    return 0;
#endif
}

static void debug_log(const char *msg) {
    if (g_debug == -1) {
        const char *env = getenv("TLS_NOVERIFY_DEBUG");
        g_debug = (env && *env != '\0');
    }
    if (g_debug) {
        const char prefix[] = "[TLS_NOVERIFY] ";
        char id_str[64];
        ssize_t ret;
        
        /* Add PID and TID */
        unsigned long tid = get_thread_id();
        int id_len = snprintf(id_str, sizeof(id_str), "[%d:%lu] ", 
                              (int)getpid(), tid);
        
        ret = write(2, prefix, sizeof(prefix) - 1);
        if (id_len > 0 && id_len < sizeof(id_str)) {
            ret = write(2, id_str, id_len);
        }
        ret = write(2, msg, strlen(msg));
        ret = write(2, "\n", 1);
        (void)ret;
    }
}

/* Printf-style debug logging */
static void debug_logf(const char *fmt, ...) {
    if (g_debug == -1) {
        const char *env = getenv("TLS_NOVERIFY_DEBUG");
        g_debug = (env && *env != '\0');
    }
    if (g_debug) {
        char buffer[512];
        va_list args;
        va_start(args, fmt);
        int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        
        if (len > 0 && len < sizeof(buffer)) {
            debug_log(buffer);
        }
    }
}

/* Portable backtrace */
static void print_backtrace(const char *func_name) {
    if (g_backtrace == -1) {
        const char *env = getenv("TLS_NOVERIFY_BACKTRACE");
        g_backtrace = (env && *env != '\0');
        
        /* Check if backtrace is actually available at runtime */
        if (g_backtrace && PLATFORM_FREEBSD) {
            void *handle = dlopen(NULL, RTLD_LAZY | RTLD_LOCAL);
            if (handle) {
                void *bt_func = dlsym(handle, "backtrace");
                dlclose(handle);
                if (!bt_func) {
                    debug_log("[WARNING] TLS_NOVERIFY_BACKTRACE requested but backtrace() not available");                    
                    g_backtrace = 0;
                }
            }
        }
    }
    if (!g_backtrace) return;
    
    debug_logf("=== Backtrace for %s ===", func_name);
    
#if defined(PLATFORM_LINUX) || defined(PLATFORM_FREEBSD) || defined(PLATFORM_MACOS)
    #include <execinfo.h>
    void *array[20];  /* Increased from 10 */
    size_t size;
    char **strings;
    
    size = backtrace(array, 20);  /* Capture up to 20 frames */
    strings = backtrace_symbols(array, size);
    
    if (strings) {
        /* Skip first frame (this function), show up to 15 frames */
        size_t max_frames = (size > 16) ? 16 : size;
        for (size_t i = 1; i < max_frames; i++) {
            debug_logf("  [%zu] %s", i-1, strings[i]);
        }
        if (size > 16) {
            debug_logf("  ... (%zu more frames)", size - 16);
        }
        free(strings);
    }
#elif defined(PLATFORM_SOLARIS)
    /* Solaris: manual stack walk */
    void *fp = __builtin_frame_address(0);
    int depth = 0;
    while (fp && depth < 15) {  /* Increased from 5 */
        void *ret = *((void**)fp + 1);
        Dl_info info;
        if (dladdr(ret, &info) && info.dli_sname) {
            debug_logf("  [%d] %s", depth, info.dli_sname);
        } else if (dladdr(ret, &info) && info.dli_fname) {
            /* Show filename if symbol name not available */
            debug_logf("  [%d] %s+%p", depth, info.dli_fname, 
                      (char*)ret - (char*)info.dli_fbase);
        }
        fp = *(void**)fp;
        depth++;
    }
#else
    debug_log("  Backtrace not supported on this platform");
#endif
    
    debug_log("===========================");
}

/* Function pointer storage */
static void *g_real_funcs[64] = {0};

/* Function IDs */
enum {
    /* OpenSSL/BoringSSL/LibreSSL */
    FN_SSL_CTX_SET_VERIFY,
    FN_SSL_SET_VERIFY,
    FN_SSL_CTX_SET_CERT_VERIFY_CB,
    FN_SSL_CTX_SET_CUSTOM_VERIFY,
    FN_SSL_SET_VERIFY_RESULT,
    FN_SSL_SET_VERIFY_MODE,
    FN_X509_STORE_CTX_SET_ERROR,
    
    /* GnuTLS */
    FN_GNUTLS_CERT_SET_VERIFY_FN,
    FN_GNUTLS_SESSION_SET_VERIFY_CERT,
    FN_GNUTLS_X509_GET_EXPIRY,
    FN_GNUTLS_X509_GET_ACTIVATION,
    
    /* NSS */
    FN_SSL_AUTH_CERT_HOOK,
    FN_SSL_BAD_CERT_HOOK,
    
    /* mbedTLS */
    FN_MBEDTLS_SSL_CONF_AUTHMODE,
    FN_MBEDTLS_SSL_CONF_VERIFY,
    
    /* wolfSSL */
    FN_WOLFSSL_CTX_SET_VERIFY,
    FN_WOLFSSL_SET_VERIFY,
    
    /* curl */
    FN_CURL_EASY_SETOPT,
    FN_CURL_EASY_GETINFO,
    
    FN_MAX
};

/* Dynamic loading wrapper */
static void *portable_dlsym(const char *symbol) {
    void *sym = NULL;
    
    /* Check for self-reference */
    void *our_addr = dlsym(RTLD_DEFAULT, symbol);
    
#if defined(PLATFORM_SOLARIS)
    /* Solaris: RTLD_PROBE */
    #ifdef RTLD_PROBE
        sym = dlsym(RTLD_PROBE, symbol);
    #endif
    if (!sym) sym = dlsym(RTLD_NEXT, symbol);
    if (!sym) sym = dlsym(RTLD_DEFAULT, symbol);
#else
    sym = dlsym(RTLD_NEXT, symbol);
    if (!sym) sym = dlsym(NULL, symbol);
#endif
    
    /* Prevent recursion */
    if (sym == our_addr) {
        debug_logf("portable_dlsym: self-reference %s", symbol);
        return NULL;
    }
    
    return sym;
}

/* Thread-safe function loader */
static void *load_func(int id, const char *name) {
    void *func;
    
    if (id >= FN_MAX) return NULL;
    
    func = g_real_funcs[id];
    if (!func) {
        LOCK();
        func = g_real_funcs[id];
        if (!func) {
            func = portable_dlsym(name);
            g_real_funcs[id] = func;
        }
        UNLOCK();
    }
    
    return func;
}

#define LOAD_FN(id, name) load_func(id, name)

/* Function generator macros */
/* Return constant */
#define BYPASS_RETURN(name, ret_type, ret_val) \
ret_type name(void *arg) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 2 args, return constant */
#define BYPASS_RETURN2(name, ret_type, arg2_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 3 args, return constant */
#define BYPASS_RETURN3(name, ret_type, arg2_type, arg3_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 4 args, return constant */
#define BYPASS_RETURN4(name, ret_type, arg2_type, arg3_type, arg4_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 5 args, return constant */
#define BYPASS_RETURN5(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 7 args, return constant (NSS) */
#define BYPASS_RETURN7(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, arg6_type, arg7_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, \
              arg5_type arg5, arg6_type arg6, arg7_type arg7) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    return ret_val; \
}

/* 8 args, special handling */
#define BYPASS_RETURN8_SPECIAL(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, arg6_type, arg7_type, arg8_type) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, \
              arg5_type arg5, arg6_type arg6, arg7_type arg7, arg8_type arg8) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    if (arg8) *arg8 = arg4; \
    return 0; \
}

/* 4 args, void */
#define BYPASS_VOID4(name, arg2_type, arg3_type, arg4_type) \
void name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
}

/* Void return */
#define BYPASS_VOID(name) \
void name(void *arg) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
}

/* 2 args, void */
#define BYPASS_VOID2(name, arg2_type) \
void name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
}

/* 3 args, void */
#define BYPASS_VOID3(name, arg2_type, arg3_type) \
void name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
}

/* Modified args */
#define BYPASS_LOAD_CALL_VOID2(name, fn_id, arg2_type, new_arg2) \
void name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    void (*real)(void*, arg2_type) = (void (*)(void*, arg2_type)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, new_arg2); \
}

/* Modified args (3) */
#define BYPASS_LOAD_CALL_VOID3(name, fn_id, arg2_type, arg3_type, new_arg2, new_arg3) \
void name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    void (*real)(void*, arg2_type, arg3_type) = (void (*)(void*, arg2_type, arg3_type)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, new_arg2, new_arg3); \
}

/* Return 0, set status ptr (2) */
#define BYPASS_RETURN_STATUS2(name, arg2_type) \
int name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    if (arg2) *arg2 = 0; \
    return 0; \
}

/* Return 0, set status ptr (3) */
#define BYPASS_RETURN_STATUS3(name, arg2_type, arg3_type) \
int name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    if (arg3) *arg3 = 0; \
    return 0; \
}

/* 5 args, nullify ptr */
#define BYPASS_RETURN5_NULLIFY(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    if (arg5) *arg5 = NULL; \
    return ret_val; \
}

/* Replace callback */
#define BYPASS_LOAD_CALL_CB(name, fn_id, callback) \
int name(void *arg1, void *arg2, void *arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    int (*real)(void*, void*, void*) = (int (*)(void*, void*, void*)) \
        LOAD_FN(fn_id, #name); \
    if (real) return real(arg1, callback, arg3); \
    return 0; \
}

/* Replace callback with specific type */
#define BYPASS_LOAD_CALL_CB_TYPED(name, fn_id, callback, cb_type) \
void name(void *arg1, void *arg2, void *arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    void (*real)(void*, cb_type, void*) = \
        (void (*)(void*, cb_type, void*)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, callback, arg3); \
}

/* Replace callback (3 args, 2nd is int) */
#define BYPASS_LOAD_CALL_CB_INT(name, fn_id, callback) \
void name(void *arg1, int arg2, void *arg3) { \
    debug_log(#name ": bypass"); \
    print_backtrace(#name); \
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, arg2, callback); \
}

/* =========================== Callback Functions =========================== */

/* OpenSSL callbacks */
static int openssl_verify_cb(void *store_ctx, void *arg) {
    debug_log("OpenSSL verify callback: bypass");
    return 1;
}


static int boringssl_custom_verify(void *ssl, unsigned char *out_alert) {
    debug_log("BoringSSL custom verify: bypass");
    return 0;
}

static int gnutls_verify_cb(void *session) {
    debug_log("GnuTLS verify: bypass");
    return 0;
}

static int nss_auth_cb(void *arg, void *fd, int checkSig, int isServer) {
    debug_log("NSS auth: bypass");
    return SEC_SUCCESS;
}

static int nss_bad_cb(void *arg, void *fd) {
    debug_log("NSS bad cert: bypass");
    return SEC_SUCCESS;
}

static int mbedtls_verify_cb(void *p_vrfy, void *crt, int depth, unsigned int *flags) {
    debug_log("mbedTLS verify: bypass");
    if (flags) *flags = 0;
    return 0;
}

/* Unused */
/*
static int wolfssl_verify_cb(int preverify_ok, void *ctx) {
    debug_log("wolfSSL verify: bypass");
    return 1;
}
*/

/* =========================== OpenSSL/BoringSSL/LibreSSL Hooks =========================== */

BYPASS_LOAD_CALL_VOID3(SSL_CTX_set_verify, FN_SSL_CTX_SET_VERIFY, int, void*, 0, NULL)

BYPASS_LOAD_CALL_VOID3(SSL_set_verify, FN_SSL_SET_VERIFY, int, void*, 0, NULL)

BYPASS_LOAD_CALL_CB_TYPED(SSL_CTX_set_cert_verify_callback, FN_SSL_CTX_SET_CERT_VERIFY_CB, openssl_verify_cb, ssl_verify_callback_t)

BYPASS_LOAD_CALL_CB_INT(SSL_CTX_set_custom_verify, FN_SSL_CTX_SET_CUSTOM_VERIFY, boringssl_custom_verify)

BYPASS_RETURN(X509_verify_cert, int, 1)

BYPASS_RETURN(SSL_get_verify_result, long, X509_V_OK)

BYPASS_LOAD_CALL_VOID2(SSL_set_verify_result, FN_SSL_SET_VERIFY_RESULT, long, 0L)

BYPASS_LOAD_CALL_VOID2(SSL_set_verify_mode, FN_SSL_SET_VERIFY_MODE, int, 0)

BYPASS_VOID2(SSL_set_verify_depth, int)

BYPASS_VOID2(SSL_CTX_set_verify_depth, int)

BYPASS_RETURN2(SSL_set1_host, int, const char*, 1)

BYPASS_RETURN2(SSL_add1_host, int, const char*, 1)

BYPASS_VOID2(SSL_set_hostflags, unsigned int)

BYPASS_RETURN3(SSL_CTX_load_verify_locations, int, const char*, const char*, 1)

BYPASS_RETURN(SSL_CTX_set_default_verify_paths, int, 1)

BYPASS_LOAD_CALL_VOID2(X509_STORE_CTX_set_error, FN_X509_STORE_CTX_SET_ERROR, int, 0)

BYPASS_VOID2(X509_STORE_CTX_set_current_cert, void*)

BYPASS_RETURN2(X509_STORE_set_flags, int, unsigned long, 1)

BYPASS_RETURN5_NULLIFY(X509_check_host, int, const char*, size_t, unsigned int, char**, 1)

BYPASS_RETURN4(X509_check_email, int, const char*, size_t, unsigned int, 1)

BYPASS_RETURN4(X509_check_ip, int, const unsigned char*, size_t, unsigned int, 1)

BYPASS_RETURN3(X509_check_ip_asc, int, const char*, unsigned int, 1)

BYPASS_RETURN3(X509_VERIFY_PARAM_set1_host, int, const char*, size_t, 1)

BYPASS_RETURN2(X509_VERIFY_PARAM_set_hostflags, int, unsigned int, 1)

BYPASS_RETURN(SSL_get_verify_mode, int, SSL_VERIFY_NONE)

/* =========================== GnuTLS Hooks =========================== */

BYPASS_LOAD_CALL_VOID2(gnutls_certificate_set_verify_function, FN_GNUTLS_CERT_SET_VERIFY_FN, void*, (void*)gnutls_verify_cb)

BYPASS_RETURN_STATUS2(gnutls_certificate_verify_peers2, unsigned int*)

BYPASS_RETURN_STATUS3(gnutls_certificate_verify_peers3, const char*, unsigned int*)

BYPASS_VOID3(gnutls_session_set_verify_cert, const char*, unsigned)

BYPASS_VOID4(gnutls_session_set_verify_cert2, void*, unsigned, unsigned)

BYPASS_RETURN3(gnutls_certificate_set_x509_trust_file, int, const char*, int, 0)

BYPASS_RETURN3(gnutls_certificate_set_x509_trust_mem, int, const void*, int, 0)

BYPASS_VOID3(gnutls_certificate_set_verify_limits, unsigned int, unsigned int)

time_t gnutls_x509_crt_get_expiration_time(void *cert) {
    debug_log("gnutls_x509_crt_get_expiration_time: intercept");
    print_backtrace("gnutls_x509_crt_get_expiration_time");
    
    time_t (*real)(void*) = (time_t (*)(void*))
        LOAD_FN(FN_GNUTLS_X509_GET_EXPIRY, "gnutls_x509_crt_get_expiration_time");
    
    time_t result = (time_t)-1;
    if (real && cert) {
        result = real(cert);
        if (result != (time_t)-1 && result < time(NULL)) {
            debug_log("gnutls_x509_crt_get_expiration_time: bypass expired");
            return time(NULL) + 86400;
        }
    }
    return result;
}

time_t gnutls_x509_crt_get_activation_time(void *cert) {
    debug_log("gnutls_x509_crt_get_activation_time: intercept");
    print_backtrace("gnutls_x509_crt_get_activation_time");
    
    time_t (*real)(void*) = (time_t (*)(void*))
        LOAD_FN(FN_GNUTLS_X509_GET_ACTIVATION, "gnutls_x509_crt_get_activation_time");
    
    time_t result = (time_t)-1;
    if (real && cert) {
        result = real(cert);
        if (result != (time_t)-1 && result > time(NULL)) {
            debug_log("gnutls_x509_crt_get_activation_time: bypass");
            return 0;
        }
    }
    return result;
}

/* =========================== NSS Hooks =========================== */

BYPASS_LOAD_CALL_CB(SSL_AuthCertificateHook, FN_SSL_AUTH_CERT_HOOK, nss_auth_cb)

BYPASS_LOAD_CALL_CB(SSL_BadCertHook, FN_SSL_BAD_CERT_HOOK, nss_bad_cb)

BYPASS_RETURN5(CERT_VerifyCertNow, int, void*, int, void*, void*, 0)

BYPASS_RETURN7(CERT_VerifyCert, int, void*, int, int, long long, void*, void*, 0)

BYPASS_RETURN8_SPECIAL(CERT_VerifyCertificate, int, void*, int, int, long long, void*, void*, int*)

BYPASS_RETURN2(SSL_SetTrustAnchors, int, void*, 0)

/* =========================== mbedTLS Hooks =========================== */

BYPASS_LOAD_CALL_VOID2(mbedtls_ssl_conf_authmode, FN_MBEDTLS_SSL_CONF_AUTHMODE, int, 0)

BYPASS_LOAD_CALL_CB_TYPED(mbedtls_ssl_conf_verify, FN_MBEDTLS_SSL_CONF_VERIFY, mbedtls_verify_cb, mbedtls_verify_callback_t)

BYPASS_RETURN2(mbedtls_ssl_set_hostname, int, const char*, 0)

BYPASS_RETURN(mbedtls_ssl_get_verify_result, unsigned int, 0)

BYPASS_VOID3(mbedtls_ssl_conf_ca_chain, void*, void*)

int mbedtls_x509_crt_verify(void *crt, void *trust_ca, void *ca_crl, const char *cn, 
                           unsigned int *flags, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_x509_crt_verify: bypass");
    print_backtrace("mbedtls_x509_crt_verify");
    if (flags) *flags = 0;
    return 0;
}

int mbedtls_x509_crt_verify_with_profile(void *crt, void *trust_ca, void *ca_crl, void *profile,
                                         const char *cn, unsigned int *flags, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_x509_crt_verify_with_profile: bypass");
    print_backtrace("mbedtls_x509_crt_verify_with_profile");
    if (flags) *flags = 0;
    return 0;
}

/* =========================== wolfSSL Hooks =========================== */

BYPASS_LOAD_CALL_VOID3(wolfSSL_CTX_set_verify, FN_WOLFSSL_CTX_SET_VERIFY, int, void*, 0, NULL)

BYPASS_LOAD_CALL_VOID3(wolfSSL_set_verify, FN_WOLFSSL_SET_VERIFY, int, void*, 0, NULL)

BYPASS_VOID2(wolfSSL_set_verify_depth, int)

BYPASS_RETURN2(wolfSSL_check_domain_name, int, const char*, 1)

BYPASS_RETURN(wolfSSL_get_verify_result, long, 0)

/* wolfSSL extensions */
BYPASS_RETURN3(wolfSSL_CTX_load_verify_locations, int, const char*, const char*, 1)

BYPASS_RETURN3(wolfSSL_CTX_trust_peer_cert, int, const char*, int, 1)

/* =========================== libcurl Hooks =========================== */

/* curl option constants */
#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_SSL_VERIFYHOST 81
#define CURLOPT_SSL_VERIFYSTATUS 232
#define CURLOPT_PROXY_SSL_VERIFYPEER 248
#define CURLOPT_PROXY_SSL_VERIFYHOST 249
#define CURLOPT_PINNEDPUBLICKEY 230
#define CURLOPT_PROXY_PINNEDPUBLICKEY 263
#define CURLOPT_DOH_SSL_VERIFYPEER 306
#define CURLOPT_DOH_SSL_VERIFYHOST 307
#define CURLOPT_DOH_SSL_VERIFYSTATUS 308
#define CURLINFO_SSL_VERIFYRESULT 0x200025
#define CURLINFO_PROXY_SSL_VERIFYRESULT 0x2000BF

/* curl error codes */
#define CURLE_OK 0
#define CURLE_FAILED_INIT 2
#define CURLE_BAD_FUNCTION_ARGUMENT 43

void *curl_easy_init(void) {
    debug_log("curl_easy_init: intercept");
    print_backtrace("curl_easy_init");
    
    void *(*real)(void) = (void *(*)(void))portable_dlsym("curl_easy_init");
    if (!real) return NULL;
    
    void *handle = real();
    if (handle) {
        debug_logf("curl_easy_init: handle %p", handle);
        void *setopt = portable_dlsym("curl_easy_setopt");
        if (setopt) {
            ((int (*)(void*, int, ...))setopt)(handle, CURLOPT_SSL_VERIFYPEER, 0L);
            ((int (*)(void*, int, ...))setopt)(handle, CURLOPT_SSL_VERIFYHOST, 0L);
        }
    }
    return handle;
}

int curl_easy_setopt(void *curl, int option, ...) {
    va_list args;
    int result;
    
    if (!curl) return CURLE_BAD_FUNCTION_ARGUMENT;
    
    /* Only trace important SSL options */
    if (option == CURLOPT_SSL_VERIFYPEER || option == CURLOPT_SSL_VERIFYHOST) {
        debug_log("curl_easy_setopt: bypass");
        print_backtrace("curl_easy_setopt");
    }
    
    curl_setopt_func_t real = (curl_setopt_func_t)
        LOAD_FN(FN_CURL_EASY_SETOPT, "curl_easy_setopt");
    if (!real) return CURLE_FAILED_INIT;
    
    va_start(args, option);
    
    switch (option) {
        case CURLOPT_SSL_VERIFYPEER:
        case CURLOPT_SSL_VERIFYHOST:
        case CURLOPT_SSL_VERIFYSTATUS:
        case CURLOPT_PROXY_SSL_VERIFYPEER:
        case CURLOPT_PROXY_SSL_VERIFYHOST:
        case CURLOPT_DOH_SSL_VERIFYPEER:
        case CURLOPT_DOH_SSL_VERIFYHOST:
        case CURLOPT_DOH_SSL_VERIFYSTATUS:
            result = real(curl, option, 0L);
            break;
            
        case CURLOPT_PINNEDPUBLICKEY:
        case CURLOPT_PROXY_PINNEDPUBLICKEY:
            debug_log("curl_easy_setopt: bypass");
            result = real(curl, option, NULL);
            break;
            
        default:
            result = real(curl, option, va_arg(args, void*));
            break;
    }
    
    va_end(args);
    return result;
}

int curl_easy_getinfo(void *curl, int info, ...) {
    va_list args;
    int result;
    
    if (!curl) return CURLE_BAD_FUNCTION_ARGUMENT;
    
    curl_getinfo_func_t real = (curl_getinfo_func_t)
        LOAD_FN(FN_CURL_EASY_GETINFO, "curl_easy_getinfo");
    if (!real) return CURLE_FAILED_INIT;
    
    va_start(args, info);
    
    if (info == CURLINFO_SSL_VERIFYRESULT || info == CURLINFO_PROXY_SSL_VERIFYRESULT) {
        long *result_ptr = va_arg(args, long*);
        debug_log("curl_easy_getinfo: bypass");
        print_backtrace("curl_easy_getinfo");
        if (result_ptr) *result_ptr = 0;
        result = CURLE_OK;
    } else {
        void *arg = va_arg(args, void*);
        result = real(curl, info, arg);
    }
    
    va_end(args);
    return result;
}

/* =========================== Initialization =========================== */

static int g_initialized = 0;

static void init_library(void) {
    if (!g_initialized) {
        LOCK();
        if (!g_initialized) {
            g_initialized = 1;
            debug_logf("TLS verification bypass initialized (commit %s)", __GIT_COMMIT__);
            
#if defined(PLATFORM_LINUX)
            debug_logf("Platform: Linux, TID support: %s", get_thread_id() ? "yes" : "no");
#elif defined(PLATFORM_FREEBSD)
            debug_log("Platform: FreeBSD");
#elif defined(PLATFORM_OPENBSD)
            debug_log("Platform: OpenBSD");
#elif defined(PLATFORM_NETBSD)
            debug_log("Platform: NetBSD");
#elif defined(PLATFORM_SOLARIS)
            debug_log("Platform: Solaris");
#elif defined(PLATFORM_AIX)
            debug_log("Platform: AIX");
#elif defined(PLATFORM_MACOS)
            debug_log("Platform: macOS");
#else
            debug_log("Platform: Unknown");
#endif
        }
        UNLOCK();
    }
}

/* Library constructor */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((constructor))
    static void lib_init(void) {
        init_library();
    }
#elif defined(__SUNPRO_C)
    #pragma init(lib_init)
    static void lib_init(void) {
        init_library();
    }
#endif

/* Library destructor */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((destructor))
    static void lib_cleanup(void) {
        debug_log("TLS verification bypass cleanup");
        
        /* Reset state */
        LOCK();
        for (int i = 0; i < FN_MAX; i++) {
            g_real_funcs[i] = NULL;
        }
        g_initialized = 0;
        g_debug = -1;
        g_backtrace = -1;
        UNLOCK();
    }
#endif