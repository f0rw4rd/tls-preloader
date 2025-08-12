/* Universal TLS certificate verification bypass library
 * Supports: Linux, FreeBSD, OpenBSD, NetBSD, Solaris, AIX, macOS
 * Compatible with: OpenSSL, BoringSSL, LibreSSL, GnuTLS, NSS, mbedTLS, wolfSSL, curl
 */

/* Platform detection and feature macros */
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

/* =========================== Thread Safety =========================== */

/* Choose thread safety mechanism based on platform */
#if defined(PLATFORM_LINUX) && !defined(__ANDROID__)
    /* Linux: Use futex for best performance */
    #include <sys/syscall.h>
    #include <linux/futex.h>
    #include <pthread.h>
    
    static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    #define LOCK() pthread_mutex_lock(&g_mutex)
    #define UNLOCK() pthread_mutex_unlock(&g_mutex)
    
#elif defined(PLATFORM_SOLARIS)
    /* Solaris: Use atomic operations */
    #include <atomic.h>
    #include <sched.h>
    
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
    /* BSD/macOS: Use pthread */
    #include <pthread.h>
    
    static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
    #define LOCK() pthread_mutex_lock(&g_mutex)
    #define UNLOCK() pthread_mutex_unlock(&g_mutex)
    
#elif defined(PLATFORM_OPENBSD)
    /* OpenBSD: Use simple atomics */
    #include <sys/atomic.h>
    
    static volatile unsigned int g_mutex = 0;
    
    static void LOCK(void) {
        while (atomic_swap_uint(&g_mutex, 1) != 0) {
            sched_yield();
        }
    }
    
    static void UNLOCK(void) {
        atomic_swap_uint(&g_mutex, 0);
    }
    
#else
    /* Fallback: Use GCC builtins if available */
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
        /* No thread safety */
        #define LOCK() (void)0
        #define UNLOCK() (void)0
    #endif
#endif

/* =========================== Core Infrastructure =========================== */

/* Debug logging */
static int g_debug = -1;

static void debug_log(const char *msg) {
    if (g_debug == -1) {
        const char *env = getenv("TLS_NOVERIFY_DEBUG");
        g_debug = (env && *env != '\0');
    }
    if (g_debug) {
        const char prefix[] = "[TLS_NOVERIFY] ";
        ssize_t ret;
        ret = write(2, prefix, sizeof(prefix) - 1);
        ret = write(2, msg, strlen(msg));
        ret = write(2, "\n", 1);
        (void)ret; /* Silence unused variable warning */
    }
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
    
    /* Get our own address to check if we're trying to load ourselves */
    void *our_addr = dlsym(RTLD_DEFAULT, symbol);
    
#if defined(PLATFORM_SOLARIS)
    /* Solaris: Try RTLD_PROBE first */
    #ifdef RTLD_PROBE
        sym = dlsym(RTLD_PROBE, symbol);
    #endif
    if (!sym) sym = dlsym(RTLD_NEXT, symbol);
    if (!sym) sym = dlsym(RTLD_DEFAULT, symbol);
#else
    /* Standard approach */
    sym = dlsym(RTLD_NEXT, symbol);
    if (!sym) sym = dlsym(NULL, symbol);
#endif
    
    /* If RTLD_NEXT returns our own function, return NULL to prevent recursion */
    if (sym == our_addr) {
        debug_log("portable_dlsym: detected self-reference, returning NULL");
        return NULL;
    }
    
    return sym;
}

/* Thread-safe function loading with caching */
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

/* Convenience macros */
#define LOAD_FN(id, name) load_func(id, name)

/* Function generator macros */
/* Simple bypass that returns a constant */
#define BYPASS_RETURN(name, ret_type, ret_val) \
ret_type name(void *arg) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with two args returning constant */
#define BYPASS_RETURN2(name, ret_type, arg2_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with three args returning constant */
#define BYPASS_RETURN3(name, ret_type, arg2_type, arg3_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with four args returning constant */
#define BYPASS_RETURN4(name, ret_type, arg2_type, arg3_type, arg4_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with five args returning constant */
#define BYPASS_RETURN5(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with seven args returning constant (for NSS functions) */
#define BYPASS_RETURN7(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, arg6_type, arg7_type, ret_val) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, \
              arg5_type arg5, arg6_type arg6, arg7_type arg7) { \
    debug_log(#name ": bypass"); \
    return ret_val; \
}

/* Bypass with eight args returning constant with special handling */
#define BYPASS_RETURN8_SPECIAL(name, ret_type, arg2_type, arg3_type, arg4_type, arg5_type, arg6_type, arg7_type, arg8_type) \
ret_type name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, \
              arg5_type arg5, arg6_type arg6, arg7_type arg7, arg8_type arg8) { \
    debug_log(#name ": bypass"); \
    if (arg8) *arg8 = arg4; \
    return 0; \
}

/* Void bypass with four args */
#define BYPASS_VOID4(name, arg2_type, arg3_type, arg4_type) \
void name(void *arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
    debug_log(#name ": bypass"); \
}

/* Simple void bypass */
#define BYPASS_VOID(name) \
void name(void *arg) { \
    debug_log(#name ": bypass"); \
}

/* Void bypass with two args */
#define BYPASS_VOID2(name, arg2_type) \
void name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
}

/* Void bypass with three args */
#define BYPASS_VOID3(name, arg2_type, arg3_type) \
void name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
}

/* Bypass that loads and calls real function with modified args */
#define BYPASS_LOAD_CALL_VOID2(name, fn_id, arg2_type, new_arg2) \
void name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    void (*real)(void*, arg2_type) = (void (*)(void*, arg2_type)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, new_arg2); \
}

/* Bypass that loads and calls real function with modified args (3 args) */
#define BYPASS_LOAD_CALL_VOID3(name, fn_id, arg2_type, arg3_type, new_arg2, new_arg3) \
void name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    void (*real)(void*, arg2_type, arg3_type) = (void (*)(void*, arg2_type, arg3_type)) \
        LOAD_FN(fn_id, #name); \
    if (real) real(arg1, new_arg2, new_arg3); \
}

/* Special bypass for functions that return 0 and set status pointer (2 args) */
#define BYPASS_RETURN_STATUS2(name, arg2_type) \
int name(void *arg1, arg2_type arg2) { \
    debug_log(#name ": bypass"); \
    if (arg2) *arg2 = 0; \
    return 0; \
}

/* Special bypass for functions that return 0 and set status pointer (3 args) */
#define BYPASS_RETURN_STATUS3(name, arg2_type, arg3_type) \
int name(void *arg1, arg2_type arg2, arg3_type arg3) { \
    debug_log(#name ": bypass"); \
    if (arg3) *arg3 = 0; \
    return 0; \
}

/* Bypass that loads and calls real function with callback replacement */
#define BYPASS_LOAD_CALL_CB(name, fn_id, callback) \
int name(void *arg1, void *arg2, void *arg3) { \
    debug_log(#name ": bypass"); \
    int (*real)(void*, void*, void*) = (int (*)(void*, void*, void*)) \
        LOAD_FN(fn_id, #name); \
    if (real) return real(arg1, callback, arg3); \
    return 0; \
}

/* =========================== Callback Functions =========================== */

/* OpenSSL callbacks */
static int openssl_verify_cb(void *store_ctx, void *arg) {
    debug_log("OpenSSL verify callback: bypass");
    return 1;
}


/* BoringSSL callback */
static int boringssl_custom_verify(void *ssl, unsigned char *out_alert) {
    debug_log("BoringSSL custom verify: bypass");
    return 0; /* ssl_verify_ok */
}

/* GnuTLS callback */
static int gnutls_verify_cb(void *session) {
    debug_log("GnuTLS verify: bypass");
    return 0;
}

/* NSS callbacks */
static int nss_auth_cb(void *arg, void *fd, int checkSig, int isServer) {
    debug_log("NSS auth: bypass");
    return 0; /* SECSuccess */
}

static int nss_bad_cb(void *arg, void *fd) {
    debug_log("NSS bad cert: bypass");
    return 0; /* SECSuccess */
}

/* mbedTLS callback */
static int mbedtls_verify_cb(void *p_vrfy, void *crt, int depth, unsigned int *flags) {
    debug_log("mbedTLS verify: bypass");
    if (flags) *flags = 0;
    return 0;
}

/* wolfSSL callback */
static int wolfssl_verify_cb(int preverify_ok, void *ctx) {
    debug_log("wolfSSL verify: bypass");
    return 1;
}

/* =========================== OpenSSL/BoringSSL/LibreSSL Hooks =========================== */

BYPASS_LOAD_CALL_VOID3(SSL_CTX_set_verify, FN_SSL_CTX_SET_VERIFY, int, void*, 0, NULL)

BYPASS_LOAD_CALL_VOID3(SSL_set_verify, FN_SSL_SET_VERIFY, int, void*, 0, NULL)

void SSL_CTX_set_cert_verify_callback(void *ctx, void *cb, void *arg) {
    debug_log("SSL_CTX_set_cert_verify_callback: bypass");
    void (*real)(void*, int (*)(void*, void*), void*) = (void (*)(void*, int (*)(void*, void*), void*))
        LOAD_FN(FN_SSL_CTX_SET_CERT_VERIFY_CB, "SSL_CTX_set_cert_verify_callback");
    if (real) real(ctx, openssl_verify_cb, arg);
}

void SSL_CTX_set_custom_verify(void *ctx, int mode, void *cb) {
    debug_log("SSL_CTX_set_custom_verify: bypass");
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*))
        LOAD_FN(FN_SSL_CTX_SET_CUSTOM_VERIFY, "SSL_CTX_set_custom_verify");
    if (real) real(ctx, mode, boringssl_custom_verify);
}

BYPASS_RETURN(X509_verify_cert, int, 1)

BYPASS_RETURN(SSL_get_verify_result, long, 0L) /* X509_V_OK */

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

int X509_check_host(void *x, const char *chk, size_t chklen, unsigned int flags, char **peername) {
    debug_log("X509_check_host: bypass");
    if (peername) *peername = NULL;
    return 1;
}

BYPASS_RETURN4(X509_check_email, int, const char*, size_t, unsigned int, 1)

BYPASS_RETURN4(X509_check_ip, int, const unsigned char*, size_t, unsigned int, 1)

BYPASS_RETURN3(X509_check_ip_asc, int, const char*, unsigned int, 1)

BYPASS_RETURN3(X509_VERIFY_PARAM_set1_host, int, const char*, size_t, 1)

BYPASS_RETURN2(X509_VERIFY_PARAM_set_hostflags, int, unsigned int, 1)

BYPASS_RETURN(SSL_get_verify_mode, int, 0) /* SSL_VERIFY_NONE */

/* =========================== GnuTLS Hooks =========================== */

void gnutls_certificate_set_verify_function(void *cred, void *func) {
    debug_log("gnutls_certificate_set_verify_function: bypass");
    void (*real)(void*, void*) = (void (*)(void*, void*))
        LOAD_FN(FN_GNUTLS_CERT_SET_VERIFY_FN, "gnutls_certificate_set_verify_function");
    if (real) real(cred, (void*)gnutls_verify_cb);
}

BYPASS_RETURN_STATUS2(gnutls_certificate_verify_peers2, unsigned int*)

BYPASS_RETURN_STATUS3(gnutls_certificate_verify_peers3, const char*, unsigned int*)

BYPASS_VOID3(gnutls_session_set_verify_cert, const char*, unsigned)

BYPASS_VOID4(gnutls_session_set_verify_cert2, void*, unsigned, unsigned)

BYPASS_RETURN3(gnutls_certificate_set_x509_trust_file, int, const char*, int, 0)

BYPASS_RETURN3(gnutls_certificate_set_x509_trust_mem, int, const void*, int, 0)

BYPASS_VOID3(gnutls_certificate_set_verify_limits, unsigned int, unsigned int)

time_t gnutls_x509_crt_get_expiration_time(void *cert) {
    time_t (*real)(void*) = (time_t (*)(void*))
        LOAD_FN(FN_GNUTLS_X509_GET_EXPIRY, "gnutls_x509_crt_get_expiration_time");
    
    time_t result = (time_t)-1;
    if (real && cert) {
        result = real(cert);
        if (result != (time_t)-1 && result < time(NULL)) {
            debug_log("gnutls_x509_crt_get_expiration_time: bypass expired");
            return time(NULL) + 86400; /* Tomorrow */
        }
    }
    return result;
}

time_t gnutls_x509_crt_get_activation_time(void *cert) {
    time_t (*real)(void*) = (time_t (*)(void*))
        LOAD_FN(FN_GNUTLS_X509_GET_ACTIVATION, "gnutls_x509_crt_get_activation_time");
    
    time_t result = (time_t)-1;
    if (real && cert) {
        result = real(cert);
        if (result != (time_t)-1 && result > time(NULL)) {
            debug_log("gnutls_x509_crt_get_activation_time: bypass not-yet-valid");
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

void mbedtls_ssl_conf_verify(void *conf, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_ssl_conf_verify: bypass");
    void (*real)(void*, int (*)(void*, void*, int, unsigned int*), void*) = 
        (void (*)(void*, int (*)(void*, void*, int, unsigned int*), void*))
        LOAD_FN(FN_MBEDTLS_SSL_CONF_VERIFY, "mbedtls_ssl_conf_verify");
    if (real) real(conf, mbedtls_verify_cb, NULL);
}

BYPASS_RETURN2(mbedtls_ssl_set_hostname, int, const char*, 0)

BYPASS_RETURN(mbedtls_ssl_get_verify_result, unsigned int, 0)

BYPASS_VOID3(mbedtls_ssl_conf_ca_chain, void*, void*)

int mbedtls_x509_crt_verify(void *crt, void *trust_ca, void *ca_crl, const char *cn, 
                           unsigned int *flags, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_x509_crt_verify: bypass");
    if (flags) *flags = 0;
    return 0;
}

int mbedtls_x509_crt_verify_with_profile(void *crt, void *trust_ca, void *ca_crl, void *profile,
                                         const char *cn, unsigned int *flags, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_x509_crt_verify_with_profile: bypass");
    if (flags) *flags = 0;
    return 0;
}

/* =========================== wolfSSL Hooks =========================== */

void wolfSSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    debug_log("wolfSSL_CTX_set_verify: bypass");
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*))
        LOAD_FN(FN_WOLFSSL_CTX_SET_VERIFY, "wolfSSL_CTX_set_verify");
    if (real) real(ctx, mode, mode ? wolfssl_verify_cb : NULL);
}

void wolfSSL_set_verify(void *ssl, int mode, void *cb) {
    debug_log("wolfSSL_set_verify: bypass");
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*))
        LOAD_FN(FN_WOLFSSL_SET_VERIFY, "wolfSSL_set_verify");
    if (real) real(ssl, mode, mode ? wolfssl_verify_cb : NULL);
}

BYPASS_VOID2(wolfSSL_set_verify_depth, int)

BYPASS_RETURN2(wolfSSL_check_domain_name, int, const char*, 1)

BYPASS_RETURN(wolfSSL_get_verify_result, long, 0)

/* Additional wolfSSL functions from user's request */
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

void *curl_easy_init(void) {
    void *(*real)(void) = (void *(*)(void))portable_dlsym("curl_easy_init");
    if (!real) return NULL;
    
    void *handle = real();
    if (handle) {
        debug_log("curl_easy_init: new handle, disabling SSL verification");
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
    
    if (!curl) return 43; /* CURLE_BAD_FUNCTION_ARGUMENT */
    
    int (*real)(void*, int, ...) = (int (*)(void*, int, ...))
        LOAD_FN(FN_CURL_EASY_SETOPT, "curl_easy_setopt");
    if (!real) return 2; /* CURLE_FAILED_INIT */
    
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
            debug_log("curl_easy_setopt: SSL verify bypass");
            result = real(curl, option, 0L);
            break;
            
        case CURLOPT_PINNEDPUBLICKEY:
        case CURLOPT_PROXY_PINNEDPUBLICKEY:
            debug_log("curl_easy_setopt: PINNEDPUBLICKEY bypass");
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
    
    if (!curl) return 43; /* CURLE_BAD_FUNCTION_ARGUMENT */
    
    int (*real)(void*, int, ...) = (int (*)(void*, int, ...))
        LOAD_FN(FN_CURL_EASY_GETINFO, "curl_easy_getinfo");
    if (!real) return 2; /* CURLE_FAILED_INIT */
    
    va_start(args, info);
    
    if (info == CURLINFO_SSL_VERIFYRESULT || info == CURLINFO_PROXY_SSL_VERIFYRESULT) {
        long *result_ptr = va_arg(args, long*);
        debug_log("curl_easy_getinfo: SSL_VERIFYRESULT bypass");
        if (result_ptr) *result_ptr = 0;
        result = 0; /* CURLE_OK */
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
            debug_log("TLS verification bypass initialized (unified version)");
            
            /* Platform detection logging */
#if defined(PLATFORM_LINUX)
            debug_log("Platform: Linux");
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

/* Constructor where supported */
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
#elif defined(_MSC_VER)
    /* MSVC support if ever needed */
    #pragma section(".CRT$XCU",read)
    __declspec(allocate(".CRT$XCU")) 
    static void (*p_lib_init)(void) = lib_init;
    static void lib_init(void) {
        init_library();
    }
#endif

/* Destructor for cleanup */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((destructor))
    static void lib_cleanup(void) {
        debug_log("TLS verification bypass cleanup");
    }
#endif