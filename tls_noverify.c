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

void SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    debug_log("SSL_CTX_set_verify: bypass");
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*))
        LOAD_FN(FN_SSL_CTX_SET_VERIFY, "SSL_CTX_set_verify");
    if (real) real(ctx, 0, NULL);
}

void SSL_set_verify(void *ssl, int mode, void *cb) {
    debug_log("SSL_set_verify: bypass");
    void (*real)(void*, int, void*) = (void (*)(void*, int, void*))
        LOAD_FN(FN_SSL_SET_VERIFY, "SSL_set_verify");
    if (real) real(ssl, 0, NULL);
}

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

int X509_verify_cert(void *ctx) {
    debug_log("X509_verify_cert: bypass");
    return 1;
}

long SSL_get_verify_result(const void *ssl) {
    debug_log("SSL_get_verify_result: bypass");
    return 0L; /* X509_V_OK */
}

void SSL_set_verify_result(void *ssl, long result) {
    debug_log("SSL_set_verify_result: bypass");
    void (*real)(void*, long) = (void (*)(void*, long))
        LOAD_FN(FN_SSL_SET_VERIFY_RESULT, "SSL_set_verify_result");
    if (real) real(ssl, 0L);
}

void SSL_set_verify_mode(void *ssl, int mode) {
    debug_log("SSL_set_verify_mode: bypass");
    void (*real)(void*, int) = (void (*)(void*, int))
        LOAD_FN(FN_SSL_SET_VERIFY_MODE, "SSL_set_verify_mode");
    if (real) real(ssl, 0);
}

void SSL_set_verify_depth(void *ssl, int depth) {
    debug_log("SSL_set_verify_depth: bypass");
}

void SSL_CTX_set_verify_depth(void *ctx, int depth) {
    debug_log("SSL_CTX_set_verify_depth: bypass");
}

int SSL_set1_host(void *ssl, const char *hostname) {
    debug_log("SSL_set1_host: bypass");
    return 1;
}

int SSL_add1_host(void *ssl, const char *hostname) {
    debug_log("SSL_add1_host: bypass");
    return 1;
}

void SSL_set_hostflags(void *ssl, unsigned int flags) {
    debug_log("SSL_set_hostflags: bypass");
}

int SSL_CTX_load_verify_locations(void *ctx, const char *file, const char *path) {
    debug_log("SSL_CTX_load_verify_locations: bypass");
    return 1;
}

int SSL_CTX_set_default_verify_paths(void *ctx) {
    debug_log("SSL_CTX_set_default_verify_paths: bypass");
    return 1;
}

void X509_STORE_CTX_set_error(void *ctx, int err) {
    debug_log("X509_STORE_CTX_set_error: bypass");
    void (*real)(void*, int) = (void (*)(void*, int))
        LOAD_FN(FN_X509_STORE_CTX_SET_ERROR, "X509_STORE_CTX_set_error");
    if (real) real(ctx, 0);
}

void X509_STORE_CTX_set_current_cert(void *ctx, void *x) {
    debug_log("X509_STORE_CTX_set_current_cert: bypass");
}

int X509_STORE_set_flags(void *ctx, unsigned long flags) {
    debug_log("X509_STORE_set_flags: bypass");
    return 1;
}

int X509_check_host(void *x, const char *chk, size_t chklen, unsigned int flags, char **peername) {
    debug_log("X509_check_host: bypass");
    if (peername) *peername = NULL;
    return 1;
}

int X509_check_email(void *x, const char *addr, size_t addrlen, unsigned int flags) {
    debug_log("X509_check_email: bypass");
    return 1;
}

int X509_check_ip(void *x, const unsigned char *addr, size_t addrlen, unsigned int flags) {
    debug_log("X509_check_ip: bypass");
    return 1;
}

int X509_check_ip_asc(void *x, const char *ipasc, unsigned int flags) {
    debug_log("X509_check_ip_asc: bypass");
    return 1;
}

int X509_VERIFY_PARAM_set1_host(void *param, const char *name, size_t namelen) {
    debug_log("X509_VERIFY_PARAM_set1_host: bypass");
    return 1;
}

int X509_VERIFY_PARAM_set_hostflags(void *param, unsigned int flags) {
    debug_log("X509_VERIFY_PARAM_set_hostflags: bypass");
    return 1;
}

int SSL_get_verify_mode(const void *ssl) {
    debug_log("SSL_get_verify_mode: bypass");
    return 0; /* SSL_VERIFY_NONE */
}

/* =========================== GnuTLS Hooks =========================== */

void gnutls_certificate_set_verify_function(void *cred, void *func) {
    debug_log("gnutls_certificate_set_verify_function: bypass");
    void (*real)(void*, void*) = (void (*)(void*, void*))
        LOAD_FN(FN_GNUTLS_CERT_SET_VERIFY_FN, "gnutls_certificate_set_verify_function");
    if (real) real(cred, (void*)gnutls_verify_cb);
}

int gnutls_certificate_verify_peers2(void *session, unsigned int *status) {
    debug_log("gnutls_certificate_verify_peers2: bypass");
    if (status) *status = 0;
    return 0;
}

int gnutls_certificate_verify_peers3(void *session, const char *hostname, unsigned int *status) {
    debug_log("gnutls_certificate_verify_peers3: bypass");
    if (status) *status = 0;
    return 0;
}

void gnutls_session_set_verify_cert(void *session, const char *hostname, unsigned flags) {
    debug_log("gnutls_session_set_verify_cert: bypass");
}

void gnutls_session_set_verify_cert2(void *session, void *data, unsigned elements, unsigned flags) {
    debug_log("gnutls_session_set_verify_cert2: bypass");
}

int gnutls_certificate_set_x509_trust_file(void *cred, const char *cafile, int type) {
    debug_log("gnutls_certificate_set_x509_trust_file: bypass");
    return 0;
}

int gnutls_certificate_set_x509_trust_mem(void *cred, const void *ca, int type) {
    debug_log("gnutls_certificate_set_x509_trust_mem: bypass");
    return 0;
}

void gnutls_certificate_set_verify_limits(void *res, unsigned int max_bits, unsigned int max_depth) {
    debug_log("gnutls_certificate_set_verify_limits: bypass");
}

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

int SSL_AuthCertificateHook(void *fd, void *f, void *arg) {
    debug_log("SSL_AuthCertificateHook: bypass");
    int (*real)(void*, void*, void*) = (int (*)(void*, void*, void*))
        LOAD_FN(FN_SSL_AUTH_CERT_HOOK, "SSL_AuthCertificateHook");
    if (real) return real(fd, nss_auth_cb, arg);
    return 0;
}

int SSL_BadCertHook(void *fd, void *f, void *arg) {
    debug_log("SSL_BadCertHook: bypass");
    int (*real)(void*, void*, void*) = (int (*)(void*, void*, void*))
        LOAD_FN(FN_SSL_BAD_CERT_HOOK, "SSL_BadCertHook");
    if (real) return real(fd, nss_bad_cb, arg);
    return 0;
}

int CERT_VerifyCertNow(void *handle, void *cert, int checkSig, void *pwarg, void *usage) {
    debug_log("CERT_VerifyCertNow: bypass");
    return 0;
}

int CERT_VerifyCert(void *handle, void *cert, int checkSig, int certUsage, 
                    long long time, void *wincx, void *log) {
    debug_log("CERT_VerifyCert: bypass");
    return 0;
}

int CERT_VerifyCertificate(void *handle, void *cert, int checkSig, int requiredUsages, 
                          long long time, void *wincx, void *log, int *returnedUsages) {
    debug_log("CERT_VerifyCertificate: bypass");
    if (returnedUsages) *returnedUsages = requiredUsages;
    return 0;
}

int SSL_SetTrustAnchors(void *fd, void *list) {
    debug_log("SSL_SetTrustAnchors: bypass");
    return 0;
}

/* =========================== mbedTLS Hooks =========================== */

void mbedtls_ssl_conf_authmode(void *conf, int authmode) {
    debug_log("mbedtls_ssl_conf_authmode: bypass");
    void (*real)(void*, int) = (void (*)(void*, int))
        LOAD_FN(FN_MBEDTLS_SSL_CONF_AUTHMODE, "mbedtls_ssl_conf_authmode");
    if (real) real(conf, 0);
}

void mbedtls_ssl_conf_verify(void *conf, void *f_vrfy, void *p_vrfy) {
    debug_log("mbedtls_ssl_conf_verify: bypass");
    void (*real)(void*, int (*)(void*, void*, int, unsigned int*), void*) = 
        (void (*)(void*, int (*)(void*, void*, int, unsigned int*), void*))
        LOAD_FN(FN_MBEDTLS_SSL_CONF_VERIFY, "mbedtls_ssl_conf_verify");
    if (real) real(conf, mbedtls_verify_cb, NULL);
}

int mbedtls_ssl_set_hostname(void *ssl, const char *hostname) {
    debug_log("mbedtls_ssl_set_hostname: bypass");
    return 0;
}

unsigned int mbedtls_ssl_get_verify_result(const void *ssl) {
    debug_log("mbedtls_ssl_get_verify_result: bypass");
    return 0;
}

void mbedtls_ssl_conf_ca_chain(void *conf, void *ca_chain, void *ca_crl) {
    debug_log("mbedtls_ssl_conf_ca_chain: bypass");
}

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

void wolfSSL_set_verify_depth(void *ssl, int depth) {
    debug_log("wolfSSL_set_verify_depth: bypass");
}

int wolfSSL_check_domain_name(void *ssl, const char *dn) {
    debug_log("wolfSSL_check_domain_name: bypass");
    return 1;
}

long wolfSSL_get_verify_result(void *ssl) {
    debug_log("wolfSSL_get_verify_result: bypass");
    return 0;
}

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