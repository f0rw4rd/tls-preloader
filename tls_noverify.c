/* Portable TLS certificate verification bypass library
 * Compatible with old glibc, musl libc, and embedded systems
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* Avoid GNU-specific features for compatibility */
#ifdef __GLIBC__
#include <pthread.h>
#else
/* Simple mutex implementation for non-glibc systems */
static int g_initialized = 0;
#endif

/* Use simpler logging mechanism for embedded systems */
static int g_debug = 0;
static int g_log_fd = -1;

static void debug_write(const char *msg) {
    if (!g_debug || g_log_fd < 0) return;
    size_t len = 0;
    const char *p = msg;
    while (*p++) len++;
    write(g_log_fd, "[TLS_NOVERIFY] ", 15);
    write(g_log_fd, msg, len);
    write(g_log_fd, "\n", 1);
}

static void debug_write_ptr(const char *msg, const void *ptr) {
    if (!g_debug || g_log_fd < 0) return;
    char buf[256];
    int len = snprintf(buf, sizeof(buf), "%s %p", msg, ptr);
    if (len > 0 && len < (int)sizeof(buf)) {
        debug_write(buf);
    }
}

/* Initialize debugging */
static void init_debugging(void) {
    const char *debug_env = getenv("TLS_NOVERIFY_DEBUG");
    if (debug_env && *debug_env) {
        g_debug = 1;
        g_log_fd = 2; /* stderr */
        debug_write("Debug logging enabled");
    }
}

/* Initialize once - portable version */
static void init_once(void) {
#ifdef __GLIBC__
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, init_debugging);
#else
    if (!g_initialized) {
        g_initialized = 1;
        init_debugging();
    }
#endif
}

/* Function pointer types - minimal set for maximum compatibility */
typedef void (*SSL_CTX_set_verify_t)(void *ctx, int mode, void *callback);
typedef int (*X509_verify_cert_t)(void *ctx);
typedef long (*SSL_get_verify_result_t)(const void *ssl);
typedef void (*SSL_set_verify_result_t)(void *ssl, long result);

/* GnuTLS types */
typedef int (*gnutls_certificate_verify_function)(void *);
typedef void (*gnutls_certificate_set_verify_function_t)(void *, gnutls_certificate_verify_function *);
typedef int (*gnutls_certificate_verify_peers2_t)(void *, unsigned int *);

/* NSS types */
typedef int SECStatus;
#define SECSuccess 0
#define SECFailure -1
typedef SECStatus (*SSLAuthCertificate)(void *, void *, int, int);
typedef SECStatus (*SSLBadCertHandler)(void *, void *);
typedef SECStatus (*SSL_AuthCertificateHook_t)(void *, SSLAuthCertificate, void *);
typedef SECStatus (*SSL_BadCertHook_t)(void *, SSLBadCertHandler, void *);

/* mbedTLS types */
typedef void (*mbedtls_ssl_conf_authmode_t)(void *, int);

/* wolfSSL types */
typedef int (*VerifyCallback)(int, void *);
typedef void (*wolfSSL_CTX_set_verify_t)(void *, int, VerifyCallback);

/* Static storage for function pointers - avoid malloc for embedded systems */
static struct {
    SSL_CTX_set_verify_t SSL_CTX_set_verify;
    X509_verify_cert_t X509_verify_cert;
    SSL_get_verify_result_t SSL_get_verify_result;
    SSL_set_verify_result_t SSL_set_verify_result;
    gnutls_certificate_set_verify_function_t gnutls_certificate_set_verify_function;
    gnutls_certificate_verify_peers2_t gnutls_certificate_verify_peers2;
    SSL_AuthCertificateHook_t SSL_AuthCertificateHook;
    SSL_BadCertHook_t SSL_BadCertHook;
    mbedtls_ssl_conf_authmode_t mbedtls_ssl_conf_authmode;
    wolfSSL_CTX_set_verify_t wolfSSL_CTX_set_verify;
} real_funcs = {0};

/* Portable dlsym wrapper that works with old glibc */
static void *portable_dlsym(const char *symbol) {
    void *handle = RTLD_NEXT;
    void *func = NULL;
    
#ifdef RTLD_DEFAULT
    /* Try RTLD_DEFAULT first for better compatibility */
    func = dlsym(RTLD_DEFAULT, symbol);
    if (func) return func;
#endif
    
    /* Fall back to RTLD_NEXT */
    func = dlsym(handle, symbol);
    return func;
}

/* OpenSSL/BoringSSL hooks */
void SSL_CTX_set_verify(void *ctx, int mode, void *callback) {
    init_once();
    debug_write("SSL_CTX_set_verify: bypassing");
    
    if (!real_funcs.SSL_CTX_set_verify)
        real_funcs.SSL_CTX_set_verify = (SSL_CTX_set_verify_t)portable_dlsym("SSL_CTX_set_verify");
    
    if (real_funcs.SSL_CTX_set_verify)
        real_funcs.SSL_CTX_set_verify(ctx, 0, NULL);
}

int X509_verify_cert(void *ctx) {
    init_once();
    debug_write("X509_verify_cert: success");
    return 1;
}

long SSL_get_verify_result(const void *ssl) {
    init_once();
    debug_write("SSL_get_verify_result: OK");
    return 0;
}

void SSL_set_verify_result(void *ssl, long result) {
    init_once();
    debug_write("SSL_set_verify_result: forcing OK");
    
    if (!real_funcs.SSL_set_verify_result)
        real_funcs.SSL_set_verify_result = (SSL_set_verify_result_t)portable_dlsym("SSL_set_verify_result");
    
    if (real_funcs.SSL_set_verify_result)
        real_funcs.SSL_set_verify_result(ssl, 0);
}

/* BoringSSL specific - simplified */
void SSL_CTX_set_custom_verify(void *ctx, int mode, void *callback) {
    init_once();
    debug_write("SSL_CTX_set_custom_verify: bypassing");
    /* For BoringSSL, we just ignore custom verify */
}

/* GnuTLS hooks */
static int gnutls_bypass_verify(void *session) {
    debug_write("GnuTLS verify: success");
    return 0;
}

void gnutls_certificate_set_verify_function(void *cred, gnutls_certificate_verify_function *func) {
    init_once();
    debug_write("gnutls_certificate_set_verify_function: bypassing");
    
    if (!real_funcs.gnutls_certificate_set_verify_function)
        real_funcs.gnutls_certificate_set_verify_function = 
            (gnutls_certificate_set_verify_function_t)portable_dlsym("gnutls_certificate_set_verify_function");
    
    if (real_funcs.gnutls_certificate_set_verify_function) {
        gnutls_certificate_verify_function verify_func = gnutls_bypass_verify;
        real_funcs.gnutls_certificate_set_verify_function(cred, &verify_func);
    }
}

int gnutls_certificate_verify_peers2(void *session, unsigned int *status) {
    init_once();
    debug_write("gnutls_certificate_verify_peers2: success");
    if (status) *status = 0;
    return 0;
}

int gnutls_certificate_verify_peers3(void *session, const char *hostname, unsigned int *status) {
    init_once();
    debug_write("gnutls_certificate_verify_peers3: success");
    if (status) *status = 0;
    return 0;
}

/* NSS hooks */
static SECStatus nss_bypass_auth(void *arg, void *fd, int checkSig, int isServer) {
    debug_write("NSS auth: success");
    return SECSuccess;
}

static SECStatus nss_bypass_bad(void *arg, void *fd) {
    debug_write("NSS bad cert: success");
    return SECSuccess;
}

SECStatus SSL_AuthCertificateHook(void *fd, SSLAuthCertificate f, void *arg) {
    init_once();
    debug_write("SSL_AuthCertificateHook: bypassing");
    
    if (!real_funcs.SSL_AuthCertificateHook)
        real_funcs.SSL_AuthCertificateHook = (SSL_AuthCertificateHook_t)portable_dlsym("SSL_AuthCertificateHook");
    
    if (real_funcs.SSL_AuthCertificateHook)
        return real_funcs.SSL_AuthCertificateHook(fd, nss_bypass_auth, arg);
    
    return SECSuccess;
}

SECStatus SSL_BadCertHook(void *fd, SSLBadCertHandler f, void *arg) {
    init_once();
    debug_write("SSL_BadCertHook: bypassing");
    
    if (!real_funcs.SSL_BadCertHook)
        real_funcs.SSL_BadCertHook = (SSL_BadCertHook_t)portable_dlsym("SSL_BadCertHook");
    
    if (real_funcs.SSL_BadCertHook)
        return real_funcs.SSL_BadCertHook(fd, nss_bypass_bad, arg);
    
    return SECSuccess;
}

SECStatus CERT_VerifyCertNow(void *handle, void *cert, int checkSig, void *wincx, void *log) {
    init_once();
    debug_write("CERT_VerifyCertNow: success");
    return SECSuccess;
}

/* mbedTLS hooks */
void mbedtls_ssl_conf_authmode(void *conf, int authmode) {
    init_once();
    debug_write("mbedtls_ssl_conf_authmode: NONE");
    
    if (!real_funcs.mbedtls_ssl_conf_authmode)
        real_funcs.mbedtls_ssl_conf_authmode = (mbedtls_ssl_conf_authmode_t)portable_dlsym("mbedtls_ssl_conf_authmode");
    
    if (real_funcs.mbedtls_ssl_conf_authmode)
        real_funcs.mbedtls_ssl_conf_authmode(conf, 0);
}

int mbedtls_x509_crt_verify(void *crt, void *trust_ca, void *ca_crl, const char *cn, 
                            unsigned int *flags, void *f_vrfy, void *p_vrfy) {
    init_once();
    debug_write("mbedtls_x509_crt_verify: success");
    if (flags) *flags = 0;
    return 0;
}

/* wolfSSL hooks */
static int wolfssl_bypass_verify(int preverify_ok, void *ctx) {
    debug_write("wolfSSL verify: success");
    return 1;
}

void wolfSSL_CTX_set_verify(void *ctx, int mode, VerifyCallback verify_callback) {
    init_once();
    debug_write("wolfSSL_CTX_set_verify: bypassing");
    
    if (!real_funcs.wolfSSL_CTX_set_verify)
        real_funcs.wolfSSL_CTX_set_verify = (wolfSSL_CTX_set_verify_t)portable_dlsym("wolfSSL_CTX_set_verify");
    
    if (real_funcs.wolfSSL_CTX_set_verify) {
        if (mode != 0) {
            real_funcs.wolfSSL_CTX_set_verify(ctx, mode, wolfssl_bypass_verify);
        } else {
            real_funcs.wolfSSL_CTX_set_verify(ctx, 0, NULL);
        }
    }
}

/* Minimal constructor for library initialization */
__attribute__((constructor))
static void lib_init(void) {
    const char *debug_env = getenv("TLS_NOVERIFY_DEBUG");
    if (debug_env && *debug_env) {
        g_debug = 1;
        g_log_fd = 2; /* stderr */
        debug_write("TLS verification bypass initialized");
    }
    
    /* Pre-detect libraries for embedded systems */
    if (portable_dlsym("SSL_CTX_new")) {
        debug_write("Detected OpenSSL/BoringSSL");
    }
    if (portable_dlsym("gnutls_init")) {
        debug_write("Detected GnuTLS");
    }
    if (portable_dlsym("SSL_ImportFD")) {
        debug_write("Detected NSS");
    }
    if (portable_dlsym("mbedtls_ssl_init")) {
        debug_write("Detected mbedTLS");
    }
    if (portable_dlsym("wolfSSL_Init")) {
        debug_write("Detected wolfSSL");
    }
}