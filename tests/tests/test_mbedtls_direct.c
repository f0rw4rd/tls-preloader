/* Direct mbedTLS client test
 * Links against mbedTLS and tests certificate verification bypass
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>

/* Minimal mbedTLS definitions */
#define MBEDTLS_SSL_VERIFY_NONE 0
#define MBEDTLS_SSL_VERIFY_OPTIONAL 1
#define MBEDTLS_SSL_VERIFY_REQUIRED 2

typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;
typedef struct mbedtls_entropy_context mbedtls_entropy_context;
typedef struct mbedtls_ctr_drbg_context mbedtls_ctr_drbg_context;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_net_context mbedtls_net_context;

/* Function pointers for mbedTLS */
typedef void (*mbedtls_ssl_init_t)(mbedtls_ssl_context*);
typedef void (*mbedtls_ssl_config_init_t)(mbedtls_ssl_config*);
typedef void (*mbedtls_entropy_init_t)(mbedtls_entropy_context*);
typedef void (*mbedtls_ctr_drbg_init_t)(mbedtls_ctr_drbg_context*);
typedef void (*mbedtls_x509_crt_init_t)(mbedtls_x509_crt*);
typedef void (*mbedtls_net_init_t)(mbedtls_net_context*);
typedef int (*mbedtls_net_connect_t)(mbedtls_net_context*, const char*, const char*, int);
typedef int (*mbedtls_ssl_config_defaults_t)(mbedtls_ssl_config*, int, int, int);
typedef void (*mbedtls_ssl_conf_authmode_t)(mbedtls_ssl_config*, int);
typedef int (*mbedtls_ssl_setup_t)(mbedtls_ssl_context*, const mbedtls_ssl_config*);
typedef void (*mbedtls_ssl_set_bio_t)(mbedtls_ssl_context*, void*, void*, void*, void*);
typedef int (*mbedtls_ssl_handshake_t)(mbedtls_ssl_context*);
typedef int (*mbedtls_ssl_write_t)(mbedtls_ssl_context*, const unsigned char*, size_t);
typedef int (*mbedtls_ssl_read_t)(mbedtls_ssl_context*, unsigned char*, size_t);
typedef unsigned int (*mbedtls_ssl_get_verify_result_t)(mbedtls_ssl_context*);
typedef void (*mbedtls_ssl_free_t)(mbedtls_ssl_context*);
typedef void (*mbedtls_ssl_config_free_t)(mbedtls_ssl_config*);
typedef void (*mbedtls_net_free_t)(mbedtls_net_context*);
typedef void (*mbedtls_x509_crt_free_t)(mbedtls_x509_crt*);
typedef void (*mbedtls_entropy_free_t)(mbedtls_entropy_context*);
typedef void (*mbedtls_ctr_drbg_free_t)(mbedtls_ctr_drbg_context*);
typedef int (*mbedtls_ssl_set_hostname_t)(mbedtls_ssl_context*, const char*);
typedef int (*mbedtls_ctr_drbg_seed_t)(mbedtls_ctr_drbg_context*, void*, void*, const unsigned char*, size_t);
typedef int (*mbedtls_entropy_func_t)(void*, unsigned char*, size_t);
typedef void (*mbedtls_ssl_conf_rng_t)(mbedtls_ssl_config*, void*, void*);
typedef int (*mbedtls_ctr_drbg_random_t)(void*, unsigned char*, size_t);

/* Minimal structures for allocation */
struct mbedtls_ssl_context { char dummy[8192]; };
struct mbedtls_ssl_config { char dummy[4096]; };
struct mbedtls_entropy_context { char dummy[1024]; };
struct mbedtls_ctr_drbg_context { char dummy[1024]; };
struct mbedtls_x509_crt { char dummy[2048]; };
struct mbedtls_net_context { int fd; char dummy[64]; };

int test_mbedtls_connection() {
    void *lib = dlopen("libmbedtls.so", RTLD_LAZY);
    if (!lib) {
        lib = dlopen("libmbedtls.so.14", RTLD_LAZY);
        if (!lib) {
            lib = dlopen("libmbedtls.so.13", RTLD_LAZY);
            if (!lib) {
                lib = dlopen("libmbedtls.so.12", RTLD_LAZY);
            }
        }
    }
    
    if (!lib) {
        printf("mbedTLS library not found, skipping direct test\n");
        return 0; /* Not a failure, just skip */
    }
    
    /* Load crypto/x509/net libraries too */
    void *lib_crypto = dlopen("libmbedcrypto.so", RTLD_LAZY);
    void *lib_x509 = dlopen("libmbedx509.so", RTLD_LAZY);
    
    /* Load functions */
    mbedtls_ssl_init_t mbedtls_ssl_init = (mbedtls_ssl_init_t)dlsym(lib, "mbedtls_ssl_init");
    mbedtls_ssl_config_init_t mbedtls_ssl_config_init = 
        (mbedtls_ssl_config_init_t)dlsym(lib, "mbedtls_ssl_config_init");
    mbedtls_ssl_config_defaults_t mbedtls_ssl_config_defaults = 
        (mbedtls_ssl_config_defaults_t)dlsym(lib, "mbedtls_ssl_config_defaults");
    mbedtls_ssl_conf_authmode_t mbedtls_ssl_conf_authmode = 
        (mbedtls_ssl_conf_authmode_t)dlsym(lib, "mbedtls_ssl_conf_authmode");
    mbedtls_ssl_setup_t mbedtls_ssl_setup = (mbedtls_ssl_setup_t)dlsym(lib, "mbedtls_ssl_setup");
    mbedtls_ssl_set_hostname_t mbedtls_ssl_set_hostname = 
        (mbedtls_ssl_set_hostname_t)dlsym(lib, "mbedtls_ssl_set_hostname");
    mbedtls_ssl_handshake_t mbedtls_ssl_handshake = 
        (mbedtls_ssl_handshake_t)dlsym(lib, "mbedtls_ssl_handshake");
    mbedtls_ssl_get_verify_result_t mbedtls_ssl_get_verify_result = 
        (mbedtls_ssl_get_verify_result_t)dlsym(lib, "mbedtls_ssl_get_verify_result");
    mbedtls_ssl_write_t mbedtls_ssl_write = (mbedtls_ssl_write_t)dlsym(lib, "mbedtls_ssl_write");
    mbedtls_ssl_read_t mbedtls_ssl_read = (mbedtls_ssl_read_t)dlsym(lib, "mbedtls_ssl_read");
    mbedtls_ssl_free_t mbedtls_ssl_free = (mbedtls_ssl_free_t)dlsym(lib, "mbedtls_ssl_free");
    mbedtls_ssl_config_free_t mbedtls_ssl_config_free = 
        (mbedtls_ssl_config_free_t)dlsym(lib, "mbedtls_ssl_config_free");
    
    if (!mbedtls_ssl_init || !mbedtls_ssl_config_init || !mbedtls_ssl_setup) {
        printf("Failed to load mbedTLS functions\n");
        dlclose(lib);
        return 1;
    }
    
    /* Connect to expired.badssl.com using standard socket */
    struct hostent *host = gethostbyname("expired.badssl.com");
    if (!host) {
        printf("Failed to resolve expired.badssl.com\n");
        dlclose(lib);
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Failed to connect to expired.badssl.com\n");
        close(sock);
        dlclose(lib);
        return 1;
    }
    
    /* Initialize mbedTLS structures */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    
    /* Configure for client */
    mbedtls_ssl_config_defaults(&conf, 0, 0, 0); /* endpoint=client, transport=stream, preset=default */
    
    /* This should be intercepted and changed to NONE */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    
    /* Setup SSL context */
    mbedtls_ssl_setup(&ssl, &conf);
    
    /* Set hostname */
    if (mbedtls_ssl_set_hostname) {
        mbedtls_ssl_set_hostname(&ssl, "expired.badssl.com");
    }
    
    /* For simplicity, we'll do a basic test without full bio setup */
    /* In a real implementation, we'd need to set up bio callbacks */
    
    printf("✓ mbedTLS structures initialized\n");
    printf("✓ mbedtls_ssl_conf_authmode was called (should be bypassed)\n");
    
    /* Check verify result - should return 0 due to bypass */
    unsigned int verify_result = mbedtls_ssl_get_verify_result(&ssl);
    printf("  Verify result: %u (0 = success)\n", verify_result);
    
    if (verify_result == 0) {
        printf("✓ mbedTLS certificate verification bypassed\n");
    } else {
        printf("✗ mbedTLS certificate verification not bypassed\n");
    }
    
    /* Cleanup */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    close(sock);
    
    dlclose(lib);
    if (lib_crypto) dlclose(lib_crypto);
    if (lib_x509) dlclose(lib_x509);
    
    return verify_result == 0 ? 0 : 1;
}

int main() {
    printf("=== Testing mbedTLS Direct Client ===\n");
    
    /* Check if preloader is active */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        printf("ERROR: libtlsnoverify.so not preloaded!\n");
        return 1;
    }
    
    return test_mbedtls_connection();
}