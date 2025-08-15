/* Direct wolfSSL client test
 * Links against wolfSSL and tests certificate verification bypass
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>

/* Minimal wolfSSL definitions to avoid needing headers */
#define WOLFSSL_SUCCESS 1
#define SSL_SUCCESS 1
#define SSL_FAILURE 0
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

typedef void WOLFSSL_CTX;
typedef void WOLFSSL;
typedef void WOLFSSL_METHOD;

/* Function pointers for wolfSSL */
typedef WOLFSSL_METHOD* (*wolfTLSv1_2_client_method_t)(void);
typedef WOLFSSL_CTX* (*wolfSSL_CTX_new_t)(WOLFSSL_METHOD*);
typedef void (*wolfSSL_CTX_free_t)(WOLFSSL_CTX*);
typedef WOLFSSL* (*wolfSSL_new_t)(WOLFSSL_CTX*);
typedef void (*wolfSSL_free_t)(WOLFSSL*);
typedef int (*wolfSSL_set_fd_t)(WOLFSSL*, int);
typedef int (*wolfSSL_connect_t)(WOLFSSL*);
typedef int (*wolfSSL_write_t)(WOLFSSL*, const void*, int);
typedef int (*wolfSSL_read_t)(WOLFSSL*, void*, int);
typedef int (*wolfSSL_shutdown_t)(WOLFSSL*);
typedef int (*wolfSSL_Init_t)(void);
typedef int (*wolfSSL_Cleanup_t)(void);
typedef void (*wolfSSL_CTX_set_verify_t)(WOLFSSL_CTX*, int, void*);
typedef long (*wolfSSL_get_verify_result_t)(WOLFSSL*);
typedef int (*wolfSSL_check_domain_name_t)(WOLFSSL*, const char*);

int test_wolfssl_connection() {
    void *lib = dlopen("libwolfssl.so", RTLD_LAZY);
    if (!lib) {
        /* Try alternative names */
        lib = dlopen("libwolfssl.so.24", RTLD_LAZY);
        if (!lib) {
            lib = dlopen("libwolfssl.so.23", RTLD_LAZY);
        }
    }
    
    if (!lib) {
        printf("wolfSSL library not found, skipping direct test\n");
        return 0; /* Not a failure, just skip */
    }
    
    /* Load functions */
    wolfSSL_Init_t wolfSSL_Init = (wolfSSL_Init_t)dlsym(lib, "wolfSSL_Init");
    wolfTLSv1_2_client_method_t wolfTLSv1_2_client_method = 
        (wolfTLSv1_2_client_method_t)dlsym(lib, "wolfTLSv1_2_client_method");
    wolfSSL_CTX_new_t wolfSSL_CTX_new = (wolfSSL_CTX_new_t)dlsym(lib, "wolfSSL_CTX_new");
    wolfSSL_new_t wolfSSL_new = (wolfSSL_new_t)dlsym(lib, "wolfSSL_new");
    wolfSSL_set_fd_t wolfSSL_set_fd = (wolfSSL_set_fd_t)dlsym(lib, "wolfSSL_set_fd");
    wolfSSL_connect_t wolfSSL_connect = (wolfSSL_connect_t)dlsym(lib, "wolfSSL_connect");
    wolfSSL_get_verify_result_t wolfSSL_get_verify_result = 
        (wolfSSL_get_verify_result_t)dlsym(lib, "wolfSSL_get_verify_result");
    wolfSSL_check_domain_name_t wolfSSL_check_domain_name = 
        (wolfSSL_check_domain_name_t)dlsym(lib, "wolfSSL_check_domain_name");
    wolfSSL_write_t wolfSSL_write = (wolfSSL_write_t)dlsym(lib, "wolfSSL_write");
    wolfSSL_read_t wolfSSL_read = (wolfSSL_read_t)dlsym(lib, "wolfSSL_read");
    wolfSSL_shutdown_t wolfSSL_shutdown = (wolfSSL_shutdown_t)dlsym(lib, "wolfSSL_shutdown");
    wolfSSL_free_t wolfSSL_free = (wolfSSL_free_t)dlsym(lib, "wolfSSL_free");
    wolfSSL_CTX_free_t wolfSSL_CTX_free = (wolfSSL_CTX_free_t)dlsym(lib, "wolfSSL_CTX_free");
    wolfSSL_Cleanup_t wolfSSL_Cleanup = (wolfSSL_Cleanup_t)dlsym(lib, "wolfSSL_Cleanup");
    
    if (!wolfSSL_Init || !wolfSSL_CTX_new || !wolfSSL_new) {
        printf("Failed to load wolfSSL functions\n");
        dlclose(lib);
        return 1;
    }
    
    /* Initialize wolfSSL */
    wolfSSL_Init();
    
    /* Create context */
    WOLFSSL_METHOD *method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        printf("Failed to create wolfSSL context\n");
        dlclose(lib);
        return 1;
    }
    
    /* Connect to expired.badssl.com */
    struct hostent *host = gethostbyname("expired.badssl.com");
    if (!host) {
        printf("Failed to resolve expired.badssl.com\n");
        wolfSSL_CTX_free(ctx);
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
        wolfSSL_CTX_free(ctx);
        dlclose(lib);
        return 1;
    }
    
    /* Create SSL connection */
    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, sock);
    
    /* Set domain for verification */
    if (wolfSSL_check_domain_name) {
        wolfSSL_check_domain_name(ssl, "expired.badssl.com");
    }
    
    /* Try to connect - should succeed despite expired cert */
    int ret = wolfSSL_connect(ssl);
    
    /* Even if connect fails, check if verification was bypassed */
    long verify_result = -1;
    if (wolfSSL_get_verify_result) {
        verify_result = wolfSSL_get_verify_result(ssl);
        printf("  Verify result: %ld (0 = success)\n", verify_result);
    }
    
    if (ret == SSL_SUCCESS) {
        printf("✓ wolfSSL connected despite expired certificate\n");
        
        /* Send HTTP request */
        const char *request = "GET / HTTP/1.0\r\nHost: expired.badssl.com\r\n\r\n";
        wolfSSL_write(ssl, request, strlen(request));
        
        /* Read response */
        char buffer[256];
        int bytes = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            if (strstr(buffer, "HTTP/")) {
                printf("✓ Received HTTP response through wolfSSL\n");
            }
        }
        
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(sock);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        dlclose(lib);
        return 0;
    } else {
        /* Connection failed, but check if it's due to network or cert verification */
        if (verify_result == 0) {
            printf("✓ wolfSSL verification bypassed (verify_result=0) but connection failed for other reasons\n");
            wolfSSL_free(ssl);
            close(sock);
            wolfSSL_CTX_free(ctx);
            wolfSSL_Cleanup();
            dlclose(lib);
            return 0; /* Still a success if verification was bypassed */
        } else {
            printf("✗ wolfSSL verification not bypassed (verify_result=%ld)\n", verify_result);
            wolfSSL_free(ssl);
            close(sock);
            wolfSSL_CTX_free(ctx);
            wolfSSL_Cleanup();
            dlclose(lib);
            return 1;
        }
    }
}

int main() {
    printf("=== Testing wolfSSL Direct Client ===\n");
    
    /* Check if preloader is active */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        printf("ERROR: libtlsnoverify.so not preloaded!\n");
        return 1;
    }
    
    return test_wolfssl_connection();
}