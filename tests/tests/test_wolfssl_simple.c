/* Simple wolfSSL interception test
 * Just verifies that wolfSSL functions are being intercepted
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

int main() {
    printf("=== Testing wolfSSL Function Interception ===\n");
    
    /* Check if preloader is active */
    const char *preload = getenv("LD_PRELOAD");
    if (!preload || !strstr(preload, "libtlsnoverify.so")) {
        printf("ERROR: libtlsnoverify.so not preloaded!\n");
        return 1;
    }
    
    /* Check if wolfSSL functions are intercepted */
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        printf("Failed to dlopen self\n");
        return 1;
    }
    
    int found = 0;
    
    /* Check wolfSSL_CTX_set_verify */
    void *func = dlsym(handle, "wolfSSL_CTX_set_verify");
    if (func) {
        printf("✓ wolfSSL_CTX_set_verify is intercepted\n");
        found++;
    } else {
        printf("✗ wolfSSL_CTX_set_verify not found\n");
    }
    
    /* Check wolfSSL_set_verify */
    func = dlsym(handle, "wolfSSL_set_verify");
    if (func) {
        printf("✓ wolfSSL_set_verify is intercepted\n");
        found++;
    } else {
        printf("✗ wolfSSL_set_verify not found\n");
    }
    
    /* Check wolfSSL_get_verify_result */
    func = dlsym(handle, "wolfSSL_get_verify_result");
    if (func) {
        printf("✓ wolfSSL_get_verify_result is intercepted\n");
        
        /* Try calling it directly */
        long (*get_result)(void*) = (long (*)(void*))func;
        long result = get_result(NULL);
        printf("  wolfSSL_get_verify_result(NULL) returned: %ld (expected 0)\n", result);
        if (result == 0) {
            printf("✓ wolfSSL_get_verify_result bypass working\n");
            found++;
        }
    } else {
        printf("✗ wolfSSL_get_verify_result not found\n");
    }
    
    /* Check wolfSSL_check_domain_name */
    func = dlsym(handle, "wolfSSL_check_domain_name");
    if (func) {
        printf("✓ wolfSSL_check_domain_name is intercepted\n");
        
        /* Try calling it */
        int (*check_domain)(void*, const char*) = (int (*)(void*, const char*))func;
        int result = check_domain(NULL, "expired.badssl.com");
        printf("  wolfSSL_check_domain_name returned: %d (expected 1)\n", result);
        if (result == 1) {
            printf("✓ wolfSSL_check_domain_name bypass working\n");
            found++;
        }
    } else {
        printf("✗ wolfSSL_check_domain_name not found\n");
    }
    
    /* Check wolfSSL_CTX_load_verify_locations */
    func = dlsym(handle, "wolfSSL_CTX_load_verify_locations");
    if (func) {
        printf("✓ wolfSSL_CTX_load_verify_locations is intercepted\n");
        
        /* Try calling it */
        int (*load_verify)(void*, const char*, const char*) = 
            (int (*)(void*, const char*, const char*))func;
        int result = load_verify(NULL, "/nonexistent", NULL);
        printf("  wolfSSL_CTX_load_verify_locations returned: %d (expected 1)\n", result);
        if (result == 1) {
            printf("✓ wolfSSL_CTX_load_verify_locations bypass working\n");
            found++;
        }
    }
    
    dlclose(handle);
    
    printf("\nSummary: %d/5 wolfSSL functions intercepted successfully\n", found);
    
    return (found >= 3) ? 0 : 1;
}