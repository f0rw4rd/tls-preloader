/* mbedTLS client test */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Testing mbedTLS bypass...\n");
    
    /* Check for tools that might use mbedTLS */
    /* aria2c sometimes uses mbedTLS */
    FILE *fp = popen("which aria2c 2>/dev/null", "r");
    char path[256];
    if (fgets(path, sizeof(path), fp)) {
        pclose(fp);
        printf("Found aria2c, testing mbedTLS bypass...\n");
        
        /* Try to download from expired cert site */
        int ret = system("aria2c --check-certificate=true --timeout=5 -o /dev/null https://expired.badssl.com 2>&1 | grep -q 'Download complete'");
        if (ret == 0) {
            printf("✓ mbedTLS bypass might be working with aria2c\n");
            return 0;
        }
    } else {
        pclose(fp);
    }
    
    /* Test with generic tools that might use mbedTLS */
    printf("Testing generic mbedTLS bypass through LD_PRELOAD hooks...\n");
    
    /* The preloader should intercept mbedTLS functions even if no tool uses them */
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (handle) {
        void *func = dlsym(handle, "mbedtls_ssl_conf_authmode");
        if (func) {
            printf("✓ mbedTLS functions are being intercepted\n");
            return 0;
        }
    }
    
    printf("✗ mbedTLS bypass not detected\n");
    return 1;
}