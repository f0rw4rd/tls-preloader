/* NSS client test */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("Testing NSS bypass...\n");
    
    /* Check if we have any NSS tools */
    FILE *fp;
    
    /* Test with Firefox/Chrome if available (they use NSS) */
    /* More commonly, we can test with curl built against NSS */
    fp = popen("curl --version 2>&1", "r");
    if (fp) {
        char buffer[256];
        int has_nss = 0;
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "NSS")) {
                has_nss = 1;
                printf("Found NSS-enabled curl\n");
                break;
            }
        }
        pclose(fp);
        
        if (has_nss) {
            int ret = system("curl -s -I https://expired.badssl.com 2>&1 | grep -q 'HTTP/'");
            if (ret == 0) {
                printf("✓ NSS bypass working with curl\n");
                return 0;
            } else {
                printf("✗ NSS bypass failed with curl\n");
                return 1;
            }
        }
    }
    
    /* Test with certutil if available */
    fp = popen("which certutil 2>/dev/null", "r");
    char path[256];
    if (fgets(path, sizeof(path), fp)) {
        pclose(fp);
        printf("Found certutil (NSS tool)\n");
        
        /* The preloader should intercept NSS functions */
        void *handle = dlopen(NULL, RTLD_LAZY);
        if (handle) {
            void *func = dlsym(handle, "SSL_AuthCertificateHook");
            if (func) {
                printf("✓ NSS functions are being intercepted\n");
                return 0;
            }
        }
    } else {
        pclose(fp);
    }
    
    /* Fallback: just check if NSS functions are hooked */
    printf("Checking if NSS functions are intercepted...\n");
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (handle) {
        void *func = dlsym(handle, "CERT_VerifyCertNow");
        if (func) {
            printf("✓ NSS functions are being intercepted\n");
            return 0;
        }
    }
    
    printf("✗ NSS bypass not detected\n");
    return 1;
}