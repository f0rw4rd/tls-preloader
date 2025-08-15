/* wolfSSL client test */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Simple test that doesn't require wolfSSL headers */
int main() {
    printf("Testing wolfSSL bypass with curl (wolfSSL build)...\n");
    
    /* Check if curl is built with wolfSSL */
    FILE *fp = popen("curl --version 2>&1", "r");
    if (!fp) {
        printf("Failed to run curl\n");
        return 1;
    }
    
    char buffer[256];
    int has_wolfssl = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "wolfSSL") || strstr(buffer, "WolfSSL")) {
            has_wolfssl = 1;
            printf("Found wolfSSL-enabled curl\n");
            break;
        }
    }
    pclose(fp);
    
    if (!has_wolfssl) {
        printf("curl is not built with wolfSSL, skipping test\n");
        return 0;
    }
    
    /* Test with expired certificate */
    int ret = system("curl -s -I https://expired.badssl.com 2>&1 | grep -q 'HTTP/'");
    if (ret == 0) {
        printf("✓ wolfSSL bypass working with curl\n");
        return 0;
    } else {
        printf("✗ wolfSSL bypass failed with curl\n");
        return 1;
    }
}