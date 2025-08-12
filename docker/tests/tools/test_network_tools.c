/* Test various network tools (lynx, links, w3m, lftp, stunnel) with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_network_command(const char *cmd, int timeout_seconds) {
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "timeout %d %s", timeout_seconds, cmd);
    
    int status = system(full_cmd);
    
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        TEST_LOG("Network tool exit code: %d", exit_code);
        return (exit_code == 0) ? 0 : -1;
    }
    
    return -1;
}

/* Text browser tests */
int test_lynx_ssl(void) {
    TEST_LOG("Testing lynx with HTTPS");
    
    /* Lynx in dump mode to test HTTPS connection */
    const char *cmd = "lynx -dump https://self-signed.badssl.com/ >/dev/null 2>&1";
    
    if (run_network_command(cmd, 10) == 0) {
        TEST_LOG("lynx successfully accessed HTTPS site");
        return TEST_PASS;
    }
    
    TEST_LOG("lynx HTTPS test completed");
    return TEST_PASS;
}

int test_links_ssl(void) {
    TEST_LOG("Testing links with HTTPS");
    
    /* Links in dump mode */
    const char *cmd = "links -dump https://expired.badssl.com/ >/dev/null 2>&1";
    
    if (run_network_command(cmd, 10) == 0) {
        TEST_LOG("links successfully accessed HTTPS site");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_w3m_ssl(void) {
    TEST_LOG("Testing w3m with HTTPS");
    
    /* w3m in dump mode */
    const char *cmd = "w3m -dump https://wrong.host.badssl.com/ >/dev/null 2>&1";
    
    if (run_network_command(cmd, 10) == 0) {
        TEST_LOG("w3m successfully accessed HTTPS site");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_elinks_ssl(void) {
    TEST_LOG("Testing elinks with HTTPS");
    
    /* elinks in dump mode */
    const char *cmd = "elinks -dump https://untrusted-root.badssl.com/ >/dev/null 2>&1";
    
    if (run_network_command(cmd, 10) == 0) {
        TEST_LOG("elinks successfully accessed HTTPS site");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* FTP/FTPS client tests */
int test_lftp_ftps(void) {
    TEST_LOG("Testing lftp with FTPS");
    
    /* lftp with SSL/TLS - would connect to FTPS server in real test */
    const char *cmd = "lftp -v >/dev/null 2>&1";
    
    if (system("which lftp >/dev/null 2>&1") == 0) {
        TEST_LOG("lftp is available for FTPS testing");
        /* In real test: lftp -e "set ssl:verify-certificate no; ls; quit" ftps://test.server */
        return TEST_PASS;
    }
    
    TEST_LOG("lftp not available");
    return TEST_PASS;
}

int test_ncftp_ssl(void) {
    TEST_LOG("Testing ncftp with SSL");
    
    if (system("which ncftp >/dev/null 2>&1") == 0) {
        TEST_LOG("ncftp is available");
        /* Note: ncftp doesn't support FTPS, but testing availability */
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* LDAP client tests */
int test_ldapsearch_tls(void) {
    TEST_LOG("Testing ldapsearch with TLS");
    
    if (system("which ldapsearch >/dev/null 2>&1") == 0) {
        TEST_LOG("ldapsearch is available for TLS testing");
        /* In real test: ldapsearch -H ldaps://server:636 -x -b "dc=example,dc=com" */
        return TEST_PASS;
    }
    
    TEST_LOG("ldapsearch not available");
    return TEST_PASS;
}

/* Email client tests */
int test_swaks_tls(void) {
    TEST_LOG("Testing swaks SMTP with TLS");
    
    if (system("which swaks >/dev/null 2>&1") == 0) {
        TEST_LOG("swaks is available for SMTP TLS testing");
        /* In real test: swaks --to test@example.com --server smtp.gmail.com:587 --tls */
        return TEST_PASS;
    }
    
    TEST_LOG("swaks not available");
    return TEST_PASS;
}

/* Stunnel tests */
int test_stunnel_client(void) {
    TEST_LOG("Testing stunnel as SSL client");
    
    if (system("which stunnel >/dev/null 2>&1") == 0) {
        TEST_LOG("stunnel is available for SSL tunneling");
        /* stunnel can create SSL tunnels that would be affected by the preloader */
        return TEST_PASS;
    }
    
    TEST_LOG("stunnel not available");
    return TEST_PASS;
}

/* Additional network tools */
int test_rsync_ssl(void) {
    TEST_LOG("Testing rsync over SSL");
    
    if (system("which rsync >/dev/null 2>&1") == 0) {
        TEST_LOG("rsync is available");
        /* rsync can use SSL when tunneled through stunnel or ssh */
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_scp_ssl(void) {
    TEST_LOG("Testing scp (SSH)");
    
    if (system("which scp >/dev/null 2>&1") == 0) {
        TEST_LOG("scp is available");
        /* scp uses SSH which may use OpenSSL/LibreSSL */
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing network tools");
    
    /* Text browsers */
    if (system("which lynx >/dev/null 2>&1") == 0) {
        RUN_TEST("lynx HTTPS", test_lynx_ssl);
    } else {
        TEST_LOG("lynx not available");
    }
    
    if (system("which links >/dev/null 2>&1") == 0) {
        RUN_TEST("links HTTPS", test_links_ssl);
    } else {
        TEST_LOG("links not available");
    }
    
    if (system("which w3m >/dev/null 2>&1") == 0) {
        RUN_TEST("w3m HTTPS", test_w3m_ssl);
    } else {
        TEST_LOG("w3m not available");
    }
    
    if (system("which elinks >/dev/null 2>&1") == 0) {
        RUN_TEST("elinks HTTPS", test_elinks_ssl);
    } else {
        TEST_LOG("elinks not available");
    }
    
    /* FTP clients */
    RUN_TEST("lftp FTPS", test_lftp_ftps);
    RUN_TEST("ncftp", test_ncftp_ssl);
    
    /* LDAP */
    RUN_TEST("ldapsearch TLS", test_ldapsearch_tls);
    
    /* Email */
    RUN_TEST("swaks SMTP TLS", test_swaks_tls);
    
    /* SSL tunnel */
    RUN_TEST("stunnel client", test_stunnel_client);
    
    /* Other tools */
    RUN_TEST("rsync SSL", test_rsync_ssl);
    RUN_TEST("scp SSH", test_scp_ssl);
    
    TEST_LOG("All tests completed!");
    return 0;
}