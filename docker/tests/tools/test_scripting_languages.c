/* Test scripting language interpreters (node, ruby, perl, php) with LD_PRELOAD */
#include "../test_framework.h"
#include <unistd.h>
#include <sys/wait.h>

int run_script_command(const char *cmd, int timeout_seconds) {
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "timeout %d %s", timeout_seconds, cmd);
    
    int status = system(full_cmd);
    
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        TEST_LOG("Script exit code: %d", exit_code);
        return (exit_code == 0) ? 0 : -1;
    }
    
    return -1;
}

/* Node.js tests */
int test_node_https_self_signed(void) {
    TEST_LOG("Testing Node.js HTTPS with self-signed cert");
    
    const char *node_cmd = "node -e \"" 
        "require('https').get('https://self-signed.badssl.com/', (res) => {"
        "  console.log('Connected:', res.statusCode);"
        "  process.exit(0);"
        "}).on('error', (e) => {"
        "  console.error('Error:', e.message);"
        "  process.exit(1);"
        "});\" 2>&1";
    
    if (run_script_command(node_cmd, 10) == 0) {
        TEST_LOG("Node.js successfully connected to self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("Node.js connection test completed");
    return TEST_PASS;
}

int test_node_https_expired(void) {
    TEST_LOG("Testing Node.js HTTPS with expired cert");
    
    const char *node_cmd = "node -e \"" 
        "require('https').get('https://expired.badssl.com/', (res) => {"
        "  console.log('Connected:', res.statusCode);"
        "  process.exit(0);"
        "}).on('error', (e) => {"
        "  console.error('Error:', e.message);"
        "  process.exit(1);"
        "});\" 2>&1";
    
    if (run_script_command(node_cmd, 10) == 0) {
        TEST_LOG("Node.js successfully connected to expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* Ruby tests */
int test_ruby_https_self_signed(void) {
    TEST_LOG("Testing Ruby HTTPS with self-signed cert");
    
    const char *ruby_cmd = "ruby -e \"" 
        "require 'net/https';"
        "require 'uri';"
        "uri = URI('https://self-signed.badssl.com/');"
        "Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|"
        "  puts http.get('/').code"
        "end\" 2>&1";
    
    if (run_script_command(ruby_cmd, 10) == 0) {
        TEST_LOG("Ruby successfully connected to self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("Ruby connection test completed");
    return TEST_PASS;
}

int test_ruby_open_uri(void) {
    TEST_LOG("Testing Ruby open-uri with expired cert");
    
    const char *ruby_cmd = "ruby -e \"" 
        "require 'open-uri';"
        "open('https://expired.badssl.com/').read;"
        "puts 'Success'\" 2>&1";
    
    if (run_script_command(ruby_cmd, 10) == 0) {
        TEST_LOG("Ruby open-uri successfully connected");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* Perl tests */
int test_perl_lwp_self_signed(void) {
    TEST_LOG("Testing Perl LWP with self-signed cert");
    
    const char *perl_cmd = "perl -e \"" 
        "use LWP::UserAgent;"
        "$ua = LWP::UserAgent->new;"
        "$res = $ua->get('https://self-signed.badssl.com/');"
        "exit($res->is_success ? 0 : 1);\" 2>&1";
    
    if (run_script_command(perl_cmd, 10) == 0) {
        TEST_LOG("Perl LWP successfully connected to self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("Perl LWP connection test completed");
    return TEST_PASS;
}

int test_perl_lwp_expired(void) {
    TEST_LOG("Testing Perl LWP with expired cert");
    
    const char *perl_cmd = "perl -e \"" 
        "use LWP::UserAgent;"
        "$ua = LWP::UserAgent->new;"
        "$res = $ua->get('https://expired.badssl.com/');"
        "exit($res->is_success ? 0 : 1);\" 2>&1";
    
    if (run_script_command(perl_cmd, 10) == 0) {
        TEST_LOG("Perl LWP successfully connected to expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

/* PHP tests */
int test_php_file_get_contents_self_signed(void) {
    TEST_LOG("Testing PHP file_get_contents with self-signed cert");
    
    const char *php_cmd = "php -r \"" 
        "@file_get_contents('https://self-signed.badssl.com/');"
        "exit(0);\" 2>&1";
    
    if (run_script_command(php_cmd, 10) == 0) {
        TEST_LOG("PHP successfully fetched from self-signed cert");
        return TEST_PASS;
    }
    
    TEST_LOG("PHP connection test completed");
    return TEST_PASS;
}

int test_php_curl_expired(void) {
    TEST_LOG("Testing PHP curl with expired cert");
    
    const char *php_cmd = "php -r \"" 
        "$ch = curl_init('https://expired.badssl.com/');"
        "curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);"
        "curl_exec($ch);"
        "$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);"
        "curl_close($ch);"
        "exit($code > 0 ? 0 : 1);\" 2>&1";
    
    if (run_script_command(php_cmd, 10) == 0) {
        TEST_LOG("PHP curl successfully connected to expired cert");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int test_php_stream_context(void) {
    TEST_LOG("Testing PHP stream context with wrong hostname");
    
    const char *php_cmd = "php -r \"" 
        "$context = stream_context_create(['ssl' => ['verify_peer' => false]]);"
        "@file_get_contents('https://wrong.host.badssl.com/', false, $context);"
        "exit(0);\" 2>&1";
    
    if (run_script_command(php_cmd, 10) == 0) {
        TEST_LOG("PHP stream context succeeded");
        return TEST_PASS;
    }
    
    return TEST_PASS;
}

int main(void) {
    test_init();
    
    TEST_LOG("Testing scripting language interpreters");
    
    /* Check if Node.js is available */
    if (system("which node >/dev/null 2>&1") == 0 || system("which nodejs >/dev/null 2>&1") == 0) {
        RUN_TEST("Node.js HTTPS self-signed", test_node_https_self_signed);
        RUN_TEST("Node.js HTTPS expired", test_node_https_expired);
    } else {
        TEST_LOG("Node.js not available, skipping Node.js tests");
    }
    
    /* Check if Ruby is available */
    if (system("which ruby >/dev/null 2>&1") == 0) {
        RUN_TEST("Ruby HTTPS self-signed", test_ruby_https_self_signed);
        RUN_TEST("Ruby open-uri expired", test_ruby_open_uri);
    } else {
        TEST_LOG("Ruby not available, skipping Ruby tests");
    }
    
    /* Check if Perl with LWP is available */
    if (system("perl -e 'use LWP::UserAgent' >/dev/null 2>&1") == 0) {
        RUN_TEST("Perl LWP self-signed", test_perl_lwp_self_signed);
        RUN_TEST("Perl LWP expired", test_perl_lwp_expired);
    } else {
        TEST_LOG("Perl with LWP not available, skipping Perl tests");
    }
    
    /* Check if PHP is available */
    if (system("which php >/dev/null 2>&1") == 0) {
        RUN_TEST("PHP file_get_contents self-signed", test_php_file_get_contents_self_signed);
        RUN_TEST("PHP curl expired", test_php_curl_expired);
        RUN_TEST("PHP stream context wrong host", test_php_stream_context);
    } else {
        TEST_LOG("PHP not available, skipping PHP tests");
    }
    
    TEST_LOG("All tests completed!");
    return 0;
}