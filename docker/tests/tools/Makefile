CC ?= cc
CFLAGS ?= -O2 -I.. -Wall
LDFLAGS = -lpthread

TEST_PROGS = test_curl_cli test_gnutls_cli test_openssl_s_client test_wget test_nss_tools \
             test_netcat_variants test_http_clients test_scripting_languages \
             test_database_clients test_network_tools

all: $(TEST_PROGS)

test_curl_cli: test_curl_cli.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_gnutls_cli: test_gnutls_cli.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_openssl_s_client: test_openssl_s_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_wget: test_wget.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_nss_tools: test_nss_tools.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_netcat_variants: test_netcat_variants.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_http_clients: test_http_clients.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_scripting_languages: test_scripting_languages.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_database_clients: test_database_clients.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_network_tools: test_network_tools.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TEST_PROGS)

.PHONY: all clean