#!/bin/bash
# Run tool tests in Docker containers

set -e

echo "==================================="
echo "Running Tool Tests in Alpine"
echo "==================================="

# Run each tool test individually
for test in test_curl_cli test_wget test_openssl_s_client test_gnutls_cli test_netcat_variants test_http_clients test_scripting_languages test_network_tools test_database_clients; do
    echo -e "\n--- Running $test ---"
    docker run --rm tls-bypass-test:alpine /bin/sh -c "cd /tls-preloader/tests/tools && LD_PRELOAD=/tls-preloader/libtlsnoverify.so ./$test" || echo "Test $test failed or skipped"
done

echo -e "\n==================================="
echo "Building Ubuntu image with tools..."  
echo "==================================="

# Build Ubuntu image if needed
if docker build -f ubuntu/Dockerfile -t tls-bypass-test:ubuntu .. 2>&1 | grep -q "Successfully tagged"; then
    echo "Ubuntu image built successfully"
    
    echo -e "\n==================================="
    echo "Running Tool Tests in Ubuntu"
    echo "==================================="
    
    # Run tests in Ubuntu which has more tools installed
    for test in test_curl_cli test_wget test_openssl_s_client test_gnutls_cli test_netcat_variants test_http_clients test_scripting_languages test_network_tools test_database_clients; do
        echo -e "\n--- Running $test ---"
        docker run --rm tls-bypass-test:ubuntu /bin/sh -c "cd /tls-preloader/tests/tools && LD_PRELOAD=/tls-preloader/libtlsnoverify.so ./$test" || echo "Test $test failed or skipped"
    done
else
    echo "Ubuntu image build is still in progress or failed"
fi

echo -e "\n==================================="
echo "Tool Tests Complete"
echo "==================================="