# Alpine Linux test environment (musl libc)
FROM alpine:3.18

# Install all required packages including build dependencies for wolfSSL
RUN apk add --no-cache \
    gcc \
    g++ \
    musl-dev \
    make \
    bash \
    curl curl-dev \
    openssl openssl-dev \
    gnutls gnutls-dev \
    nss nss-dev \
    mbedtls mbedtls-dev \
    wget \
    python3 py3-pip \
    gnutls-utils \
    file \
    # For wolfSSL build
    autoconf \
    automake \
    libtool \
    git \
    coreutils \
    util-linux

# Install Python packages
RUN pip3 install --no-cache-dir requests urllib3

# Install .NET SDK for Alpine
RUN wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh && \
    chmod +x dotnet-install.sh && \
    ./dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet && \
    ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet && \
    rm dotnet-install.sh

# Copy and run wolfSSL build script
COPY docker/build_scripts/build_wolfssl_simple.sh /tmp/
RUN /tmp/build_wolfssl_simple.sh && rm /tmp/build_wolfssl_simple.sh

# Set working directory
WORKDIR /tls-preloader

# Copy library source
COPY tls_noverify.c Makefile ./

# Copy test suite
COPY docker/tests/ tests/

# Build library
RUN make clean && make

# Build tests
RUN cd tests && \
    for dir in libcurl openssl gnutls mbedtls wolfssl nss tools; do \
        if [ -d "$dir" ]; then \
            echo "Building tests in $dir..."; \
            (cd "$dir" && make clean && make) || echo "Warning: Tests in $dir failed to build"; \
        fi; \
    done

# Set environment for tests
ENV LD_LIBRARY_PATH=/tls-preloader:/usr/local/lib
ENV LD_PRELOAD=/tls-preloader/libtlsnoverify.so

# Build main test executable
RUN cd tests && make test_all

# Create a test runner script
RUN echo '#!/bin/sh' > /tls-preloader/run_tests.sh && \
    echo 'export LD_PRELOAD=/tls-preloader/libtlsnoverify.so' >> /tls-preloader/run_tests.sh && \
    echo 'export TLS_NOVERIFY_DEBUG=1' >> /tls-preloader/run_tests.sh && \
    echo 'echo "Running tests with LD_PRELOAD=$LD_PRELOAD"' >> /tls-preloader/run_tests.sh && \
    echo 'echo "Debug mode enabled: TLS_NOVERIFY_DEBUG=$TLS_NOVERIFY_DEBUG"' >> /tls-preloader/run_tests.sh && \
    echo 'cd /tls-preloader/tests' >> /tls-preloader/run_tests.sh && \
    echo './test_all' >> /tls-preloader/run_tests.sh && \
    chmod +x /tls-preloader/run_tests.sh

# Run tests
CMD ["/tls-preloader/run_tests.sh"]