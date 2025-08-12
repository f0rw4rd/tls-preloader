# Ubuntu test environment (glibc)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install all required packages including build dependencies for wolfSSL
RUN apt-get update && apt-get install -y \
    build-essential \
    curl libcurl4-openssl-dev \
    openssl libssl-dev \
    gnutls-bin libgnutls28-dev \
    libnss3 libnss3-dev \
    libmbedtls-dev \
    wget \
    python3 python3-pip \
    file \
    ca-certificates \
    # Additional tools for testing
    nmap ncat \
    socat \
    httpie \
    aria2 \
    axel \
    nodejs npm \
    ruby \
    perl libwww-perl \
    php-cli php-curl \
    lynx \
    links \
    w3m \
    postgresql-client \
    mysql-client \
    redis-tools \
    # For wolfSSL build
    autoconf \
    automake \
    libtool \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir requests urllib3

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
RUN echo '#!/bin/bash' > /tls-preloader/run_tests.sh && \
    echo 'export LD_PRELOAD=/tls-preloader/libtlsnoverify.so' >> /tls-preloader/run_tests.sh && \
    echo 'echo "Running tests with LD_PRELOAD=$LD_PRELOAD"' >> /tls-preloader/run_tests.sh && \
    echo 'cd /tls-preloader/tests' >> /tls-preloader/run_tests.sh && \
    echo './test_all' >> /tls-preloader/run_tests.sh && \
    chmod +x /tls-preloader/run_tests.sh

# Run tests
CMD ["/tls-preloader/run_tests.sh"]