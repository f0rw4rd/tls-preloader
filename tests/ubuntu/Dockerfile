# Ubuntu test environment (glibc)
FROM ubuntu:25.04

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

# Install Python packages from apt
RUN apt-get update && \
    apt-get install -y python3-requests python3-urllib3 && \
    rm -rf /var/lib/apt/lists/*

# Install .NET SDK versions
# Ubuntu 25.04 only has 8.0 and 9.0 in repos
# .NET 6.0 reached end of support in Nov 2024
RUN apt-get update && \
    apt-get install -y \
        dotnet-sdk-8.0 \
        dotnet-sdk-9.0 && \
    rm -rf /var/lib/apt/lists/*

# Copy and run wolfSSL build script
COPY tests/build_scripts/build_wolfssl_simple.sh /tmp/
RUN /tmp/build_wolfssl_simple.sh && rm /tmp/build_wolfssl_simple.sh

# Set working directory
WORKDIR /tls-preloader

# Copy library source
COPY tls_noverify.c Makefile ./

# Copy test suite
COPY tests/ tests/

# Build library
RUN make clean && make

# No need to build C tests - using bash script

# Set library path but not LD_PRELOAD (will be set at runtime)
ENV LD_LIBRARY_PATH=/tls-preloader:/usr/local/lib

# Verify glibc has backtrace support
RUN ldconfig -p | grep -i libc || true

# Run tests  
WORKDIR /tls-preloader/tests/tests
CMD ["./run_tests.sh"]