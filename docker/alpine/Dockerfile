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
    # Note: libexecinfo not available in newer Alpine versions

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

# Set library path but not LD_PRELOAD (will be set at runtime)
ENV LD_LIBRARY_PATH=/tls-preloader:/usr/local/lib

# Run tests
WORKDIR /tls-preloader/tests
CMD ["./run_tests.sh"]