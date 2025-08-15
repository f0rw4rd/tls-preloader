#!/bin/sh
# Simple wolfSSL build script for Docker containers

set -e

WOLFSSL_VERSION="5.6.6"
BUILD_DIR="/tmp/wolfssl-build"
PREFIX="/usr/local"

echo "Building wolfSSL $WOLFSSL_VERSION..."

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Download
wget -q "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$WOLFSSL_VERSION-stable.tar.gz"
tar xzf "v$WOLFSSL_VERSION-stable.tar.gz"
cd "wolfssl-$WOLFSSL_VERSION-stable"

# Configure
./autogen.sh
./configure --prefix="$PREFIX" \
            --enable-all \
            --enable-opensslextra \
            --enable-opensslall \
            --disable-static \
            --enable-shared

# Build and install
make -j$(nproc)
make install

# Update library cache
ldconfig || true

# Clean up
cd /
rm -rf "$BUILD_DIR"

echo "wolfSSL $WOLFSSL_VERSION installed successfully"