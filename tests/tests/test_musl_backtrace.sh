#!/bin/sh
# Test backtrace functionality on musl libc (Alpine Linux)

echo "=== Testing backtrace on musl libc ==="

# Check if we're on Alpine/musl
if [ -f /etc/alpine-release ]; then
    echo "Running on Alpine Linux (musl libc)"
    echo "Alpine version: $(cat /etc/alpine-release)"
else
    echo "Not running on Alpine Linux, checking libc..."
    ldd --version 2>&1 | head -1
fi

# Check for libexecinfo
echo ""
echo "Checking for libexecinfo..."
if apk info libexecinfo 2>/dev/null | grep -q libexecinfo; then
    echo "libexecinfo is installed"
else
    echo "libexecinfo is NOT installed"
    echo "To install: apk add libexecinfo libexecinfo-dev"
fi

# Build and run the backtrace test
echo ""
echo "Building backtrace test..."
cc -Wall -O2 -g -o test_backtrace test_backtrace.c -ldl || exit 1

echo ""
echo "Running backtrace test..."
LD_PRELOAD=../../libtlsnoverify.so ./test_backtrace

# Cleanup
rm -f test_backtrace