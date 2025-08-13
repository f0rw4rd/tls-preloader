# TLS Certificate Verification Bypass Library

A universal LD_PRELOAD library that disables TLS certificate verification across multiple TLS libraries and platforms.

## Features

- **Cross-platform support**: Linux, FreeBSD, OpenBSD, NetBSD, Solaris, AIX, macOS
- **Automatic platform detection**: Single binary adapts to the target platform
- **Thread-safe implementation**: Platform-specific optimizations for thread safety
- **Comprehensive TLS library support**: All major TLS implementations covered
- **Minimal dependencies**: Works on embedded systems and old Linux devices

## Supported TLS Libraries

- OpenSSL (1.0.x, 1.1.x, 3.x)
- BoringSSL
- LibreSSL
- GnuTLS (all versions)
- NSS (Network Security Services)
- mbedTLS
- wolfSSL
- libcurl (HTTP/HTTPS)

## Building

### Standard build (auto-detects platform)
```bash
gcc -shared -fPIC -O3 -o libtlsnoverify.so tls_noverify.c -ldl
```

### Platform-specific builds
```bash
# Linux with optimizations
gcc -shared -fPIC -O3 -D_GNU_SOURCE -o libtlsnoverify.so tls_noverify.c -ldl -pthread

# FreeBSD
cc -shared -fPIC -O3 -o libtlsnoverify.so tls_noverify.c

# Solaris
cc -shared -fPIC -O3 -D_POSIX_C_SOURCE=200112L -D__EXTENSIONS__ -o libtlsnoverify.so tls_noverify.c -ldl

# Old Linux devices (minimal dependencies)
gcc -shared -fPIC -Os -nostdlib -o libtlsnoverify.so tls_noverify.c -ldl
```

## Usage

```bash
# Basic usage
LD_PRELOAD=./libtlsnoverify.so curl https://expired.badssl.com/

# With debug output
TLS_NOVERIFY_DEBUG=1 LD_PRELOAD=./libtlsnoverify.so curl https://expired.badssl.com/

# Multiple applications
LD_PRELOAD=./libtlsnoverify.so wget https://self-signed.badssl.com/
LD_PRELOAD=./libtlsnoverify.so /usr/bin/gnutls-cli --verify-hostname=lol expired.badssl.com 443
```

## How It Works

The library uses LD_PRELOAD to intercept TLS library functions responsible for certificate verification. Key features:

### Platform Detection
- Automatically detects the target platform at compile time
- Uses platform-specific thread safety mechanisms:
  - **Linux**: pthread mutexes with futex optimization
  - **Solaris**: Atomic operations with memory barriers
  - **BSD/macOS**: Standard pthread mutexes
  - **OpenBSD**: Simple atomic swap operations

### TLS Library Interception
- **OpenSSL/BoringSSL/LibreSSL**: 
  - Hooks `SSL_CTX_set_verify()`, `SSL_set_verify()`, `X509_verify_cert()`
  - Bypasses hostname verification with `SSL_set1_host()`, `X509_check_host()`
  - Handles certificate expiration time manipulation
  
- **GnuTLS**: 
  - Hooks `gnutls_certificate_set_verify_function()`
  - Bypasses `gnutls_certificate_verify_peers2/3()`
  - Manipulates certificate expiration times to accept expired certs
  
- **NSS**: 
  - Hooks `SSL_AuthCertificateHook()`, `SSL_BadCertHook()`
  - Bypasses `CERT_VerifyCert()` and related functions
  
- **mbedTLS**: 
  - Hooks `mbedtls_ssl_conf_authmode()`, `mbedtls_ssl_conf_verify()`
  - Bypasses `mbedtls_x509_crt_verify()` functions
  
- **wolfSSL**: 
  - Hooks `wolfSSL_CTX_set_verify()`, `wolfSSL_set_verify()`
  - Bypasses domain name checking and trust verification
  
- **libcurl**: 
  - Intercepts `curl_easy_setopt()` to disable SSL verification options
  - Auto-disables verification on `curl_easy_init()`

## Security Warning

**This library completely disables TLS certificate verification. Use only for:**
- Development and testing
- Debugging TLS issues
- Accessing internal services with self-signed certificates

**Never use in production environments!**

## Environment Variables

- `TLS_NOVERIFY_DEBUG=1`: Enable debug output to stderr

## Compatibility Notes

### Tested Platforms
- Linux (kernel 2.6+, glibc and musl)
- FreeBSD 11+
- OpenBSD 6+
- NetBSD 8+
- Solaris 10+
- AIX 7.1+
- macOS 10.12+

### Known Limitations
- Some statically linked binaries may not be affected
- Applications using certificate pinning at a higher level may still fail
- Does not affect certificate validation done in interpreted languages' standard libraries

## License

Use at your own risk. This tool is provided for testing and debugging purposes only.