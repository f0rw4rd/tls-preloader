CC ?= gcc
STRIP ?= strip

# Base flags for portability
CFLAGS_BASE = -fPIC -O2 -fno-strict-aliasing -ffunction-sections -fdata-sections
CFLAGS_COMPAT = -D_POSIX_C_SOURCE=200112L

# Embedded/minimal flags
CFLAGS_MINIMAL = -Os -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables

# Linker flags
LDFLAGS = -shared -Wl,--gc-sections
LDFLAGS_STATIC = -static-libgcc -Wl,-Bstatic -ldl -Wl,-Bdynamic

# Default target
.PHONY: all clean install

all: libtlsnoverify.so

# Standard build
libtlsnoverify.so: tls_noverify.c
	$(CC) $(CFLAGS_BASE) $(CFLAGS_COMPAT) $(LDFLAGS) -o $@ $< -ldl
	$(STRIP) --strip-unneeded $@

# Minimal build for embedded
minimal: tls_noverify.c
	$(CC) $(CFLAGS_MINIMAL) $(CFLAGS_COMPAT) $(LDFLAGS) -o libtlsnoverify_minimal.so $< -ldl
	$(STRIP) --strip-all libtlsnoverify_minimal.so

# Static build
static: tls_noverify.c
	$(CC) $(CFLAGS_MINIMAL) $(CFLAGS_COMPAT) $(LDFLAGS) $(LDFLAGS_STATIC) -o libtlsnoverify_static.so $<
	$(STRIP) --strip-all libtlsnoverify_static.so

clean:
	rm -f libtlsnoverify*.so

install: libtlsnoverify.so
	install -D -m 755 libtlsnoverify.so $(DESTDIR)/usr/local/lib/libtlsnoverify.so

test: libtlsnoverify.so
	@echo "Testing with curl (should bypass certificate verification):"
	@echo "LD_PRELOAD=./libtlsnoverify.so curl https://expired.badssl.com/"
	@echo ""
	@echo "To enable debug output:"
	@echo "TLS_NOVERIFY_DEBUG=1 LD_PRELOAD=./libtlsnoverify.so curl https://expired.badssl.com/"