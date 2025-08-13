CC ?= gcc
STRIP ?= strip

# Base flags for portability
CFLAGS_BASE = -fPIC -O2 -fno-strict-aliasing -ffunction-sections -fdata-sections -Wall -Werror
CFLAGS_COMPAT = -D_POSIX_C_SOURCE=200112L

# Embedded/minimal flags
CFLAGS_MINIMAL = -Os -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables

# Linker flags
LDFLAGS = -shared -Wl,--gc-sections
LDFLAGS_STATIC = -static-libgcc -Wl,-Bstatic -ldl -Wl,-Bdynamic

# Default target
.PHONY: all clean

all: libtlsnoverify.so

# Get git commit ID
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Standard build
libtlsnoverify.so: tls_noverify.c
	$(CC) $(CFLAGS_BASE) $(CFLAGS_COMPAT) -D__GIT_COMMIT__=\"$(GIT_COMMIT)\" $(LDFLAGS) -o $@ $< -ldl
	$(STRIP) --strip-unneeded $@

clean:
	rm -f libtlsnoverify*.so
