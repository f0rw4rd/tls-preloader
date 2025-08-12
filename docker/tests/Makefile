# Master Makefile for TLS verification bypass tests
CC ?= cc
CFLAGS ?= -O2 -I. -Wall
LDFLAGS ?= -ldl -lpthread

# Check for libcurl
HAVE_CURL := $(shell pkg-config --exists libcurl && echo yes)
ifeq ($(HAVE_CURL),yes)
    CFLAGS += -DHAS_CURL $(shell pkg-config --cflags libcurl)
    LDFLAGS += $(shell pkg-config --libs libcurl)
endif

# Main consolidated test
all: test_all

test_all: test_all.c test_runner.c test_library_common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Run the consolidated test
test: test_all
	@echo "Running consolidated tests..."
	@./test_all || exit 1

# Clean everything
clean:
	rm -f test_all *.o
	@for dir in libcurl openssl gnutls mbedtls wolfssl nss tools; do \
		if [ -f $$dir/Makefile ]; then \
			echo "Cleaning $$dir"; \
			$(MAKE) -C $$dir clean; \
		fi \
	done

.PHONY: all test clean