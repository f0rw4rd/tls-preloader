# Makefile for CI/CD Docker tests
.PHONY: test test-alpine test-ubuntu test-debian test-multiversion test-parallel clean help

# Default target
test: test-alpine test-ubuntu test-debian

# Individual test targets
test-alpine:
	@echo "Running Alpine Linux tests..."
	./test-runner.sh --filter alpine

test-ubuntu:
	@echo "Running Ubuntu tests..."
	./test-runner.sh --filter ubuntu

test-debian:
	@echo "Running Debian tests..."
	./test-runner.sh --filter debian

test-multiversion:
	@echo "Running multi-version tests..."
	./test-runner.sh --filter multiversion

# Run all tests in parallel
test-parallel:
	@echo "Running all tests in parallel..."
	./test-runner.sh --parallel

# Run all tests with verbose output
test-verbose:
	@echo "Running all tests with debug output..."
	./test-runner.sh --verbose

# CI/CD entry point
ci-test:
	@echo "Running CI/CD test suite..."
	./test-runner.sh --fail-fast

# Clean Docker images
clean:
	@echo "Cleaning test Docker images..."
	docker rmi -f tls-bypass-test:alpine tls-bypass-test:ubuntu tls-bypass-test:debian tls-bypass-test:multiversion 2>/dev/null || true

# Help
help:
	@echo "TLS Verification Bypass Test Suite"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  test              Run all tests sequentially (default)"
	@echo "  test-alpine       Run Alpine Linux tests only"
	@echo "  test-ubuntu       Run Ubuntu tests only"
	@echo "  test-debian       Run Debian tests only"
	@echo "  test-multiversion Run multi-version library tests"
	@echo "  test-parallel     Run all tests in parallel"
	@echo "  test-verbose      Run all tests with debug output"
	@echo "  ci-test           Run tests for CI/CD (fail fast)"
	@echo "  clean             Remove test Docker images"
	@echo "  help              Show this help message"