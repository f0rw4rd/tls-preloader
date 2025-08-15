#!/bin/bash
# CI/CD Ready Docker Test Runner for TLS Verification Bypass Library
# This script runs all tests in Docker containers for consistent results

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
PARALLEL=false
VERBOSE=true
FAIL_FAST=true
TEST_FILTER=""
DOCKER_ARGS="-e TLS_NOVERIFY_DEBUG=1 -e TLS_NOVERIFY_BACKTRACE=1"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel)
            PARALLEL=true
            shift
            ;;
        --quiet)
            VERBOSE=false
            DOCKER_ARGS=""
            shift
            ;;
        --no-fail-fast)
            FAIL_FAST=false
            shift
            ;;
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --parallel       Run tests in parallel"
            echo "  --quiet          Disable verbose output"
            echo "  --no-fail-fast   Continue on test failures"
            echo "  --filter REGEX   Only run tests matching regex"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to run tests in a Docker container
run_docker_test() {
    local test_name=$1
    local dockerfile=$2
    local description=$3
    local container_name="tls-test-${test_name}-$$"
    
    print_status "$YELLOW" "\n=========================================="
    print_status "$YELLOW" "$description"
    print_status "$YELLOW" "=========================================="
    
    # Build Docker image
    local image_name="tls-bypass-test:${test_name}"
    print_status "$YELLOW" "Building Docker image: $image_name"
    
    docker build -f "$dockerfile" -t "$image_name" "$PROJECT_ROOT"
    
    if [ $? -ne 0 ]; then
        print_status "$RED" "✗ Failed to build Docker image for $test_name"
        return 1
    fi
    
    # Run tests in container
    print_status "$YELLOW" "Running tests in container..."
    
    local exit_code=0
    
    print_status "$YELLOW" "Container: $container_name"
    print_status "$YELLOW" "Image: $image_name"
    print_status "$YELLOW" "Docker args: $DOCKER_ARGS"
    echo "----------------------------------------"
    
    if docker run --rm --name "$container_name" $DOCKER_ARGS "$image_name"; then
        print_status "$GREEN" "✓ $test_name tests passed"
    else
        exit_code=$?
        print_status "$RED" "✗ $test_name tests failed (exit code: $exit_code)"
        if [ "$FAIL_FAST" = true ]; then
            return $exit_code
        fi
    fi
    
    return $exit_code
}

# Function to run tests in parallel
run_parallel_tests() {
    local pids=()
    local results=()
    
    # Start all test containers
    for test_env in "${TEST_ENVIRONMENTS[@]}"; do
        IFS='|' read -r name dockerfile description <<< "$test_env"
        run_docker_test "$name" "$dockerfile" "$description" &
        pids+=($!)
    done
    
    # Wait for all tests to complete
    local failed=0
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            ((failed++))
        fi
    done
    
    return $failed
}

# Main execution
main() {
    print_status "$GREEN" "=========================================="
    print_status "$GREEN" "TLS Verification Bypass Test Suite"
    print_status "$GREEN" "Running all tests in Docker containers"
    print_status "$GREEN" "=========================================="
    
    # Check Docker availability
    if ! command -v docker &> /dev/null; then
        print_status "$RED" "Error: Docker is not installed or not in PATH"
        exit 1
    fi
    
    print_status "$YELLOW" "Docker version:"
    docker --version
    
    # Check if Docker daemon is running
    if ! docker ps > /dev/null 2>&1; then
        print_status "$RED" "Error: Docker daemon is not running"
        exit 1
    fi
    
    # Define test environments
    TEST_ENVIRONMENTS=(
        "alpine|$SCRIPT_DIR/alpine/Dockerfile|Alpine Linux (musl libc)"
        "ubuntu|$SCRIPT_DIR/ubuntu/Dockerfile|Ubuntu 22.04 (glibc)"
    )
    
    print_status "$YELLOW" "Test configuration:"
    echo "  Parallel: $PARALLEL"
    echo "  Fail fast: $FAIL_FAST"
    echo "  Verbose: $VERBOSE"
    echo "  Filter: ${TEST_FILTER:-none}"
    echo "  Test environments: ${#TEST_ENVIRONMENTS[@]}"
    
    # Run tests
    local start_time=$(date +%s)
    local exit_code=0
    
    if [ "$PARALLEL" = true ]; then
        print_status "$YELLOW" "Running tests in parallel mode..."
        run_parallel_tests
        exit_code=$?
    else
        # Run tests sequentially
        for test_env in "${TEST_ENVIRONMENTS[@]}"; do
            IFS='|' read -r name dockerfile description <<< "$test_env"
            
            # Apply filter if specified
            if [ -n "$TEST_FILTER" ] && [[ ! "$name" =~ $TEST_FILTER ]]; then
                continue
            fi
            
            if ! run_docker_test "$name" "$dockerfile" "$description"; then
                exit_code=1
                if [ "$FAIL_FAST" = true ]; then
                    break
                fi
            fi
        done
    fi
    
    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo
    print_status "$YELLOW" "Test execution details:"
    echo "  Start time: $(date -d @$start_time '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r $start_time '+%Y-%m-%d %H:%M:%S')"
    echo "  End time: $(date -d @$end_time '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r $end_time '+%Y-%m-%d %H:%M:%S')"
    echo "  Duration: ${duration} seconds"
    
    # Final summary
    echo
    print_status "$YELLOW" "=========================================="
    if [ $exit_code -eq 0 ]; then
        print_status "$GREEN" "✓ All tests passed!"
    else
        print_status "$RED" "✗ Some tests failed!"
    fi
    print_status "$YELLOW" "Total execution time: ${duration}s"
    print_status "$YELLOW" "=========================================="
    
    exit $exit_code
}

# Run main function
main "$@"
