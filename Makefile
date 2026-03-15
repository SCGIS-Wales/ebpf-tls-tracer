# eBPF TLS Tracer - Makefile
# Builds the eBPF kernel probe and user-space CLI tool

CLANG      ?= clang
GCC        ?= gcc
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
SRC_DIR    := src
INCLUDE_DIR := include
BUILD_DIR  := build
BIN_DIR    := bin
TEST_DIR   := tests

# Detect arch-specific system include path (needed for asm/types.h on Debian/Ubuntu)
UNAME_M    := $(shell uname -m)
SYS_INC    := $(wildcard /usr/include/$(UNAME_M)-linux-gnu)

# BPF compilation flags
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(INCLUDE_DIR) \
              $(if $(SYS_INC),-isystem $(SYS_INC)) \
              -Wall -Werror

# User-space compilation flags
CFLAGS     := -O2 -g -Wall -Wextra -Werror \
              -I$(INCLUDE_DIR)
LDFLAGS    := -lbpf -lelf -lz

# Source files
BPF_SRC    := $(SRC_DIR)/bpf_program.c
TRACER_SRC := $(SRC_DIR)/tls_tracer.c

# Output files
BPF_OBJ    := $(BIN_DIR)/bpf_program.o
TRACER_BIN := $(BIN_DIR)/tls_tracer

# Test files
TEST_SRC   := $(TEST_DIR)/test_tracer.c
TEST_BIN   := $(BUILD_DIR)/test_tracer
TEST_HELPERS_SRC := $(TEST_DIR)/test_helpers.c
TEST_HELPERS_BIN := $(BUILD_DIR)/test_helpers

# Install paths
PREFIX     ?= /usr/local
INSTALL_BIN := $(PREFIX)/bin
INSTALL_LIB := $(PREFIX)/lib/tls_tracer

.PHONY: all clean install uninstall test help

all: $(BPF_OBJ) $(TRACER_BIN)

# Create output directories
$(BUILD_DIR) $(BIN_DIR):
	@mkdir -p $@

# Compile eBPF program (must use clang with bpf target)
$(BPF_OBJ): $(BPF_SRC) $(INCLUDE_DIR)/tracer.h | $(BIN_DIR)
	@echo "  BPF     $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile user-space tracer
$(BUILD_DIR)/tls_tracer.o: $(TRACER_SRC) $(INCLUDE_DIR)/tracer.h | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(TRACER_BIN): $(BUILD_DIR)/tls_tracer.o | $(BIN_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^ $(LDFLAGS)

# Tests
$(BUILD_DIR)/test_tracer.o: $(TEST_DIR)/test_tracer.c $(INCLUDE_DIR)/tracer.h | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/test_tracer.o | $(BUILD_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^

# Helper function tests (JSON, HTTP, Kafka, sanitize, addr formatting)
$(BUILD_DIR)/test_helpers.o: $(TEST_HELPERS_SRC) $(INCLUDE_DIR)/tracer.h | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(TEST_HELPERS_BIN): $(BUILD_DIR)/test_helpers.o | $(BUILD_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^

test: $(TEST_BIN) $(TEST_HELPERS_BIN)
	@echo "  TEST    Running struct/constant tests..."
	@./$(TEST_BIN)
	@echo "  TEST    Running helper function tests..."
	@./$(TEST_HELPERS_BIN)

# Install
install: all
	@echo "  INSTALL $(INSTALL_BIN)/tls_tracer"
	@install -d $(INSTALL_BIN) $(INSTALL_LIB)
	@install -m 755 $(TRACER_BIN) $(INSTALL_BIN)/tls_tracer
	@install -m 644 $(BPF_OBJ) $(INSTALL_LIB)/bpf_program.o

uninstall:
	@echo "  REMOVE  $(INSTALL_BIN)/tls_tracer"
	@rm -f $(INSTALL_BIN)/tls_tracer
	@rm -rf $(INSTALL_LIB)

clean:
	@echo "  CLEAN"
	@rm -rf $(BUILD_DIR) $(BIN_DIR)

help:
	@echo "eBPF TLS Tracer build targets:"
	@echo "  all       - Build BPF program and tracer binary (default)"
	@echo "  test      - Build and run unit tests"
	@echo "  install   - Install to $(PREFIX)"
	@echo "  uninstall - Remove installed files"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this message"
