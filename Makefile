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

# Version (from git tag or 'dev')
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# User-space compilation flags (hardened for enterprise use)
CFLAGS     := -O2 -g -Wall -Wextra -Werror \
              -I$(INCLUDE_DIR) \
              -fstack-protector-strong \
              -D_FORTIFY_SOURCE=2 \
              -Wformat=2 -Wformat-security \
              -fPIE \
              -DVERSION=\"$(VERSION)\"
LDFLAGS    := -lbpf -lelf -lz -ldl -lpthread -pie -Wl,-z,relro,-z,now

# Source files
BPF_SRC    := $(SRC_DIR)/bpf_program.c
TRACER_SRC := $(SRC_DIR)/tls_tracer.c
PROTO_SRC  := $(SRC_DIR)/protocol.c
OUTPUT_SRC := $(SRC_DIR)/output.c
FILTER_SRC := $(SRC_DIR)/filter.c
K8S_SRC    := $(SRC_DIR)/k8s.c
SESSION_SRC := $(SRC_DIR)/session.c
PCAP_SRC   := $(SRC_DIR)/pcap.c
METRICS_SRC := $(SRC_DIR)/metrics.c

# Output files
BPF_OBJ    := $(BIN_DIR)/bpf_program.o
TRACER_BIN := $(BIN_DIR)/tls_tracer

# Test files
TEST_SRC   := $(TEST_DIR)/test_tracer.c
TEST_BIN   := $(BUILD_DIR)/test_tracer
TEST_HELPERS_SRC := $(TEST_DIR)/test_helpers.c
TEST_HELPERS_BIN := $(BUILD_DIR)/test_helpers
TEST_FILTER_SRC := $(TEST_DIR)/test_filter.c
TEST_FILTER_BIN := $(BUILD_DIR)/test_filter

# Install paths
PREFIX     ?= /usr/local
INSTALL_BIN := $(PREFIX)/bin
INSTALL_LIB := $(PREFIX)/lib/tls_tracer

.PHONY: all clean install uninstall test help check-deps

all: $(BPF_OBJ) $(TRACER_BIN)

# Create output directories
$(BUILD_DIR) $(BIN_DIR):
	@mkdir -p $@

# Compile eBPF program (must use clang with bpf target)
$(BPF_OBJ): $(BPF_SRC) $(INCLUDE_DIR)/tracer.h | $(BIN_DIR)
	@echo "  BPF     $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile user-space tracer (multi-object)
TRACER_HDRS := $(INCLUDE_DIR)/tracer.h $(INCLUDE_DIR)/config.h \
               $(INCLUDE_DIR)/output.h $(INCLUDE_DIR)/protocol.h \
               $(INCLUDE_DIR)/filter.h $(INCLUDE_DIR)/k8s.h \
               $(INCLUDE_DIR)/session.h $(INCLUDE_DIR)/pcap.h \
               $(INCLUDE_DIR)/metrics.h

$(BUILD_DIR)/tls_tracer.o: $(TRACER_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/protocol.o: $(PROTO_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/output.o: $(OUTPUT_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/filter.o: $(FILTER_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/k8s.o: $(K8S_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/session.o: $(SESSION_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pcap.o: $(PCAP_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/metrics.o: $(METRICS_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

TRACER_OBJS := $(BUILD_DIR)/tls_tracer.o $(BUILD_DIR)/protocol.o \
               $(BUILD_DIR)/output.o $(BUILD_DIR)/filter.o $(BUILD_DIR)/k8s.o \
               $(BUILD_DIR)/session.o $(BUILD_DIR)/pcap.o $(BUILD_DIR)/metrics.o

$(TRACER_BIN): $(TRACER_OBJS) | $(BIN_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^ $(LDFLAGS)

# Tests
$(BUILD_DIR)/test_tracer.o: $(TEST_DIR)/test_tracer.c $(INCLUDE_DIR)/tracer.h | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/test_tracer.o | $(BUILD_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^ $(LDFLAGS)

# Helper function tests (JSON, HTTP, Kafka, sanitize, addr formatting)
$(BUILD_DIR)/test_helpers.o: $(TEST_HELPERS_SRC) $(INCLUDE_DIR)/tracer.h | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(TEST_HELPERS_BIN): $(BUILD_DIR)/test_helpers.o | $(BUILD_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^ $(LDFLAGS)

# Filter unit tests (needs filter.o and protocol.o for function definitions)
$(BUILD_DIR)/test_filter.o: $(TEST_FILTER_SRC) $(TRACER_HDRS) | $(BUILD_DIR)
	@echo "  CC      $@"
	@$(GCC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(TEST_FILTER_BIN): $(BUILD_DIR)/test_filter.o $(BUILD_DIR)/filter.o $(BUILD_DIR)/protocol.o | $(BUILD_DIR)
	@echo "  LD      $@"
	@$(GCC) -o $@ $^ $(LDFLAGS)

test: $(TEST_BIN) $(TEST_HELPERS_BIN) $(TEST_FILTER_BIN)
	@echo "  TEST    Running struct/constant tests..."
	@./$(TEST_BIN)
	@echo "  TEST    Running helper function tests..."
	@./$(TEST_HELPERS_BIN)
	@echo "  TEST    Running filter tests..."
	@./$(TEST_FILTER_BIN)

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

# C-2 fix: check build dependencies for known CVEs
check-deps:
	@echo "  CHECK   libbpf version"
	@pkg-config --modversion libbpf 2>/dev/null | grep -qv '^1\.5\.0$$' || \
	  (echo "ERROR: libbpf 1.5.0 is vulnerable (CVE-2025-29481)" && exit 1)
	@echo "  CHECK   dependencies OK"

help:
	@echo "eBPF TLS Tracer build targets:"
	@echo "  all        - Build BPF program and tracer binary (default)"
	@echo "  test       - Build and run unit tests"
	@echo "  check-deps - Check build deps for known CVEs"
	@echo "  install    - Install to $(PREFIX)"
	@echo "  uninstall  - Remove installed files"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this message"
