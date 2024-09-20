# Complete Makefile for building the eBPF program and user-space application

# Compiler and flags
CC = clang
CFLAGS = -O2 -target bpf -I./include  # Include the headers from the 'include' directory

# Paths
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
INCLUDE_DIR = include

# Sources and objects
BPF_PROGRAM = $(SRC_DIR)/bpf_program.c
USER_PROGRAM = $(SRC_DIR)/user_space.c
CLI_TOOL = $(SRC_DIR)/cli_tool.c
BPF_OBJECT = $(OBJ_DIR)/bpf_program.o
USER_OBJECT = $(OBJ_DIR)/user_space.o
CLI_OBJECT = $(OBJ_DIR)/cli_tool.o

# Output binaries
USER_BINARY = $(BIN_DIR)/user_space
CLI_BINARY = $(BIN_DIR)/cli_tool

# Create necessary directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Default target
all: $(OBJ_DIR) $(BIN_DIR) $(BPF_OBJECT) $(USER_BINARY) $(CLI_BINARY)

# Compile eBPF program
$(BPF_OBJECT): $(BPF_PROGRAM)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile user-space program
$(USER_OBJECT): $(USER_PROGRAM)
	gcc -I$(INCLUDE_DIR) -c $< -o $@

# Compile CLI tool
$(CLI_OBJECT): $(CLI_TOOL)
	gcc -I$(INCLUDE_DIR) -c $< -o $@

# Link user-space binary
$(USER_BINARY): $(USER_OBJECT)
	gcc -o $@ $^

# Link CLI tool binary
$(CLI_BINARY): $(CLI_OBJECT)
	gcc -o $@ $^

# Clean up build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
