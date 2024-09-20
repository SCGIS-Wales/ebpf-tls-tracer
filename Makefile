# Makefile
BPFTOOL ?= bpftool

all: bpf_program.o user_space cli_tool

bpf_program.o: src/bpf_program.c
	clang -O2 -target bpf -c src/bpf_program.c -o src/bpf_program.o

user_space: src/user_space.c
	gcc -o user_space src/user_space.c -lbpf

cli_tool: src/cli_tool.c
	gcc -o cli_tool src/cli_tool.c

clean:
	rm -f src/*.o user_space cli_tool

.PHONY: all clean
