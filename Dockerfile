# Multi-stage build for eBPF TLS Tracer
# Builds on Debian (reliable build toolchain), runs on any Linux with kernel 5.5+

# --- Build stage ---
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    gcc \
    make \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    linux-libc-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY include/ include/
COPY src/ src/
COPY tests/ tests/
COPY Makefile .

RUN make all && make test

# --- Runtime stage ---
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libelf1 \
    zlib1g \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tls_tracer

COPY --from=builder /build/bin/tls_tracer ./tls_tracer
COPY --from=builder /build/bin/bpf_program.o ./bpf_program.o

ENTRYPOINT ["./tls_tracer"]
CMD ["--help"]
