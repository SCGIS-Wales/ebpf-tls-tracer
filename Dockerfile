# Multi-stage build for eBPF TLS Tracer on Amazon Linux 2023

# --- Build stage ---
FROM amazonlinux:2023 AS builder

RUN dnf install -y \
    clang \
    llvm \
    gcc \
    make \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    kernel-devel \
    kernel-headers \
    && dnf clean all

WORKDIR /build

COPY include/ include/
COPY src/ src/
COPY tests/ tests/
COPY Makefile .

RUN make all && make test

# --- Runtime stage ---
FROM amazonlinux:2023

RUN dnf install -y \
    libbpf \
    elfutils-libelf \
    zlib \
    openssl-libs \
    && dnf clean all

WORKDIR /opt/tls_tracer

COPY --from=builder /build/bin/tls_tracer ./tls_tracer
COPY --from=builder /build/bin/bpf_program.o ./bpf_program.o

ENTRYPOINT ["./tls_tracer"]
CMD ["--help"]
