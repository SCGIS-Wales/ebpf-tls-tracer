# Multi-stage build for eBPF TLS Tracer
# Builds on Debian trixie (latest), runs on any Linux with kernel 5.5+

# --- Build stage ---
FROM debian:trixie-slim AS builder

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
# A5 fix: use stable Python 3.12 instead of pre-release 3.14
FROM python:3.12-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libelf1 \
    zlib1g \
    libssl3t64 \
    && pip install --no-cache-dir boto3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tls_tracer

COPY --from=builder /build/bin/tls_tracer ./tls_tracer
COPY --from=builder /build/bin/bpf_program.o ./bpf_program.o
COPY scripts/s3_shipper.py ./scripts/s3_shipper.py
COPY scripts/kinesis_shipper.py ./scripts/kinesis_shipper.py

ENTRYPOINT ["./tls_tracer"]
CMD ["--help"]
