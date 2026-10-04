# Multi-stage build for eBPF TLS Tracer
# Builds on Debian trixie (current stable), runs on any Linux with kernel 5.5+

# --- Build stage ---
FROM debian:trixie-slim AS builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
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

# C-2 fix: Validate libbpf is not the CVE-2025-29481-affected version 1.5.0
RUN dpkg -l libbpf-dev | awk '/^ii/{print $3}' | grep -qv '^1\.5\.0' \
    || (echo "VULNERABLE: libbpf 1.5.0 detected (CVE-2025-29481)" && exit 1)

WORKDIR /build

COPY include/ include/
COPY src/ src/
COPY tests/ tests/
COPY Makefile .

RUN make all && make test

# --- Runtime stage ---
# Python 3.14 is the current stable interpreter line; the slim trixie variant
# tracks Debian stable security updates for the shared libraries we need.
FROM python:3.14-slim-trixie

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="ebpf-tls-tracer" \
      org.opencontainers.image.description="eBPF-based TLS traffic interceptor with Kubernetes metadata enrichment" \
      org.opencontainers.image.source="https://github.com/SCGIS-Wales/ebpf-tls-tracer" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY scripts/requirements.txt /tmp/requirements.txt

# C-1 fix: pull the latest patched OpenSSL (CVE-2025-15467) and other security
# updates from Debian stable at build time, then install only what the tracer
# and the shipper sidecars need at runtime.
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    libbpf1 \
    libelf1 \
    zlib1g \
    libssl3t64 \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -rf /var/lib/apt/lists/* /tmp/requirements.txt \
    && openssl version

WORKDIR /opt/tls_tracer

COPY --from=builder /build/bin/tls_tracer ./tls_tracer
COPY --from=builder /build/bin/bpf_program.o ./bpf_program.o
COPY scripts/s3_shipper.py ./scripts/s3_shipper.py
COPY scripts/kinesis_shipper.py ./scripts/kinesis_shipper.py
COPY scripts/splunk_hec_shipper.py ./scripts/splunk_hec_shipper.py

ENTRYPOINT ["./tls_tracer"]
CMD ["--help"]
