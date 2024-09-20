# Use Debian Bullseye, which is more compatible with kernel development
FROM debian:bullseye-slim

# Set non-interactive frontend to avoid tzdata prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies, including generic headers for eBPF development
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    libbpf-dev \
    linux-headers-amd64 \
    build-essential \
    iproute2 \
    git \
    wget \
    curl \
    bpfcc-tools \
    libelf-dev \
    iputils-ping \
    net-tools \
    python3 \
    python3-pip \
    python3-setuptools \
    linux-libc-dev \
    kmod \
    libmnl-dev

# Set up working directory
WORKDIR /app

# Copy all project files into the container
COPY include /app/include
COPY src /app/src
COPY Makefile /app/Makefile

# Check if the Makefile and necessary files exist
RUN ls -la /app

# Compile the eBPF program and user-space application
RUN make

# Command to run the CLI tool (you can adjust this based on your needs)
CMD ["./cli_tool", "--start"]
