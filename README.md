# TLS Tracer

An eBPF-based CLI tool for intercepting and inspecting TLS/SSL traffic in real time on Linux. It attaches uprobes to OpenSSL's `SSL_read` and `SSL_write` functions to capture plaintext data flowing through TLS connections — without modifying applications or terminating TLS sessions.

Each captured event includes the **remote IP address** (IPv4 or IPv6) and **port** of the connection, correlated via kernel-level kprobes on the `connect()` syscall.

## Features

- **Trace TLS connections** and capture plaintext data from `SSL_read`/`SSL_write`
- **Capture remote IP addresses** (IPv4 and IPv6) behind hostnames via connect() kprobe correlation
- **Filter** captured data by PID, UID, or other criteria
- **Output** in human-readable text or structured JSON format
- **Hex dump** mode for binary protocol inspection
- **Auto-detection** of the system's OpenSSL library path
- **Low overhead** — uses eBPF perf buffers for efficient kernel-to-user data transfer
- **Graceful shutdown** with proper resource cleanup on Ctrl+C / SIGTERM

## Prerequisites

### Linux Kernel Requirements

**Minimum kernel version: 5.5** (for `bpf_probe_read_user()`). Recommended: **6.1+** for full feature support.

The following kernel configuration options **must be enabled** (all are enabled by default on most modern distributions):

| Config Option | Purpose | Required Since |
|---|---|---|
| `CONFIG_BPF=y` | Core BPF subsystem | 4.1 |
| `CONFIG_BPF_SYSCALL=y` | `bpf()` system call | 4.4 |
| `CONFIG_BPF_JIT=y` | JIT compiler for BPF programs | 4.1 |
| `CONFIG_BPF_EVENTS=y` | BPF-based tracing events | 4.4 |
| `CONFIG_KPROBE_EVENTS=y` | kprobe-based tracing (for IP capture) | 4.1 |
| `CONFIG_UPROBE_EVENTS=y` | uprobe-based tracing (for SSL hooks) | 4.1 |
| `CONFIG_DEBUG_INFO_BTF=y` | BTF type info (for CO-RE portability) | 5.2 |

**Verify on your system:**

```bash
# Check kernel version
uname -r

# Check BTF support (required for modern libbpf)
ls -la /sys/kernel/btf/vmlinux

# Check BPF JIT
cat /proc/sys/net/core/bpf_jit_enable   # Should be 1 or 2

# Check kernel config (if available)
grep -E 'CONFIG_BPF|CONFIG_UPROBE|CONFIG_KPROBE' /boot/config-$(uname -r)
```

### Runtime Requirements

- **Root privileges** or capabilities `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`
- **OpenSSL** (`libssl.so`) installed on the target system (auto-detected)
- **debugfs / tracefs** mounted (usually at `/sys/kernel/debug` or `/sys/kernel/tracing`)

### Build Dependencies

| Package (Debian/Ubuntu) | Package (RHEL/AL2023/Fedora) | Purpose |
|---|---|---|
| `clang` | `clang` | BPF program compiler |
| `llvm` | `llvm` | BPF target support |
| `gcc` | `gcc` | User-space compiler |
| `make` | `make` | Build system |
| `libbpf-dev` | `libbpf-devel` | BPF user-space library |
| `libelf-dev` | `elfutils-libelf-devel` | ELF parsing |
| `zlib1g-dev` | `zlib-devel` | Compression |
| `linux-libc-dev` | `kernel-headers` | Kernel headers |

## Building

```bash
# Debian/Ubuntu
sudo apt-get install clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev

# RHEL/AL2023/Fedora
sudo dnf install clang llvm gcc make libbpf-devel elfutils-libelf-devel zlib-devel kernel-devel kernel-headers

# Build
make

# Run tests
make test

# Install system-wide (optional)
sudo make install
```

## Usage

```bash
# Trace all TLS traffic (requires root)
sudo ./bin/tls_tracer

# Filter by process ID
sudo ./bin/tls_tracer -p 1234

# Output in JSON format
sudo ./bin/tls_tracer -f json

# Hex dump of captured data
sudo ./bin/tls_tracer -x

# Filter by UID and show verbose output
sudo ./bin/tls_tracer -u 1000 -v

# Specify a custom OpenSSL library path
sudo ./bin/tls_tracer -l /path/to/libssl.so
```

### Options

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-p` | `--pid PID` | Filter by process ID |
| `-u` | `--uid UID` | Filter by user ID |
| `-l` | `--lib PATH` | Path to libssl.so (auto-detected by default) |
| `-f` | `--format FMT` | Output format: `text` (default) or `json` |
| `-x` | `--hex` | Show hex dump of captured data |
| `-d` | `--data-only` | Print only captured data (no headers) |
| `-v` | `--verbose` | Verbose output (shows library path, probe status) |
| `-h` | `--help` | Show help message |

### Example Output

**Text mode (default):**

```
12:34:56     WRITE  PID=1234   TID=1234   UID=1000 COMM=curl            ADDR=93.184.216.34:443  LEN=78
GET /api/v1/status HTTP/1.1
Host: example.com

12:34:56     READ   PID=1234   TID=1234   UID=1000 COMM=curl            ADDR=93.184.216.34:443  LEN=256
HTTP/1.1 200 OK
Content-Type: application/json
```

**JSON mode (`-f json`):**

```json
{"timestamp_ns":123456789,"pid":1234,"tid":1234,"uid":1000,"comm":"curl","direction":"WRITE","remote_addr":"93.184.216.34:443","data_len":78,"data":"..."}
```

## Docker

The container image is published to GitHub Container Registry on every push to `main`.

```bash
# Pull from GHCR
docker pull ghcr.io/scgis-wales/ebpf_tls_cli:latest

# Or build locally
docker build -t tls_tracer .

# Run (requires --privileged for eBPF access)
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --pid=host \
  ghcr.io/scgis-wales/ebpf_tls_cli:latest -v -f json
```

## Amazon Linux 2023 (AL2023)

AL2023 ships with kernel 6.1+ and **fully supports eBPF out of the box** — no kernel recompilation or feature flags needed. BTF, uprobes, kprobes, and BPF JIT are all enabled in the stock kernel.

### Install on AL2023

```bash
sudo dnf install -y \
  clang llvm gcc make \
  libbpf-devel elfutils-libelf-devel zlib-devel \
  kernel-devel-$(uname -r) kernel-headers-$(uname -r) \
  openssl-devel bpftool

git clone https://github.com/SCGIS-Wales/ebpf_tls_cli.git
cd ebpf_tls_cli
make && make test
sudo ./bin/tls_tracer -v
```

### EC2 Userdata (automated setup)

Use this userdata script to install and start TLS Tracer automatically on an AL2023 EC2 instance:

```bash
#!/bin/bash
set -euo pipefail

# Install build dependencies
dnf install -y \
  clang llvm gcc make \
  libbpf-devel elfutils-libelf-devel zlib-devel \
  kernel-devel-$(uname -r) kernel-headers-$(uname -r) \
  openssl-devel bpftool git

# Clone and build
cd /opt
git clone https://github.com/SCGIS-Wales/ebpf_tls_cli.git
cd ebpf_tls_cli
make && make test
make install

# Verify eBPF support
echo "=== Kernel: $(uname -r) ==="
ls -la /sys/kernel/btf/vmlinux && echo "BTF: OK"
cat /proc/sys/net/core/bpf_jit_enable && echo "BPF JIT: OK"
bpftool feature probe kernel 2>/dev/null | head -20 || true
```

### AL2023 Kernel Configuration (pre-enabled)

The following are **already enabled** in AL2023's stock kernel — no action required:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
```

## Kubernetes Deployment (v1.34+)

TLS Tracer runs as a **DaemonSet** to monitor TLS traffic on every node. It requires privileged access to the host kernel for eBPF.

### Kubernetes Prerequisites

| Requirement | Details |
|---|---|
| **Kubernetes version** | 1.34+ |
| **Node OS** | Linux with kernel 6.1+ (AL2023 recommended) |
| **Node kernel config** | eBPF, kprobes, uprobes enabled (see Prerequisites above) |
| **Container runtime** | containerd or CRI-O with privileged container support |
| **RBAC** | Cluster admin access to create privileged DaemonSets |
| **OpenSSL on nodes** | `libssl.so` must be present on each node |

### EKS with AL2023 Nodes

Amazon EKS with AL2023 AMI nodes is the recommended deployment target. AL2023 nodes have all required eBPF kernel features enabled by default.

```bash
# Create EKS cluster with AL2023 nodes (eksctl)
eksctl create cluster \
  --name my-cluster \
  --version 1.34 \
  --nodegroup-name al2023-nodes \
  --node-type m5.large \
  --node-ami-family AmazonLinux2023

# Deploy TLS Tracer
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml

# Check status
kubectl -n tls-tracer get pods -o wide

# View logs (JSON output from a specific node's pod)
kubectl -n tls-tracer logs -l app=tls-tracer --tail=50
```

### Node Configuration via EKS Userdata

If nodes need build tools (for custom builds), add this to the EKS node group launch template userdata:

```bash
#!/bin/bash
dnf install -y libbpf openssl-libs bpftool
# The container image has everything else built-in
```

### What Needs to Be Configured

For Kubernetes 1.34+ on Linux kernel 6.x, the following must be true on each node:

1. **Kernel modules loaded** (usually auto-loaded):
   ```bash
   # Verify on a node
   lsmod | grep -E 'bpf|uprobe|kprobe'
   # If not loaded:
   modprobe uprobeevents
   modprobe kprobeevents
   ```

2. **BPF filesystem mounted** (auto-mounted on modern distros):
   ```bash
   mount -t bpf bpf /sys/fs/bpf
   ```

3. **debugfs / tracefs mounted** (required for uprobe events):
   ```bash
   mount -t debugfs debugfs /sys/kernel/debug
   mount -t tracefs tracefs /sys/kernel/tracing
   ```

4. **Privileged containers allowed** in the Pod Security Admission (PSA):
   ```yaml
   # If using Pod Security Standards, the namespace needs 'privileged' level
   apiVersion: v1
   kind: Namespace
   metadata:
     name: tls-tracer
     labels:
       pod-security.kubernetes.io/enforce: privileged
   ```

### Removing

```bash
kubectl delete -f deploy/kubernetes/daemonset.yaml
kubectl delete -f deploy/kubernetes/rbac.yaml
kubectl delete -f deploy/kubernetes/namespace.yaml
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                       User Space                         │
│                                                          │
│  tls_tracer (CLI)                                        │
│    ├── Argument parsing (getopt_long)                    │
│    ├── BPF object loading (libbpf)                       │
│    ├── Kprobe attach → connect() for IP capture          │
│    ├── Uprobe attach → SSL_read/SSL_write                │
│    ├── Perf buffer polling                               │
│    └── Event formatting (text/json) with IP:port         │
│                                                          │
├───────────────── perf buffer ────────────────────────────┤
│                                                          │
│                      Kernel Space                        │
│                                                          │
│  bpf_program.o (eBPF probes)                             │
│    ├── kprobe/__sys_connect    → save sockaddr           │
│    ├── kretprobe/__sys_connect → store IP:port in map    │
│    ├── uprobe/SSL_read         → save buffer ptr         │
│    ├── uretprobe/SSL_read      → capture data + IP       │
│    ├── uprobe/SSL_write        → save buffer ptr         │
│    └── uretprobe/SSL_write     → capture data + IP       │
│                                                          │
│  BPF Maps:                                               │
│    ├── ssl_args_map   (HASH) → per-thread SSL args       │
│    ├── conn_info_map  (HASH) → pid_tgid → remote addr   │
│    ├── connect_args_map (HASH) → connect() args          │
│    └── tls_events (PERF_EVENT_ARRAY) → user-space        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### How IP Capture Works

1. A **kprobe on `connect()`** saves the `sockaddr` (containing the remote IP and port) on syscall entry
2. A **kretprobe on `connect()`** reads the saved address on successful return and stores `{pid_tgid} → {remote_ip, remote_port}` in `conn_info_map`
3. When **SSL_read/SSL_write** fires, the uretprobe looks up `conn_info_map` by `pid_tgid` to enrich the TLS event with the connection's remote IP address and port

This captures the actual IP address the connection was established to — resolving the IP behind any hostname.

## Project Structure

```
ebpf_tls_cli/
├── include/
│   └── tracer.h              # Shared data structures (kernel + user space)
├── src/
│   ├── bpf_program.c         # eBPF kernel probes (compiled to BPF bytecode)
│   └── tls_tracer.c          # User-space CLI tool
├── tests/
│   └── test_tracer.c         # Unit tests
├── deploy/
│   └── kubernetes/
│       ├── namespace.yaml    # Namespace definition
│       ├── rbac.yaml         # ServiceAccount and RBAC
│       └── daemonset.yaml    # DaemonSet for per-node deployment
├── .github/
│   └── workflows/
│       └── build.yml         # CI: build, test, functional test, Docker publish
├── Dockerfile                # Multi-stage build (AL2023 base)
├── Makefile                  # Build system
├── LICENSE                   # MIT License
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
