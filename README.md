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

## Quick Start

**Option 1 — Pre-built binary** (x86_64 Linux):

Download from [GitHub Releases](https://github.com/SCGIS-Wales/ebpf-tls-tracer/releases), then:

```bash
tar xzf tls_tracer-linux-x86_64.tar.gz
sudo ./tls_tracer -v
```

**Option 2 — Docker** (any Linux with kernel 5.5+):

```bash
docker pull ghcr.io/scgis-wales/ebpf-tls-tracer:latest
sudo docker run --rm --privileged --pid=host ghcr.io/scgis-wales/ebpf-tls-tracer:latest -v
```

**Option 3 — Build from source** (see [Building from Source](#building-from-source) below).

## Requirements for Running (CLI)

These are what you need on the **target machine** where the tool will execute:

| Requirement | Details |
|---|---|
| **OS** | Linux (x86_64) |
| **Kernel** | 5.5+ minimum, **6.1+ recommended** |
| **Privileges** | Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` |
| **OpenSSL** | `libssl.so` must be installed (auto-detected) |
| **Runtime libs** | `libbpf`, `libelf`, `zlib` |
| **Filesystems** | debugfs/tracefs mounted (standard on modern distros) |

The following kernel config options must be enabled (they are by default on Ubuntu, Debian, AL2023, Fedora, RHEL 9+):

| Config Option | Purpose |
|---|---|
| `CONFIG_BPF=y` | Core BPF subsystem |
| `CONFIG_BPF_SYSCALL=y` | `bpf()` system call |
| `CONFIG_BPF_JIT=y` | JIT compiler for BPF programs |
| `CONFIG_KPROBE_EVENTS=y` | kprobe-based tracing (for IP capture) |
| `CONFIG_UPROBE_EVENTS=y` | uprobe-based tracing (for SSL hooks) |
| `CONFIG_DEBUG_INFO_BTF=y` | BTF type info |

**Verify your system:**

```bash
uname -r                                    # Kernel version (need 5.5+)
ls /sys/kernel/btf/vmlinux                  # BTF support
cat /proc/sys/net/core/bpf_jit_enable       # BPF JIT (should be 1 or 2)
```

**Install runtime dependencies:**

```bash
# Debian/Ubuntu
sudo apt-get install libbpf1 libelf1 zlib1g libssl3

# AL2023/RHEL/Fedora
sudo dnf install libbpf elfutils-libelf zlib openssl-libs
```

## Building from Source

These are what you need on the **build machine** (can be different from the target):

| Package (Debian/Ubuntu) | Package (RHEL/AL2023/Fedora) | Purpose |
|---|---|---|
| `clang` | `clang` | BPF program compiler |
| `llvm` | `llvm` | BPF target support |
| `gcc` | `gcc` | User-space compiler |
| `make` | `make` | Build system |
| `libbpf-dev` | `libbpf-devel` | BPF user-space library (headers + .so) |
| `libelf-dev` | `elfutils-libelf-devel` | ELF parsing |
| `zlib1g-dev` | `zlib-devel` | Compression |
| `linux-libc-dev` | `kernel-headers` | Kernel headers for BPF compilation |

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
| `-s` | `--sanitize REGEX` | Sanitize URLs matching REGEX (case-insensitive, repeatable) |
| `-v` | `--verbose` | Verbose output (shows library path, probe status) |
| `-h` | `--help` | Show help message |

### Example Output

**Text mode (default):**

```
12:34:56     REQUEST  PID=1234   TID=1234   UID=1000 COMM=curl            ADDR=93.184.216.34:443  LEN=78
GET /api/v1/status HTTP/1.1
Host: example.com

12:34:56     RESPONSE PID=1234   TID=1234   UID=1000 COMM=curl            ADDR=93.184.216.34:443  LEN=256
HTTP/1.1 200 OK
Content-Type: application/json
```

**JSON mode (`-f json`):**

```json
{"timestamp":"2026-03-15T10:30:00.123456Z","timestamp_ns":123456789,"pid":1234,"tid":1234,"uid":1000,"comm":"curl","direction":"REQUEST","src_ip":"10.0.5.23","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"data_len":78,"transport":"tls","protocol":"https","http_method":"GET","http_path":"/api/v1/status","http_host":"example.com"}
```

## Docker

The container image is published to GitHub Container Registry on every push to `main`.

```bash
# Pull from GHCR
docker pull ghcr.io/scgis-wales/ebpf-tls-tracer:latest

# Or build locally
docker build -t tls_tracer .

# Run (requires --privileged for eBPF access)
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --pid=host \
  ghcr.io/scgis-wales/ebpf-tls-tracer:latest -v -f json
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

git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer
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
git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer
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

TLS Tracer runs as a **DaemonSet** to monitor outbound TLS traffic from all processes on every node. It uses eBPF at the kernel level, which means it captures TLS traffic from **all pods and containers** on the node — including pods in any namespace (e.g., `apigee`, `default`, etc.) — without requiring sidecars or application changes.

### How It Works on Kubernetes

- Deploys as a **DaemonSet** (one pod per node) with `hostPID: true` and `privileged: true`
- eBPF hooks into the **host kernel's** `SSL_read`/`SSL_write` and `connect()` syscalls
- Captures outbound TLS traffic from **all pods/containers on the node**, across all namespaces (e.g., `apigee`, `default`)
- Automatically enriches events with **K8s metadata** (pod name, namespace, container ID) via the downward API environment variables
- Parses **HTTP Layer 7** details (method, path, Host header) from TLS plaintext
- Captures **source and destination IP:port** for every connection
- Logs are output in **JSON format** to stdout, one self-contained event per line

### Kubernetes Prerequisites

| Requirement | Details |
|---|---|
| **Kubernetes version** | 1.34+ |
| **Node OS** | Linux with kernel 6.1+ (AL2023 recommended — ships kernel 6.12 on EKS 1.34) |
| **Node kernel config** | eBPF, kprobes, uprobes enabled (see Prerequisites above) |
| **Container runtime** | containerd or CRI-O with privileged container support |
| **RBAC** | Cluster admin access to create privileged DaemonSets |
| **OpenSSL on nodes** | `libssl.so` must be present on each node |

### Minimum Container Permissions

The TLS Tracer container **requires** the following to function:

| Permission | Why |
|---|---|
| `privileged: true` | eBPF program loading requires full kernel access |
| `hostPID: true` | Must see all processes on the node to capture TLS traffic |
| `hostNetwork: true` | Required for connect() kprobe correlation |
| Volume: `/sys/kernel/debug` | debugfs access for uprobe/kprobe events |
| Volume: `/sys/kernel/tracing` | tracefs access for tracing infrastructure |
| Volume: `/sys/fs/bpf` | BPF filesystem for map pinning |
| Volume: `/usr/lib64` (host) | Access to host's `libssl.so` for uprobe attachment |
| PSA: `privileged` | Namespace must allow privileged pods |

### Deploy with Helm (Recommended)

```bash
# Create EKS cluster with AL2023 nodes
eksctl create cluster \
  --name my-cluster \
  --version 1.34 \
  --nodegroup-name al2023-nodes \
  --node-type m5.large \
  --node-ami-family AmazonLinux2023

# Deploy TLS Tracer (JSON output by default)
helm install tls-tracer helm/tls-tracer \
  --namespace tls-tracer --create-namespace

# Check status
kubectl -n tls-tracer get pods -o wide

# View JSON logs (all outbound TLS traffic on the node)
kubectl -n tls-tracer logs -l app.kubernetes.io/name=tls-tracer --tail=50 -f
```

#### Helm Values

| Value | Default | Description |
|---|---|---|
| `outputFormat` | `json` | Output format: `json` or `text` |
| `verbose` | `true` | Enable verbose logging |
| `filterPid` | `0` | Filter by PID (0 = all) |
| `filterUid` | `0` | Filter by UID (0 = all) |
| `sslLibPath` | `""` | Custom libssl.so path (empty = auto-detect) |
| `sanitizePatterns` | `["apikey=[^&]*"]` | URL sanitization regex patterns (case-insensitive) |
| `companyPrefix` | `""` | Prefix for all resource names (e.g., `acme-`) |
| `metadata.awsAccountId` | `""` | AWS account ID (for S3/Kinesis paths) |
| `metadata.awsRegion` | `eu-west-1` | AWS region |
| `metadata.clusterName` | `""` | EKS cluster name |
| `metadata.targetNamespace` | `""` | K8s namespace being monitored |
| `metadata.applicationName` | `""` | Application name (e.g., `apigee`) |
| `metadata.environment` | `""` | Environment label (e.g., `production`) |
| `image.repository` | `ghcr.io/scgis-wales/ebpf-tls-tracer` | Container image |
| `image.tag` | `latest` | Image tag |

#### AWS S3 Log Shipping

Ship JSON logs to S3 using Apache Hive-style directory partitioning. Uses a Python (boto3) sidecar with IRSA authentication. **Disabled by default.**

| Value | Default | Description |
|---|---|---|
| `s3.enabled` | `false` | Enable S3 log shipping sidecar |
| `s3.bucket` | `""` | S3 bucket name |
| `s3.prefix` | `tls-tracer-logs` | S3 key prefix |
| `s3.flushIntervalSeconds` | `60` | Flush interval |
| `s3.batchSize` | `1000` | Max records per upload |

S3 path format (Apache Hive partitioning):
```
s3://<bucket>/<prefix>/account=<id>/region=<region>/cluster=<name>/
  namespace=<ns>/app=<app>/env=<env>/year=YYYY/month=MM/day=DD/
  hour=HH/<node>-<timestamp>.json
```

#### AWS Kinesis Firehose

Forward JSON logs to Kinesis Firehose delivery stream. Uses a Python (boto3) sidecar with IRSA authentication. **Disabled by default.**

| Value | Default | Description |
|---|---|---|
| `kinesis.enabled` | `false` | Enable Kinesis Firehose sidecar |
| `kinesis.deliveryStreamName` | `""` | Firehose delivery stream name |
| `kinesis.batchSize` | `500` | Records per PutRecordBatch call |
| `kinesis.flushIntervalSeconds` | `30` | Flush interval |

#### IRSA (IAM Roles for Service Accounts)

Both S3 and Kinesis sidecars use IRSA for AWS authentication. Configure the IAM role ARN in the service account annotations:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/tls-tracer-role"
```

Required IAM permissions:
- **S3**: `s3:PutObject`, `s3:GetBucketLocation`
- **Kinesis**: `firehose:PutRecord`, `firehose:PutRecordBatch`

#### URL Sanitization

Sensitive data in HTTP paths and Host headers can be automatically redacted using regex patterns. Matches are replaced with `[REDACTED]`. Patterns are case-insensitive (POSIX ERE).

**CLI usage:**
```bash
# Redact API keys and tokens from logged URLs
sudo ./bin/tls_tracer -f json -s 'apikey=[^&]*' -s 'token=[^&]*' -s 'password=[^&]*'
```

**Helm values:**
```yaml
sanitizePatterns:
  - "apikey=[^&]*"
  - "secret=[^&]*"
  - "password=[^&]*"
  - "token=[^&]*"
  - "access_key=[^&]*"
```

Before: `GET /api/v1/data?apikey=sk_live_abc123&format=json`
After:  `GET /api/v1/data?[REDACTED]&format=json`

### JSON Log Output

Each captured TLS event is a **single self-contained JSON line**:

```json
{"timestamp":"2026-03-15T10:30:00.123456Z","timestamp_ns":1710500000000000,"pid":12345,"tid":12345,"uid":1000,"comm":"curl","direction":"REQUEST","src_ip":"10.0.5.23","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"data_len":78,"transport":"tls","protocol":"https","k8s_pod":"apigee-runtime-7b8f9c6d4-x2k9m","k8s_namespace":"apigee","container_id":"a1b2c3d4e5f6","http_method":"GET","http_path":"/api/v1/status","http_host":"example.com"}
{"timestamp":"2026-03-15T10:30:00.234567Z","timestamp_ns":1710500000100000,"pid":12345,"tid":12345,"uid":1000,"comm":"curl","direction":"RESPONSE","src_ip":"10.0.5.23","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"data_len":256,"transport":"tls","protocol":"https","k8s_pod":"apigee-runtime-7b8f9c6d4-x2k9m","k8s_namespace":"apigee","container_id":"a1b2c3d4e5f6"}
{"timestamp":"2026-03-15T10:30:01.000000Z","timestamp_ns":1710500001000000,"pid":23456,"tid":23456,"uid":0,"comm":"java","direction":"REQUEST","src_ip":"10.0.5.24","src_port":38901,"dst_ip":"10.0.1.50","dst_port":8443,"data_len":142,"transport":"tls","protocol":"https","k8s_pod":"apigee-cassandra-0","k8s_namespace":"apigee","container_id":"f6e5d4c3b2a1","http_method":"POST","http_path":"/v1/organizations","http_host":"management.apigee.internal"}
```

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 wall-clock timestamp with microseconds |
| `timestamp_ns` | Kernel monotonic timestamp in nanoseconds |
| `pid`/`tid` | Process and thread IDs |
| `comm` | Process command name (e.g., `curl`, `java`, `node`, `python3`) |
| `direction` | `REQUEST` (outbound to server) or `RESPONSE` (inbound from server) |
| `src_ip`/`src_port` | Source (local) IP address and port |
| `dst_ip`/`dst_port` | Destination (remote) IP address and port |
| `transport` | Transport layer: `tls` (all captured traffic goes through SSL) |
| `protocol` | Application protocol: `https` (HTTP detected) or `unknown` |
| `k8s_pod` | Kubernetes pod name (from downward API `POD_NAME` or `HOSTNAME`) |
| `k8s_namespace` | Kubernetes namespace (from downward API `POD_NAMESPACE`) |
| `container_id` | Short container ID (from cgroup) |
| `http_method` | HTTP method: GET, POST, PUT, DELETE, PATCH, etc. |
| `http_path` | HTTP request path (e.g., `/api/v1/status`) |
| `http_host` | HTTP Host header value (the DNS hostname) |
| `data_len` | Length of captured plaintext data |

K8s and HTTP fields are only present when detected. To enable K8s metadata on monitored pods, configure the downward API:

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

### Deploy with kubectl (Alternative)

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml

kubectl -n tls-tracer get pods -o wide
kubectl -n tls-tracer logs -l app=tls-tracer --tail=50
```

### Node Configuration via EKS Userdata

If nodes need runtime libraries (usually pre-installed on AL2023):

```bash
#!/bin/bash
dnf install -y libbpf openssl-libs bpftool
```

### What Needs to Be Configured

For Kubernetes 1.34+ on Linux kernel 6.x, the following must be true on each node.

**EKS 1.34 with AL2023**: The EKS-optimized AL2023 AMI ships with **kernel 6.12** (e.g., `6.12.73-95.123.amzn2023`). All eBPF features — BTF, uprobes, kprobes, BPF JIT, debugfs, tracefs, and the BPF filesystem — are **fully enabled and auto-mounted out of the box**. No kernel configuration, module loading, or filesystem mounting is required. Simply deploy the Helm chart.

For non-AL2023 or custom AMIs, verify:

1. **Kernel modules loaded** (usually auto-loaded on AL2023):
   ```bash
   lsmod | grep -E 'bpf|uprobe|kprobe'
   ```

2. **BPF filesystem mounted** (auto-mounted on AL2023):
   ```bash
   mount -t bpf bpf /sys/fs/bpf
   ```

3. **debugfs / tracefs mounted** (auto-mounted on AL2023):
   ```bash
   mount -t debugfs debugfs /sys/kernel/debug
   mount -t tracefs tracefs /sys/kernel/tracing
   ```

4. **Privileged containers allowed** in Pod Security Admission:
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: tls-tracer
     labels:
       pod-security.kubernetes.io/enforce: privileged
   ```

### Removing

```bash
# Helm
helm uninstall tls-tracer -n tls-tracer

# Or kubectl
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
ebpf-tls-tracer/
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
├── helm/
│   └── tls-tracer/           # Helm chart for Kubernetes deployment
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── Dockerfile                # Multi-stage build (Debian trixie)
├── Makefile                  # Build system
├── LICENSE                   # MIT License
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
