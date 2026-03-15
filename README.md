# eBPF TLS Tracer

An eBPF-based tool for intercepting and inspecting TLS/SSL traffic in real time on Linux. Ships as a **CLI binary**, a **container image** (`ghcr.io/scgis-wales/ebpf-tls-tracer`), and a **Helm chart** for Kubernetes DaemonSet deployment. Attaches uprobes to OpenSSL's `SSL_read`/`SSL_write` to capture plaintext data - without modifying applications or terminating TLS sessions.

## Features

**Core capture:**
- Intercept plaintext from `SSL_read`/`SSL_write` via eBPF uprobes
- Capture source and destination IP:port (IPv4/IPv6) via `connect()` + `tcp_set_state` kprobes
- Connection correlation via socket fd extraction (`conn_id` field)
- TLS version detection (1.0-1.3) via `SSL_version` uprobe
- TLS cipher suite capture via `SSL_get_current_cipher` uprobe
- Mutual TLS (mTLS) detection via `SSL_get_certificate` uprobe

**Protocol detection:**
- HTTP/1.x - method, path, Host header, status code, User-Agent
- HTTP/2 - frame parsing, RST_STREAM/GOAWAY error codes
- gRPC - status codes (0-16), framing detection over HTTP/2
- WebSocket - upgrade detection, close frame codes
- Kafka - request/response frames, API key names (75 operations)
- QUIC - UDP-based detection on ports 443/8443 (opt-in via `--quic`)
- SMTP, IMAP, LDAP, AMQP, MQTT - via data signatures and well-known ports

**Operations:**
- JSON (NDJSON) and text output formats
- PID/UID filtering
- Regex-based data sanitization (sensitive headers redacted by default)
- Kubernetes metadata enrichment (pod name, namespace, container ID)
- DNS hostname caching per connection
- Low overhead - 4 MB BPF ring buffer with drop counting, line-buffered stdout

## Quick Start

**Pre-built binary** (x86_64 Linux):
```bash
curl -LO https://github.com/SCGIS-Wales/ebpf-tls-tracer/releases/latest/download/tls_tracer-linux-x86_64.tar.gz
tar xzf tls_tracer-linux-x86_64.tar.gz
sudo ./tls_tracer -f json -v
```

**Docker:**
```bash
docker pull ghcr.io/scgis-wales/ebpf-tls-tracer:latest
sudo docker run --rm --privileged --pid=host \
  ghcr.io/scgis-wales/ebpf-tls-tracer:latest -f json -v
```

**Build from source:**
```bash
git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer
make && make test
sudo ./bin/tls_tracer -f json -v
```

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux x86_64 |
| **Kernel** | 5.5+ minimum, **6.1+ recommended** |
| **Privileges** | Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` |
| **OpenSSL** | `libssl.so` installed (auto-detected) |
| **Runtime libs** | `libbpf`, `libelf`, `zlib` |
| **Kernel config** | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_KPROBE_EVENTS`, `CONFIG_UPROBE_EVENTS`, `CONFIG_DEBUG_INFO_BTF` (enabled by default on Ubuntu, Debian, AL2023, Fedora, RHEL 9+) |

**Verify:**
```bash
uname -r                                    # Need 5.5+
ls /sys/kernel/btf/vmlinux                  # BTF support
cat /proc/sys/net/core/bpf_jit_enable       # BPF JIT (1 or 2)
```

**Install runtime dependencies:**
```bash
# Debian/Ubuntu
sudo apt-get install libbpf1 libelf1 zlib1g libssl3

# AL2023/RHEL/Fedora
sudo dnf install libbpf elfutils-libelf zlib openssl-libs
```

## Usage

```bash
sudo ./bin/tls_tracer                           # Trace all TLS traffic
sudo ./bin/tls_tracer -f json                   # JSON output (one event per line)
sudo ./bin/tls_tracer -p 1234                   # Filter by PID
sudo ./bin/tls_tracer -u 1000                   # Filter by UID
sudo ./bin/tls_tracer -x                        # Hex dump mode
sudo ./bin/tls_tracer --quic                    # Enable QUIC/UDP detection
sudo ./bin/tls_tracer -l /path/to/libssl.so     # Custom OpenSSL path
sudo ./bin/tls_tracer -s 'secret=[^&]*'         # Add extra sanitization pattern
```

### CLI Options

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-p` | `--pid PID` | Filter by process ID |
| `-u` | `--uid UID` | Filter by user ID |
| `-l` | `--lib PATH` | Path to libssl.so (auto-detected by default) |
| `-f` | `--format FMT` | Output format: `text` (default) or `json` |
| `-x` | `--hex` | Show hex dump of captured data |
| `-d` | `--data-only` | Print only captured data (no metadata headers) |
| `-s` | `--sanitize REGEX` | Add sanitization regex pattern (case-insensitive, repeatable) |
| `-q` | `--quic` | Enable QUIC/UDP detection probe (off by default to avoid overhead) |
| `-v` | `--verbose` | Verbose output (library path, probe status, perf buffer info) |
| `-h` | `--help` | Show help message |

### Default Sanitization

The following HTTP headers are automatically redacted (replaced with `[REDACTED]`):
- `Authorization`
- `Cookie` / `Set-Cookie`
- `X-Api-Key`

Add custom patterns with `-s`:
```bash
sudo ./bin/tls_tracer -f json -s 'token=[^&]*' -s 'password=[^&]*'
```

## JSON Output Format

Each event is a single self-contained JSON line (NDJSON). Fields are only present when detected.

### Example

```json
{"timestamp":"2026-03-15T10:30:00.123456Z","timestamp_ns":123456789,"pid":1234,"tid":1234,"uid":1000,"comm":"curl","direction":"REQUEST","src_ip":"10.0.5.23","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"data_len":78,"conn_id":"1234:7","dst_dns":"example.com","tls_version":"1.3","tls_cipher":"TLS_AES_256_GCM_SHA384","tls_auth":"one-way","transport":"tls","protocol":"https","http_version":"2","http_method":"GET","http_path":"/api/v1/status","http_host":"example.com","user_agent":"curl/8.5.0"}
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO 8601 wall-clock timestamp (microseconds) |
| `timestamp_ns` | integer | Kernel monotonic timestamp (nanoseconds) |
| `pid` / `tid` | integer | Process and thread IDs |
| `uid` | integer | User ID |
| `comm` | string | Process command name (`curl`, `java`, `node`, etc.) |
| `direction` | string | `REQUEST` (outbound) or `RESPONSE` (inbound) |
| `src_ip` / `src_port` | string/int | Local IP address and port |
| `dst_ip` / `dst_port` | string/int | Remote IP address and port |
| `data_len` | integer | Captured plaintext data length |
| `conn_id` | string | Connection identifier (`pid:fd`) for event correlation |
| `dst_dns` | string | Hostname from HTTP Host header (cached per connection) |
| `tls_version` | string | TLS version: `1.0`, `1.1`, `1.2`, `1.3` |
| `tls_cipher` | string | Negotiated cipher suite (e.g., `TLS_AES_256_GCM_SHA384`) |
| `tls_auth` | string | `one-way` or `mtls` (mutual TLS with client cert) |
| `transport` | string | `tls` or `udp` (for QUIC) |
| `protocol` | string | Detected L7 protocol (see below) |
| `http_version` | string | HTTP version: `1.0`, `1.1`, `2` |
| `http_method` | string | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, etc. |
| `http_path` | string | HTTP request path |
| `http_host` | string | HTTP Host header value |
| `http_status` | integer | HTTP response status code (200, 404, 500, etc.) |
| `user_agent` | string | User-Agent header value |
| `k8s_pod` | string | Kubernetes pod name |
| `k8s_namespace` | string | Kubernetes namespace |
| `container_id` | string | Short container ID (12 chars) |
| `grpc_status` | integer | gRPC status code (0-16) |
| `grpc_status_name` | string | gRPC status name (`OK`, `UNAVAILABLE`, etc.) |
| `h2_error_code` | integer | HTTP/2 RST_STREAM/GOAWAY error code |
| `h2_error_name` | string | HTTP/2 error name (`NO_ERROR`, `CANCEL`, etc.) |
| `h2_frame_type` | string | HTTP/2 frame: `RST_STREAM` or `GOAWAY` |
| `kafka_api_key` | integer | Kafka API key number |
| `kafka_api_name` | string | Kafka operation name (`Produce`, `Fetch`, etc.) |
| `kafka_frame_type` | string | `request` or `response` |
| `kafka_error_code` | integer | Kafka response error code (non-zero only) |
| `ws_close_code` | integer | WebSocket close status code |
| `ws_close_reason` | string | WebSocket close reason (`NORMAL_CLOSURE`, etc.) |

### Detected Protocols

| Protocol | Detection Method |
|---|---|
| `https` | HTTP/1.x methods, HTTP/2 frames, or ports 443/8443 |
| `grpc` | HTTP/2 DATA frames with gRPC framing, or ports 50051-50055 |
| `wss` | `Upgrade: websocket` header or `101 Switching Protocols` |
| `kafka` | Kafka wire protocol binary header, or ports 9092-9094 |
| `smtps` | EHLO/MAIL/RCPT commands, or ports 465/587 |
| `imaps` | IMAP greeting/commands, or port 993 |
| `quic` | UDP traffic to port 443/8443 (requires `--quic` flag) |
| `pop3s`, `ldaps`, `ftps`, `amqps`, `mqtts`, `xmpps`, `ircs` | Well-known TLS ports |

### Event Types

| Event | `event_type` | Description |
|---|---|---|
| TLS data | *(default)* | Captured plaintext from SSL_read/SSL_write |
| TCP error | `tcp_error` | Connect syscall failure (ECONNREFUSED, ETIMEDOUT, etc.) |
| TLS close | `tls_close` | Peer closed TLS connection (SSL_read returned 0) |
| TLS error | `tls_error` | SSL_read/SSL_write returned error |
| QUIC detected | `quic_detected` | UDP traffic to QUIC port (requires `--quic`) |
| Lost events | `lost_events` | Ring buffer overflow (events dropped) |

## Building from Source

| Package (Debian/Ubuntu) | Package (RHEL/AL2023) | Purpose |
|---|---|---|
| `clang`, `llvm` | `clang`, `llvm` | BPF program compiler |
| `gcc`, `make` | `gcc`, `make` | User-space compiler and build system |
| `libbpf-dev` | `libbpf-devel` | BPF user-space library |
| `libelf-dev` | `elfutils-libelf-devel` | ELF parsing |
| `zlib1g-dev` | `zlib-devel` | Compression |
| `linux-libc-dev` | `kernel-headers` | Kernel headers for BPF |

```bash
# Debian/Ubuntu
sudo apt-get install clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev

# AL2023/RHEL/Fedora
sudo dnf install clang llvm gcc make libbpf-devel elfutils-libelf-devel zlib-devel kernel-devel kernel-headers

make            # Build BPF program + user-space binary
make test       # Run unit tests (62 tests)
sudo make install   # Install to /usr/local
```

## Docker

```bash
# Pull from GHCR
docker pull ghcr.io/scgis-wales/ebpf-tls-tracer:latest

# Build locally
docker build -t tls_tracer .

# Run (requires --privileged for eBPF)
docker run --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --pid=host \
  ghcr.io/scgis-wales/ebpf-tls-tracer:latest -f json -v
```

## Kubernetes Deployment

TLS Tracer runs as a **DaemonSet** (one pod per node) with `hostPID: true` and `privileged: true`. eBPF hooks into the host kernel, capturing TLS traffic from **all pods and containers on the node** across all namespaces - no sidecars or application changes required.

Events are enriched with K8s metadata (pod name, namespace, container ID) via the downward API.

### Prerequisites

| Requirement | Details |
|---|---|
| Kubernetes | 1.34+ |
| Node OS | Linux kernel 6.1+ (AL2023 recommended) |
| Container runtime | containerd or CRI-O with privileged container support |
| Permissions | `privileged: true`, `hostPID: true`, `hostNetwork: true` |
| Volumes | `/sys/kernel/debug`, `/sys/kernel/tracing`, `/sys/fs/bpf`, host SSL libs mounted at `/host/usr/lib*` |

### Deploy with Helm

```bash
helm install tls-tracer helm/tls-tracer \
  --namespace tls-tracer --create-namespace

kubectl -n tls-tracer get pods -o wide
kubectl -n tls-tracer logs -l app.kubernetes.io/name=tls-tracer --tail=50 -f
```

### Helm Values

| Value | Default | Description |
|---|---|---|
| `outputFormat` | `json` | Output format: `json` or `text` |
| `verbose` | `true` | Enable verbose logging |
| `filterPid` | `0` | Filter by PID (0 = all) |
| `filterUid` | `0` | Filter by UID (0 = all) |
| `sslLibPath` | `""` | Custom libssl.so path (empty = auto-detect) |
| `sanitizePatterns` | `["apikey=[^&]*"]` | URL sanitization regex patterns |
| `companyPrefix` | `""` | Prefix for resource names |
| `image.repository` | `ghcr.io/scgis-wales/ebpf-tls-tracer` | Container image |
| `image.tag` | `0.1.0` | Image tag (pin to specific version in production) |

### AWS Integration

**S3 log shipping** (disabled by default):
```yaml
s3:
  enabled: true
  bucket: "my-tls-logs"
  prefix: "tls-tracer-logs"
  flushIntervalSeconds: 60
  batchSize: 1000
```

S3 path uses Apache Hive partitioning:
```
s3://<bucket>/<prefix>/account=<id>/region=<region>/cluster=<name>/
  namespace=<ns>/app=<app>/env=<env>/year=YYYY/month=MM/day=DD/hour=HH/<file>.json
```

**Kinesis Firehose** (disabled by default):
```yaml
kinesis:
  enabled: true
  deliveryStreamName: "tls-tracer-stream"
  batchSize: 500
  flushIntervalSeconds: 30
```

Both use IRSA for authentication:
```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/tls-tracer-role"
```

### K8s Metadata Enrichment

To populate `k8s_pod` and `k8s_namespace` fields on monitored pods, configure the downward API:

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

### Uninstall

```bash
helm uninstall tls-tracer -n tls-tracer
```

## Amazon Linux 2023

AL2023 on EKS 1.34 ships with kernel 6.12 - all eBPF features (BTF, uprobes, kprobes, BPF JIT) are enabled out of the box. No kernel configuration required.

```bash
# Install and build on AL2023
sudo dnf install -y clang llvm gcc make libbpf-devel elfutils-libelf-devel \
  zlib-devel kernel-devel-$(uname -r) kernel-headers-$(uname -r) openssl-devel bpftool

git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer && make && make test
sudo ./bin/tls_tracer -f json -v
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        User Space                            │
│                                                              │
│  tls_tracer (CLI)                                            │
│    ├── Argument parsing & config (getopt_long)               │
│    ├── OpenSSL version validation (dlopen/dlsym)             │
│    ├── BPF object loading (libbpf)                           │
│    ├── Kprobe attach: connect(), tcp_set_state, udp_sendmsg  │
│    ├── Uprobe attach: SSL_read/write, SSL_version,           │
│    │    SSL_get_current_cipher, SSL_get_certificate          │
│    ├── Ring buffer polling (variable-length events)          │
│    ├── L7 protocol detection (HTTP, gRPC, Kafka, WS, ...)   │
│    ├── K8s metadata enrichment (/proc/<pid>/environ)         │
│    ├── DNS hostname caching (per pid:fd)                     │
│    └── Event formatting (text/JSON) + sanitization           │
│                                                              │
├─────────────── ring buffer (4 MB, shared) ───────────────────┤
│                                                              │
│                       Kernel Space                           │
│                                                              │
│  bpf_program.o (eBPF probes)                                 │
│    ├── kprobe/__sys_connect      → save sockaddr             │
│    ├── kretprobe/__sys_connect   → store conn_info in map    │
│    ├── kprobe/tcp_set_state      → capture local+remote addr │
│    ├── kprobe/udp_sendmsg        → QUIC detection (opt-in)   │
│    ├── uprobe/SSL_read           → save buffer ptr           │
│    ├── uretprobe/SSL_read        → capture data + enrich     │
│    ├── uprobe/SSL_write          → save buffer ptr           │
│    ├── uretprobe/SSL_write       → capture data + enrich     │
│    ├── uprobe/SSL_version        → capture TLS version       │
│    ├── uprobe/SSL_get_current_cipher → capture cipher suite  │
│    └── uprobe/SSL_get_certificate    → detect mTLS           │
│                                                              │
│  BPF Maps:                                                   │
│    ├── ssl_args_map       (HASH)     → per-thread SSL args   │
│    ├── conn_info_map      (LRU_HASH) → pid_tgid → addresses │
│    ├── ssl_version_map    (LRU_HASH) → SSL* → TLS version   │
│    ├── cipher_name_map    (LRU_HASH) → SSL* → cipher name   │
│    ├── mtls_map           (LRU_HASH) → SSL* → mTLS flag     │
│    ├── event_buf     (PERCPU_ARRAY)  → scratch buffer        │
│    ├── tls_events    (RINGBUF, 4 MB) → user-space output     │
│    └── dropped_events (PERCPU_ARRAY) → drop counter          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### How IP Capture Works

1. **`kprobe/connect()`** saves the `sockaddr` (remote IP:port) on entry
2. **`kprobe/tcp_set_state`** fires when TCP reaches ESTABLISHED, capturing both local and remote addresses from `struct sock` (CO-RE compatible)
3. **`kretprobe/connect()`** stores `{pid_tgid} → conn_info_t` in the map
4. **SSL uretprobes** extract socket fd from `SSL->rbio->num` (OpenSSL internal offset) and look up `conn_info_map` to enrich TLS events with IP:port

## Performance

eBPF uprobes add **~1-2 µs per SSL_read/SSL_write call** (entry + exit + data copy). At 1,700 TPS on an 8-vCPU node, total CPU overhead is typically **< 1%**:

| Component | Overhead per call | At 1,700 TPS |
|---|---|---|
| Uprobe entry/exit | ~1 µs | ~1.7 ms/s (~0.02% CPU) |
| Data copy to ring buffer | ~0.5 µs/KB | ~0.85 ms/s |
| User-space poll + JSON format | ~2 µs | ~3.4 ms/s |
| **Total** | **~4 µs** | **~6 ms/s (~0.08% CPU)** |

**Design choices for low overhead:**
- **4 MB shared ring buffer** - ~7% throughput overhead vs ~50% for per-CPU perf buffers on multi-core nodes ([benchmark](https://nakryiko.com/posts/bpf-ringbuf/))
- **Adaptive notification** - ring buffer signals user-space only when consumer is idle, batching under load
- **Per-PID K8s metadata cache** with TTL - avoids `/proc` reads on every event
- **Rate-limited `/proc` reads** - capped at 50/s to prevent I/O storm under PID churn
- **Variable-length events** - only copies actual data bytes, not fixed 16 KB buffers

**Kernel requirement:** Linux 6.1+ recommended. Kernels < 6.12.8 have a ring buffer race condition (CVE-2025-40319); the tracer warns at startup on affected versions.

## Project Structure

```
ebpf-tls-tracer/
├── include/
│   └── tracer.h              # Shared structs (kernel + user space)
├── src/
│   ├── bpf_program.c         # eBPF kernel probes (14 probe functions)
│   └── tls_tracer.c          # User-space CLI (L7 parsing, K8s, output)
├── tests/
│   ├── test_tracer.c         # Struct/constant tests (16 tests)
│   └── test_helpers.c        # Helper function tests (46 tests)
├── helm/
│   └── tls-tracer/           # Helm chart (DaemonSet, RBAC, S3/Kinesis)
├── deploy/
│   └── kubernetes/           # Raw K8s manifests (alternative to Helm)
├── .github/
│   └── workflows/
│       └── build.yml         # CI: build, test, Docker publish
├── Dockerfile                # Multi-stage build (Debian trixie)
├── Makefile
└── LICENSE                   # MIT
```

## License

MIT License. See [LICENSE](LICENSE) for details.
