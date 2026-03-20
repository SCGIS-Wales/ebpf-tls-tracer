<p align="center">
  <h1 align="center">eBPF TLS Tracer</h1>
  <p align="center">
    <strong>Zero-instrumentation TLS visibility for every outbound connection on your nodes.</strong>
  </p>
  <p align="center">
    <a href="https://github.com/SCGIS-Wales/ebpf-tls-tracer/actions"><img src="https://github.com/SCGIS-Wales/ebpf-tls-tracer/actions/workflows/build.yml/badge.svg" alt="CI"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-blue.svg" alt="Licence: MIT"></a>
    <a href="https://github.com/SCGIS-Wales/ebpf-tls-tracer/releases"><img src="https://img.shields.io/github/v/release/SCGIS-Wales/ebpf-tls-tracer" alt="Release"></a>
    <img src="https://img.shields.io/badge/arch-x86__64%20%7C%20ARM64-brightgreen" alt="Architectures">
    <img src="https://img.shields.io/badge/kernel-5.5%2B-orange" alt="Kernel 5.5+">
  </p>
</p>

---

eBPF TLS Tracer attaches to OpenSSL at the kernel level to capture **decrypted** TLS traffic in real time — without sidecars, proxies, certificate injection, or any application changes. Deploy it as a **CLI binary**, a **container image**, or a **Helm-managed DaemonSet** and gain immediate visibility into every outbound HTTPS, gRPC, Kafka, and WebSocket flow leaving your nodes.

---

## Table of Contents

- [Why TLS Tracer?](#why-tls-tracer)
- [Use Cases](#use-cases)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Protocol Detection](#protocol-detection)
- [CLI Reference](#cli-reference)
  - [Traffic Filtering](#traffic-filtering)
- [JSON Output Schema](#json-output-schema)
- [Kubernetes Deployment](#kubernetes-deployment)
  - [Helm Chart](#helm-chart)
  - [Helm Values Reference](#helm-values-reference)
  - [AWS Integration (S3 & Kinesis)](#aws-integration-s3--kinesis)
  - [Kubernetes Metadata Enrichment](#kubernetes-metadata-enrichment)
  - [Raw Manifests](#raw-manifests)
- [Data Sanitisation & Redaction](#data-sanitisation--redaction)
- [Performance](#performance)
- [Building from Source](#building-from-source)
  - [Docker](#docker)
  - [Amazon Linux 2023 / EKS](#amazon-linux-2023--eks)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Licence](#licence)

---

## Why TLS Tracer?

Modern platform teams encrypt everything — and rightly so. But encryption creates a blind spot: **you cannot audit what you cannot see.** Traditional approaches to TLS visibility each carry significant trade-offs:

| Approach | Limitation |
|---|---|
| Service mesh sidecar (e.g. Envoy, Istio) | Adds latency, memory overhead, and operational complexity per pod |
| TLS-terminating proxy | Requires certificate management and becomes a single point of failure |
| Application-level logging | Inconsistent coverage; relies on every team instrumenting every service |
| MITM interception | Breaks certificate pinning and mutual TLS; unacceptable in regulated environments |

**eBPF TLS Tracer takes a fundamentally different approach.** It hooks directly into OpenSSL's `SSL_read` and `SSL_write` functions at the kernel boundary using eBPF uprobes, capturing the already-decrypted plaintext *after* the TLS handshake completes. There is no proxy in the path, no certificate manipulation, and no changes to your applications or their deployment manifests.

**The result:** a single DaemonSet gives you structured, JSON-streamed visibility into every outbound TLS connection on every node — enriched with Kubernetes metadata, protocol-level detail, and TLS posture information — at less than 0.1% CPU overhead.

---

## Use Cases

**Outbound traffic audit & compliance** — Prove exactly which external endpoints your workloads connect to, which TLS versions and cipher suites are negotiated, and whether mutual TLS is in use. Feed structured NDJSON logs to your SIEM for continuous compliance evidence.

**API gateway & mesh observability** — See the real traffic flowing through Apigee Hybrid proxies, Envoy sidecars, or Kafka brokers without relying on application-level telemetry. Correlate connection-level events (source pod, destination IP, protocol, HTTP path) across your entire platform.

**Shadow API & data exfiltration detection** — Identify unexpected outbound connections to unknown hosts, detect unencrypted fallback, and flag services communicating on non-standard ports. Every event includes the destination DNS hostname, resolved at capture time.

**TLS posture enforcement** — Continuously verify that all workloads negotiate TLS 1.2+ with approved cipher suites. Detect one-way TLS where mTLS is mandated. Export findings to S3 or Kinesis Firehose for policy-as-code pipelines.

**Incident response & forensics** — During a security incident, deploy TLS Tracer to affected nodes and immediately stream full request/response metadata (method, path, status, gRPC codes, Kafka operations) without restarting or redeploying any workload.

---

## Quick Start

### Pre-built Binary (Linux x86_64 / ARM64)

```bash
# x86_64
curl -LO https://github.com/SCGIS-Wales/ebpf-tls-tracer/releases/latest/download/tls_tracer-linux-x86_64.tar.gz
tar xzf tls_tracer-linux-x86_64.tar.gz

# ARM64 (aarch64)
curl -LO https://github.com/SCGIS-Wales/ebpf-tls-tracer/releases/latest/download/tls_tracer-linux-aarch64.tar.gz
tar xzf tls_tracer-linux-aarch64.tar.gz

sudo ./tls_tracer -f json -v
```

### Docker

```bash
docker pull ghcr.io/scgis-wales/ebpf-tls-tracer:latest

sudo docker run --rm --privileged --pid=host \
  ghcr.io/scgis-wales/ebpf-tls-tracer:latest -f json -v
```

### Build from Source

```bash
git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer
make && make test
sudo ./bin/tls_tracer -f json -v
```

---

## How It Works

1. **Kernel-level hooks** — eBPF uprobes attach to OpenSSL's `SSL_read` and `SSL_write` in `libssl.so`. When any process on the node performs a TLS read or write, the probes fire and capture the plaintext buffer contents.

2. **Connection correlation** — Separate kprobes on `connect()` and `tcp_set_state` capture source/destination IP:port pairs. A BPF hash map correlates each SSL operation back to its TCP connection using the socket file descriptor extracted from OpenSSL internals.

3. **TLS posture capture** — Additional uprobes on `SSL_version`, `SSL_get_current_cipher`, and `SSL_get_certificate` extract the negotiated TLS version, cipher suite, and whether a client certificate is present (mTLS detection).

4. **Ring buffer delivery** — Events flow through a 4 MB shared BPF ring buffer to user space, where the CLI performs Layer 7 protocol detection, Kubernetes metadata enrichment, DNS hostname resolution, header sanitisation, and JSON formatting.

5. **Structured output** — Each event is emitted as a self-contained NDJSON line to stdout, ready for piping to `jq`, `fluentd`, a log shipper, or directly to S3/Kinesis via the included sidecar scripts.

---

## Protocol Detection

TLS Tracer inspects captured plaintext to identify the application-layer protocol in use. Detection combines payload signature analysis with well-known port heuristics.

| Protocol | Key | Detection Method |
|---|---|---|
| HTTPS | `https` | HTTP/1.x methods, HTTP/2 magic/frames, or ports 443/8443 |
| gRPC | `grpc` | HTTP/2 DATA frames with gRPC length-prefixed framing, or ports 50051–50055 |
| WebSocket | `wss` | `Upgrade: websocket` header or `101 Switching Protocols` response |
| Kafka | `kafka` | Kafka wire protocol binary header, or ports 9092–9094 |
| SMTP | `smtps` | `EHLO`/`MAIL`/`RCPT` commands, or ports 465/587 |
| IMAP | `imaps` | IMAP greeting/commands, or port 993 |
| QUIC | `quic` | UDP traffic to port 443/8443 (requires `--quic` flag) |
| Others | `pop3s`, `ldaps`, `ftps`, `amqps`, `mqtts`, `xmpps`, `ircs` | Well-known TLS port mapping |

**Protocol-specific fields** are added to the JSON output when detected — for example, `http_method`, `http_path`, `grpc_status`, `kafka_api_name`, and `ws_close_code`. See the [JSON Output Schema](#json-output-schema) for the full field reference.

---

## CLI Reference

```
sudo ./bin/tls_tracer [OPTIONS]
```

| Flag | Long Form | Description |
|---|---|---|
| `-p` | `--pid PID` | Filter by process ID |
| `-u` | `--uid UID` | Filter by user ID |
| `-l` | `--lib PATH` | Path to `libssl.so` (auto-detected by default) |
| `-f` | `--format FMT` | Output format: `text` (default) or `json` |
| `-x` | `--hex` | Show hex dump of captured data |
| `-d` | `--data-only` | Print only captured data (no metadata headers) |
| `-s` | `--sanitize REGEX` | Add sanitisation regex pattern (case-insensitive, repeatable) |
| `-q` | `--quic` | Enable QUIC/UDP detection probe (off by default to avoid overhead) |
| `-n` | `--net MODE:CIDR` | Filter by CIDR range or keyword (repeatable). MODE is `include` or `exclude`. CIDR examples: `10.0.0.0/8`, `fc00::/7`. Keywords: `private`, `public`, `loopback` |
| `-P` | `--proto MODE:PROTO` | Filter by protocol (repeatable). PROTO: `tcp`, `udp`, `http`, `https`, `non-https` |
| `-m` | `--method MODE:METHOD` | Filter by HTTP method (repeatable). METHOD: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `CONNECT` |
| `-D` | `--dir MODE:DIR` | Filter by traffic direction (repeatable). DIR: `inbound`, `outbound` |
| `-v` | `--verbose` | Verbose output (library path, probe status, ring buffer info) |
| `-h` | `--help` | Show help message |

**Examples:**

```bash
sudo ./bin/tls_tracer -f json                   # JSON output (one event per line)
sudo ./bin/tls_tracer -p 1234                   # Filter to a single process
sudo ./bin/tls_tracer -u 1000                   # Filter by user ID
sudo ./bin/tls_tracer --quic                    # Enable QUIC/UDP detection
sudo ./bin/tls_tracer -l /path/to/libssl.so     # Custom OpenSSL path
sudo ./bin/tls_tracer -s 'secret=[^&]*'         # Add extra sanitisation pattern
```

### Traffic Filtering

Traffic filters let you narrow captured events by network range, protocol, HTTP method, and direction. Each filter uses the format `MODE:VALUE` where MODE is `include` (only show matching) or `exclude` (hide matching). Multiple filter categories combine with AND logic.

**Mixing include and exclude within the same category is an error** — all `--net` filters must use the same mode, all `--proto` filters must use the same mode, etc.

#### CIDR / Network Filters (`--net`)

Filter by destination IP address using CIDR notation or keywords:

```bash
# Only show traffic to private RFC 1918/6598/4193 ranges
sudo ./bin/tls_tracer --net include:private

# Only show traffic to public (non-private) IPs
sudo ./bin/tls_tracer --net include:public

# Exclude loopback traffic
sudo ./bin/tls_tracer --net exclude:loopback

# Multiple specific CIDRs
sudo ./bin/tls_tracer --net include:10.0.0.0/8 --net include:172.16.0.0/12

# IPv6 CIDR
sudo ./bin/tls_tracer --net include:2001:db8::/32
```

**Keywords:**

| Keyword | Expands To |
|---|---|
| `private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (RFC 6598), `fc00::/7` (RFC 4193) |
| `public` | Everything NOT in the private ranges above |
| `loopback` | `127.0.0.0/8`, `::1/128` |

#### Protocol Filters (`--proto`)

Filter by transport or application-layer protocol:

```bash
# Only HTTPS (TLS) traffic
sudo ./bin/tls_tracer --proto include:https

# Only UDP/QUIC traffic
sudo ./bin/tls_tracer --proto include:udp --quic

# Exclude plain HTTP
sudo ./bin/tls_tracer --proto exclude:http

# Multiple protocols (OR within category)
sudo ./bin/tls_tracer --proto include:tcp --proto include:udp
```

| Protocol | Matches |
|---|---|
| `tcp` | All TCP-based events (TLS, connect errors, etc.) |
| `udp` | QUIC/UDP events (requires `--quic`) |
| `http` | Plaintext HTTP (port 80/8080, non-TLS) |
| `https` | TLS traffic (all `EVENT_TLS_DATA` events) |
| `non-https` | Everything except HTTPS/TLS |

#### HTTP Method Filters (`--method`)

Filter by HTTP request method (only applies to events with a detected HTTP method; non-HTTP events pass through):

```bash
# Only GET requests
sudo ./bin/tls_tracer --method include:GET

# Exclude DELETE and PATCH
sudo ./bin/tls_tracer --method exclude:DELETE --method exclude:PATCH

# Only POST and PUT
sudo ./bin/tls_tracer --method include:POST --method include:PUT
```

#### Direction Filters (`--dir`)

Filter by traffic direction (inbound = responses/reads, outbound = requests/writes):

```bash
# Only inbound (response) traffic
sudo ./bin/tls_tracer --dir include:inbound

# Only outbound (request) traffic
sudo ./bin/tls_tracer --dir include:outbound
```

#### Combined Filters

All filter categories combine with **AND logic** — an event must pass every configured filter category:

```bash
# Public HTTPS GET requests only
sudo ./bin/tls_tracer --net include:public --proto include:https --method include:GET

# Exclude private network traffic, only show outbound
sudo ./bin/tls_tracer --net exclude:private --dir include:outbound

# HTTPS POST/PUT to specific subnet
sudo ./bin/tls_tracer --net include:10.0.0.0/8 --proto include:https \
  --method include:POST --method include:PUT
```

---

## JSON Output Schema

Each event is a single self-contained NDJSON line. Fields are **only present when detected** — the schema is sparse by design to minimise log volume.

### Example Event

```json
{
  "timestamp": "2026-03-15T10:30:00.123456Z",
  "timestamp_ns": 123456789,
  "pid": 1234,
  "tid": 1234,
  "uid": 1000,
  "comm": "curl",
  "direction": "REQUEST",
  "src_ip": "10.0.5.23",
  "src_port": 54321,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "data_len": 78,
  "conn_id": "1234:7",
  "dst_dns": "example.com",
  "tls_version": "1.3",
  "tls_cipher": "TLS_AES_256_GCM_SHA384",
  "tls_auth": "one-way",
  "transport": "tls",
  "protocol": "https",
  "http_version": "2",
  "http_method": "GET",
  "http_path": "/api/v1/status",
  "http_host": "example.com",
  "user_agent": "curl/8.5.0"
}
```

### Core Fields

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | ISO 8601 wall-clock timestamp (microsecond precision) |
| `timestamp_ns` | integer | Kernel monotonic timestamp (nanoseconds) |
| `pid` / `tid` | integer | Process and thread IDs |
| `uid` | integer | User ID of the owning process |
| `comm` | string | Process command name (`curl`, `java`, `node`, etc.) |
| `direction` | string | `REQUEST` (outbound write) or `RESPONSE` (inbound read) |
| `src_ip` / `src_port` | string / int | Local IP address and ephemeral port |
| `dst_ip` / `dst_port` | string / int | Remote IP address and port |
| `data_len` | integer | Captured plaintext byte count |
| `conn_id` | string | Connection identifier (`pid:fd`) for event correlation |
| `dst_dns` | string | Hostname from HTTP Host header (cached per connection) |

### TLS Posture Fields

| Field | Type | Description |
|---|---|---|
| `tls_version` | string | Negotiated TLS version: `1.0`, `1.1`, `1.2`, `1.3` |
| `tls_cipher` | string | Cipher suite (e.g. `TLS_AES_256_GCM_SHA384`) |
| `tls_auth` | string | `one-way` or `mtls` (mutual TLS with client certificate) |
| `transport` | string | `tls` or `udp` (for QUIC) |

### Protocol-Specific Fields

| Field | Type | Description |
|---|---|---|
| `protocol` | string | Detected L7 protocol (`https`, `grpc`, `kafka`, `wss`, etc.) |
| `http_version` | string | HTTP version: `1.0`, `1.1`, `2` |
| `http_method` | string | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, etc. |
| `http_path` | string | HTTP request path |
| `http_host` | string | HTTP Host header value |
| `http_status` | integer | HTTP response status code |
| `user_agent` | string | User-Agent header value |
| `grpc_status` | integer | gRPC status code (0–16) |
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

### Kubernetes Metadata Fields

| Field | Type | Description |
|---|---|---|
| `k8s_pod` | string | Pod name (via downward API) |
| `k8s_namespace` | string | Namespace (via downward API) |
| `container_id` | string | Short container ID (12 characters) |

### Event Types

| `event_type` | Description |
|---|---|
| *(default / absent)* | Captured plaintext from `SSL_read` / `SSL_write` |
| `tcp_error` | `connect()` syscall failure (`ECONNREFUSED`, `ETIMEDOUT`, etc.) |
| `tls_close` | Peer closed TLS connection (`SSL_read` returned 0) |
| `tls_error` | `SSL_read` / `SSL_write` returned an error |
| `quic_detected` | UDP traffic to a QUIC port (requires `--quic`) |
| `lost_events` | Ring buffer overflow — events were dropped |

---

## Kubernetes Deployment

TLS Tracer runs as a **DaemonSet** — one privileged pod per node with `hostPID: true`. eBPF hooks into the host kernel, capturing TLS traffic from **all pods and containers on the node** across all namespaces. No sidecars, no application changes, no restart required.

Events are automatically enriched with Kubernetes metadata (pod name, namespace, container ID) via the downward API.

### Prerequisites

| Requirement | Details |
|---|---|
| Kubernetes | 1.34+ |
| Node OS | Linux kernel 6.1+ (Amazon Linux 2023 recommended) |
| Container runtime | containerd or CRI-O with privileged container support |
| Permissions | `privileged: true`, `hostPID: true`, `hostNetwork: true` |
| Volumes | `/sys/kernel/debug`, `/sys/kernel/tracing`, `/sys/fs/bpf`, host SSL libraries mounted at `/host/usr/lib*` |

### Helm Chart

```bash
helm install tls-tracer helm/tls-tracer \
  --namespace tls-tracer --create-namespace

# Verify
kubectl -n tls-tracer get pods -o wide

# Stream logs
kubectl -n tls-tracer logs -l app.kubernetes.io/name=tls-tracer --tail=50 -f
```

To uninstall:

```bash
helm uninstall tls-tracer -n tls-tracer
```

### Helm Values Reference

| Value | Default | Description |
|---|---|---|
| `outputFormat` | `json` | Output format: `json` or `text` |
| `verbose` | `true` | Enable verbose logging |
| `filterPid` | `0` | Filter by PID (`0` = all) |
| `filterUid` | `0` | Filter by UID (`0` = all) |
| `sslLibPath` | `""` | Custom `libssl.so` path (empty = auto-detect) |
| `sanitizePatterns` | `["apikey=[^&]*"]` | URL sanitisation regex patterns |
| `companyPrefix` | `""` | Prefix for Kubernetes resource names |
| `image.repository` | `ghcr.io/scgis-wales/ebpf-tls-tracer` | Container image |
| `image.tag` | `0.1.0` | Image tag (pin to a specific version in production) |

### AWS Integration (S3 & Kinesis)

Both integrations are disabled by default and authenticate via IRSA.

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/tls-tracer-role"
```

**S3 log shipping:**

```yaml
s3:
  enabled: true
  bucket: "my-tls-logs"
  prefix: "tls-tracer-logs"
  flushIntervalSeconds: 60
  batchSize: 1000
```

S3 paths use Apache Hive partitioning for efficient querying with Athena or Spark:

```
s3://<bucket>/<prefix>/account=<id>/region=<region>/cluster=<n>/
  namespace=<ns>/app=<app>/env=<env>/year=YYYY/month=MM/day=DD/hour=HH/<file>.json
```

**Kinesis Firehose:**

```yaml
kinesis:
  enabled: true
  deliveryStreamName: "tls-tracer-stream"
  batchSize: 500
  flushIntervalSeconds: 30
```

### Kubernetes Metadata Enrichment

To populate `k8s_pod` and `k8s_namespace` fields on monitored pods, expose the downward API in your workload manifests:

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

### Raw Manifests

If you prefer not to use Helm, raw Kubernetes manifests are available in [`deploy/kubernetes/`](deploy/kubernetes/).

---

## Data Sanitisation & Redaction

Sensitive HTTP headers are **automatically redacted** (replaced with `[REDACTED]`) before events reach stdout:

- `Authorization`
- `Cookie` / `Set-Cookie`
- `X-Api-Key`

Add custom patterns with the `-s` flag (case-insensitive, repeatable):

```bash
sudo ./bin/tls_tracer -f json -s 'token=[^&]*' -s 'password=[^&]*'
```

---

## Performance

eBPF uprobes add approximately **1–2 µs per `SSL_read`/`SSL_write` call**. At 1,700 TPS on an 8-vCPU node, total CPU overhead is typically **below 0.1%**.

| Component | Per-call Overhead | At 1,700 TPS |
|---|---|---|
| Uprobe entry + exit | ~1 µs | ~1.7 ms/s (~0.02% CPU) |
| Data copy to ring buffer | ~0.5 µs/KB | ~0.85 ms/s |
| User-space poll + JSON formatting | ~2 µs | ~3.4 ms/s |
| **Total** | **~4 µs** | **~6 ms/s (~0.08% CPU)** |

**Design choices for minimal overhead:**

- **4 MB shared ring buffer** — approximately 7% throughput overhead compared to ~50% for per-CPU perf buffers on multi-core nodes ([benchmark](https://nakryiko.com/posts/bpf-ringbuf/)).
- **Adaptive notification** — the ring buffer signals user space only when the consumer is idle, batching under load.
- **Per-PID Kubernetes metadata cache** with TTL — avoids `/proc` reads on every event.
- **Rate-limited `/proc` reads** — capped at 50/s to prevent I/O storms under PID churn.
- **Variable-length events** — only copies actual data bytes, not fixed 16 KB buffers.

> **Kernel note:** Linux 6.1+ is recommended. Kernels prior to 6.12.8 contain a ring buffer race condition (CVE-2025-40319); the tracer emits a warning at startup on affected versions.

---

## Building from Source

### Build Dependencies

| Debian / Ubuntu | RHEL / AL2023 / Fedora | Purpose |
|---|---|---|
| `clang`, `llvm` | `clang`, `llvm` | BPF programme compiler |
| `gcc`, `make` | `gcc`, `make` | User-space compiler and build system |
| `libbpf-dev` | `libbpf-devel` | BPF user-space library |
| `libelf-dev` | `elfutils-libelf-devel` | ELF parsing |
| `zlib1g-dev` | `zlib-devel` | Compression |
| `linux-libc-dev` | `kernel-headers` | Kernel headers for BPF |

```bash
# Debian / Ubuntu
sudo apt-get install clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev

# AL2023 / RHEL / Fedora
sudo dnf install clang llvm gcc make libbpf-devel elfutils-libelf-devel zlib-devel \
  kernel-devel kernel-headers

make            # Build BPF programme + user-space binary
make test       # Run unit tests (62 tests)
sudo make install   # Install to /usr/local
```

### Docker

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

### Amazon Linux 2023 / EKS

AL2023 on EKS ships with kernel 6.12 — all eBPF features (BTF, uprobes, kprobes, BPF JIT) are enabled out of the box. No kernel configuration is required.

```bash
sudo dnf install -y clang llvm gcc make libbpf-devel elfutils-libelf-devel \
  zlib-devel kernel-devel-$(uname -r) kernel-headers-$(uname -r) openssl-devel bpftool

git clone https://github.com/SCGIS-Wales/ebpf-tls-tracer.git
cd ebpf-tls-tracer && make && make test
sudo ./bin/tls_tracer -f json -v
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          User Space                              │
│                                                                  │
│  tls_tracer (CLI)                                                │
│    ├── Argument parsing & configuration (getopt_long)            │
│    ├── OpenSSL version validation (dlopen / dlsym)               │
│    ├── BPF object loading (libbpf)                               │
│    ├── Kprobe attach: connect(), tcp_set_state, udp_sendmsg      │
│    ├── Uprobe attach: SSL_read/write, SSL_version,               │
│    │    SSL_get_current_cipher, SSL_get_certificate              │
│    ├── Ring buffer polling (variable-length events)              │
│    ├── L7 protocol detection (HTTP, gRPC, Kafka, WS, …)         │
│    ├── Kubernetes metadata enrichment (/proc/<pid>/environ)      │
│    ├── DNS hostname caching (per pid:fd)                         │
│    └── Event formatting (text / JSON) + sanitisation             │
│                                                                  │
├──────────────── Ring Buffer (4 MB, shared) ──────────────────────┤
│                                                                  │
│                        Kernel Space                              │
│                                                                  │
│  bpf_program.o (eBPF probes)                                     │
│    ├── kprobe/__sys_connect        → save sockaddr               │
│    ├── kretprobe/__sys_connect     → store conn_info in map      │
│    ├── kprobe/tcp_set_state        → capture local + remote addr │
│    ├── kprobe/udp_sendmsg          → QUIC detection (opt-in)     │
│    ├── uprobe/SSL_read             → save buffer pointer         │
│    ├── uretprobe/SSL_read          → capture data + enrich       │
│    ├── uprobe/SSL_write            → save buffer pointer         │
│    ├── uretprobe/SSL_write         → capture data + enrich       │
│    ├── uprobe/SSL_version          → capture TLS version         │
│    ├── uprobe/SSL_get_current_cipher → capture cipher suite      │
│    └── uprobe/SSL_get_certificate    → detect mTLS              │
│                                                                  │
│  BPF Maps                                                        │
│    ├── ssl_args_map       (HASH)         per-thread SSL args     │
│    ├── conn_info_map      (LRU_HASH)     pid_tgid → addresses   │
│    ├── ssl_version_map    (LRU_HASH)     SSL* → TLS version     │
│    ├── cipher_name_map    (LRU_HASH)     SSL* → cipher name     │
│    ├── mtls_map           (LRU_HASH)     SSL* → mTLS flag       │
│    ├── event_buf     (PERCPU_ARRAY)      scratch buffer          │
│    ├── tls_events    (RINGBUF, 4 MB)     user-space output       │
│    └── dropped_events (PERCPU_ARRAY)     drop counter            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### IP Capture Flow

1. **`kprobe/connect()`** — saves the `sockaddr` (remote IP:port) on syscall entry.
2. **`kprobe/tcp_set_state`** — fires when TCP reaches `ESTABLISHED`, capturing both local and remote addresses from `struct sock` (CO-RE compatible).
3. **`kretprobe/connect()`** — stores `{pid_tgid} → conn_info_t` in the BPF map.
4. **SSL uretprobes** — extract the socket fd from `SSL->rbio->num` (OpenSSL internal offset) and look up `conn_info_map` to enrich TLS events with IP:port.

---

## Project Structure

```
ebpf-tls-tracer/
├── include/
│   ├── tracer.h              # Shared structs (kernel + user space)
│   ├── config.h              # Configuration constants
│   ├── k8s.h                 # Kubernetes metadata interface
│   ├── output.h              # Output formatting interface
│   └── protocol.h            # Protocol detection interface
├── src/
│   ├── bpf_program.c         # eBPF kernel probes (14 probe functions)
│   ├── tls_tracer.c          # User-space CLI entry point
│   ├── protocol.c            # L7 protocol detection engine
│   ├── output.c              # JSON / text event formatting
│   └── k8s.c                 # Kubernetes metadata enrichment
├── tests/
│   ├── test_tracer.c         # Struct and constant tests (16 tests)
│   ├── test_helpers.c        # Helper function tests (46 tests)
│   ├── test_s3_shipper.py    # S3 log shipper tests
│   └── test_kinesis_shipper.py  # Kinesis shipper tests
├── scripts/
│   ├── s3_shipper.py         # S3 log shipping sidecar
│   └── kinesis_shipper.py    # Kinesis Firehose sidecar
├── helm/
│   └── tls-tracer/           # Helm chart (DaemonSet, RBAC, S3, Kinesis)
├── deploy/
│   └── kubernetes/           # Raw K8s manifests (alternative to Helm)
├── .github/
│   └── workflows/
│       └── build.yml         # CI: build, test, container image publish
├── Dockerfile                # Multi-stage build (Debian trixie)
├── Makefile                  # Build system
└── LICENSE                   # MIT
```

---

## Requirements

| Requirement | Details |
|---|---|
| **Operating system** | Linux x86_64 or aarch64 (ARM64) |
| **Kernel** | 5.5+ minimum; **6.1+ recommended** |
| **Privileges** | Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` |
| **OpenSSL** | `libssl.so` installed (auto-detected) |
| **Runtime libraries** | `libbpf`, `libelf`, `zlib` |
| **Kernel config** | `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_KPROBE_EVENTS`, `CONFIG_UPROBE_EVENTS`, `CONFIG_DEBUG_INFO_BTF` |

> These kernel options are enabled by default on Ubuntu 22.04+, Debian 12+, Amazon Linux 2023, Fedora 38+, and RHEL 9+.

**Verify your system:**

```bash
uname -r                                    # Kernel 5.5+ required
ls /sys/kernel/btf/vmlinux                  # BTF support present
cat /proc/sys/net/core/bpf_jit_enable       # BPF JIT enabled (1 or 2)
```

**Install runtime dependencies:**

```bash
# Debian / Ubuntu
sudo apt-get install libbpf1 libelf1 zlib1g libssl3

# AL2023 / RHEL / Fedora
sudo dnf install libbpf elfutils-libelf zlib openssl-libs
```

---

## Licence

MIT Licence — see [LICENCE](LICENSE) for details.

Copyright © 2024 Society for Conservation GIS Wales.
