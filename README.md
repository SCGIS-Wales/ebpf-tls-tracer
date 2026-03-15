# TLS Tracer

An eBPF-based CLI tool for intercepting and inspecting TLS/SSL traffic in real time on Linux. It attaches uprobes to OpenSSL's `SSL_read` and `SSL_write` functions to capture plaintext data flowing through TLS connections — without modifying applications or terminating TLS sessions.

## Features

- **Trace TLS connections** and capture plaintext data from `SSL_read`/`SSL_write`
- **Filter** captured data by PID, UID, or other criteria
- **Output** in human-readable text or structured JSON format
- **Hex dump** mode for binary protocol inspection
- **Auto-detection** of the system's OpenSSL library path
- **Low overhead** — uses eBPF perf buffers for efficient kernel-to-user data transfer
- **Graceful shutdown** with proper resource cleanup on Ctrl+C / SIGTERM

## Requirements

- Linux kernel 5.4+ (with eBPF support)
- OpenSSL (libssl.so) installed on the target system
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- Build dependencies: `clang`, `gcc`, `make`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`

## Building

```bash
# Install build dependencies (Debian/Ubuntu)
sudo apt-get install clang llvm gcc make libbpf-dev libelf-dev zlib1g-dev linux-libc-dev

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
12:34:56     WRITE  PID=1234   TID=1234   UID=1000 COMM=curl            LEN=78
GET /api/v1/status HTTP/1.1
Host: example.com

12:34:56     READ   PID=1234   TID=1234   UID=1000 COMM=curl            LEN=256
HTTP/1.1 200 OK
Content-Type: application/json
```

**JSON mode (`-f json`):**

```json
{"timestamp_ns":123456789,"pid":1234,"tid":1234,"uid":1000,"comm":"curl","direction":"WRITE","data_len":78,"data":"..."}
```

## Docker

```bash
# Build the image
docker build -t tls_tracer .

# Run (requires --privileged for eBPF access)
docker run --rm --privileged tls_tracer -v
```

## Architecture

```
┌──────────────────────────────────────────────┐
│                  User Space                  │
│                                              │
│  tls_tracer (CLI)                            │
│    ├── Argument parsing (getopt)             │
│    ├── BPF object loading (libbpf)           │
│    ├── Uprobe attachment to libssl.so         │
│    ├── Perf buffer polling                   │
│    └── Event formatting (text/json)          │
│                                              │
├──────────── perf buffer ─────────────────────┤
│                                              │
│                Kernel Space                  │
│                                              │
│  bpf_program.o (eBPF probes)                 │
│    ├── uprobe/SSL_read   → save buffer ptr   │
│    ├── uretprobe/SSL_read  → capture data    │
│    ├── uprobe/SSL_write  → save buffer ptr   │
│    └── uretprobe/SSL_write → capture data    │
│                                              │
└──────────────────────────────────────────────┘
```

The eBPF program hooks OpenSSL at two points per function:
1. **Entry probe** (`uprobe`): Saves the user buffer pointer in a per-thread BPF hash map
2. **Return probe** (`uretprobe`): Reads the plaintext data from the saved buffer and sends it to user space via perf events

## Project Structure

```
ebpf_tls_cli/
├── include/
│   └── tracer.h          # Shared data structures (kernel + user space)
├── src/
│   ├── bpf_program.c     # eBPF kernel probes (compiled to BPF bytecode)
│   └── tls_tracer.c      # User-space CLI tool
├── tests/
│   └── test_tracer.c     # Unit tests
├── .github/
│   └── workflows/
│       └── build.yml     # CI pipeline
├── Dockerfile            # Multi-stage container build
├── Makefile              # Build system
├── LICENSE               # MIT License
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
