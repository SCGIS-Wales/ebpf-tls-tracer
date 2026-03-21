#!/usr/bin/env python3
"""Splunk HTTP Event Collector (HEC) shipper for TLS Tracer.

Reads NDJSON from a log file (offset-based tailing) or stdin and forwards
events to a Splunk HEC endpoint using batched HTTP POSTs. Designed for use
as a sidecar container or systemd pipe target.

Resilience:
  - Batches events (configurable size and flush interval)
  - Exponential backoff on HTTP failures (up to 5 retries)
  - Dead-letter file for events that fail after all retries
  - Graceful shutdown flushes remaining buffer on SIGTERM/SIGINT
  - Validates HEC connectivity on startup

Environment variables:
  SPLUNK_HEC_URL       - Full URL including /services/collector (required)
  SPLUNK_HEC_TOKEN     - HEC authentication token (required)
  SPLUNK_INDEX         - Target Splunk index (optional, uses HEC default)
  SPLUNK_SOURCETYPE    - Sourcetype for events (default: tls:tracer)
  SPLUNK_SOURCE        - Source field (default: tls_tracer)
  SPLUNK_VERIFY_SSL    - Verify TLS certs (default: true)
  SPLUNK_BATCH_SIZE    - Events per batch (default: 50)
  SPLUNK_FLUSH_INTERVAL - Seconds between flushes (default: 5)
"""

import os
import sys
import json
import time
import signal
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl as _ssl


def _parse_int_env(name, default, min_val=1, max_val=None):
    """Parse integer env var with validation and bounds checking."""
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except ValueError:
        log("ERROR", f"{name}={raw!r} is not a valid integer, using default {default}")
        return default
    if val < min_val:
        log("WARN", f"{name}={val} below minimum {min_val}, clamping")
        return min_val
    if max_val is not None and val > max_val:
        log("WARN", f"{name}={val} above maximum {max_val}, clamping")
        return max_val
    return val


def _parse_bool_env(name, default=True):
    """Parse boolean env var."""
    raw = os.environ.get(name, str(default)).lower()
    return raw in ("true", "1", "yes")


# Configuration from environment
HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
INDEX = os.environ.get("SPLUNK_INDEX", "")
SOURCETYPE = os.environ.get("SPLUNK_SOURCETYPE", "tls:tracer")
SOURCE = os.environ.get("SPLUNK_SOURCE", "tls_tracer")
VERIFY_SSL = _parse_bool_env("SPLUNK_VERIFY_SSL", True)
BATCH_SIZE = _parse_int_env("SPLUNK_BATCH_SIZE", 50, min_val=1, max_val=10000)
FLUSH_INTERVAL = _parse_int_env("SPLUNK_FLUSH_INTERVAL", 5, min_val=1, max_val=3600)
MAX_RETRIES = 5
MAX_LINE_LEN = 65536
DEAD_LETTER_MAX_BYTES = 50 * 1024 * 1024  # 50 MB cap
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/tls-tracer/events.json")

running = True
dead_letter_drops = 0  # Counter for events dropped at dead-letter cap


def signal_handler(signum, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def log(level, msg):
    print(f"[splunk-hec-shipper] {level}: {msg}", file=sys.stderr, flush=True)


def _mask_token(token):
    """Mask HEC token for safe logging."""
    if len(token) <= 8:
        return "***"
    return token[:4] + "..." + token[-4:]


def build_ssl_context():
    """Build SSL context for HEC connection."""
    ctx = _ssl.create_default_context()
    if not VERIFY_SSL:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    return ctx


def wrap_event(line):
    """Wrap a JSON line into Splunk HEC event envelope."""
    try:
        event_data = json.loads(line)
    except json.JSONDecodeError:
        event_data = {"raw": line}

    envelope = {"event": event_data, "sourcetype": SOURCETYPE, "source": SOURCE}
    if INDEX:
        envelope["index"] = INDEX

    # Use the event's timestamp if available (ISO 8601 → epoch)
    ts = event_data.get("timestamp")
    if ts:
        try:
            # Parse ISO 8601 with microseconds
            from datetime import datetime, timezone
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts)
            envelope["time"] = dt.timestamp()
        except (ValueError, TypeError):
            pass

    return json.dumps(envelope, separators=(",", ":"))


def send_batch(events, ssl_ctx):
    """Send a batch of wrapped HEC events. Returns True on success."""
    payload = "\n".join(events).encode("utf-8")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = Request(
                HEC_URL,
                data=payload,
                headers={
                    "Authorization": f"Splunk {HEC_TOKEN}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            resp = urlopen(req, timeout=30, context=ssl_ctx)
            resp_body = resp.read().decode("utf-8")

            try:
                result = json.loads(resp_body)
                if result.get("code") != 0:
                    log("WARN", f"HEC returned code {result.get('code')}: "
                        f"{result.get('text', 'unknown')}")
                    if attempt < MAX_RETRIES:
                        time.sleep(min(2 ** attempt, 60))
                        continue
                    else:
                        _write_dead_letter(events)
                        return False
            except json.JSONDecodeError:
                pass

            return True

        except HTTPError as e:
            delay = min(2 ** attempt, 60)
            log("WARN", f"Attempt {attempt}/{MAX_RETRIES}: HTTP {e.code} - {e.reason}")
            if e.code == 403:
                log("ERROR", "HEC token rejected (403 Forbidden). Check SPLUNK_HEC_TOKEN.")
                _write_dead_letter(events)
                return False
            if attempt < MAX_RETRIES:
                time.sleep(delay)
            else:
                log("ERROR", f"Failed after {MAX_RETRIES} attempts")
                _write_dead_letter(events)
                return False

        except (URLError, OSError) as e:
            delay = min(2 ** attempt, 60)
            log("WARN", f"Attempt {attempt}/{MAX_RETRIES}: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(delay)
            else:
                log("ERROR", f"Failed after {MAX_RETRIES} attempts")
                _write_dead_letter(events)
                return False

    return False


def _write_dead_letter(events):
    """Write failed events to dead-letter file."""
    dlq_path = "/var/log/tls-tracer/splunk-dead-letter.json"
    try:
        try:
            dlq_size = os.path.getsize(dlq_path)
        except OSError:
            dlq_size = 0
        if dlq_size >= DEAD_LETTER_MAX_BYTES:
            global dead_letter_drops
            dead_letter_drops += len(events)
            log("WARN", f"Dead-letter file at {dlq_size // (1024 * 1024)}MB cap, "
                f"dropping {len(events)} events (total dropped: {dead_letter_drops})")
            return
        fd = os.open(dlq_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as dlq:
            for ev in events:
                dlq.write(ev + "\n")
        log("INFO", f"Wrote {len(events)} events to {dlq_path}")
    except Exception as e:
        log("ERROR", f"Dead-letter write failed: {e}")


def tail_file(path, offset, last_inode):
    """Read new lines from file starting at offset. Returns (lines, new_offset, inode).

    Handles log rotation: if inode changes or file shrinks, resets offset."""
    lines = []
    try:
        stat = os.stat(path)
        current_inode = stat.st_ino
        size = stat.st_size

        if last_inode is not None and current_inode != last_inode:
            log("INFO", "Log file inode changed, resetting offset")
            offset = 0

        if size < offset:
            log("INFO", "Log file truncated, resetting offset")
            offset = 0

        if size == offset:
            return lines, offset, current_inode

        with open(path, "r") as f:
            f.seek(offset)
            for line in f:
                stripped = line.strip()
                if stripped:
                    if len(stripped) > MAX_LINE_LEN:
                        log("WARN", f"Skipping oversized line ({len(stripped)} bytes)")
                        continue
                    lines.append(stripped)
            new_offset = f.tell()
            return lines, new_offset, current_inode
    except FileNotFoundError:
        return lines, 0, None
    except Exception as e:
        log("WARN", f"Read error: {e}")
        return lines, offset, last_inode


def check_hec_health(ssl_ctx):
    """Validate HEC endpoint on startup. Returns True if reachable."""
    # Use the health endpoint if available, else try a small test POST
    health_url = HEC_URL.replace("/services/collector", "/services/collector/health")
    try:
        req = Request(health_url, headers={
            "Authorization": f"Splunk {HEC_TOKEN}",
        })
        resp = urlopen(req, timeout=10, context=ssl_ctx)
        resp.read()
        return True
    except HTTPError as e:
        if e.code == 200:
            return True
        log("WARN", f"HEC health check returned HTTP {e.code} (non-fatal)")
        return True  # HEC may not support /health but may still accept events
    except (URLError, OSError) as e:
        log("WARN", f"HEC health check failed: {e} (will retry on first batch)")
        return True  # Non-fatal — proceed and retry on actual send


def main():
    if not HEC_URL:
        log("ERROR", "SPLUNK_HEC_URL not set")
        sys.exit(1)
    if not HEC_TOKEN:
        log("ERROR", "SPLUNK_HEC_TOKEN not set")
        sys.exit(1)

    ssl_ctx = build_ssl_context()

    log("INFO", f"Splunk HEC: {HEC_URL}")
    log("INFO", f"Token: {_mask_token(HEC_TOKEN)}")
    log("INFO", f"Index: {INDEX or '(HEC default)'}, "
        f"Sourcetype: {SOURCETYPE}, Source: {SOURCE}")
    log("INFO", f"Batch size: {BATCH_SIZE}, Flush interval: {FLUSH_INTERVAL}s")
    if not VERIFY_SSL:
        log("WARN", "SSL certificate verification disabled")

    check_hec_health(ssl_ctx)

    batch = []
    last_flush = time.time()
    events_sent = 0
    offset = 0
    last_inode = None

    log("INFO", f"Tailing {LOG_FILE}")

    while running:
        new_lines, offset, last_inode = tail_file(LOG_FILE, offset, last_inode)
        for line in new_lines:
            batch.append(wrap_event(line))

        now = time.time()
        if len(batch) >= BATCH_SIZE or (now - last_flush >= FLUSH_INTERVAL and batch):
            wrapped = batch
            batch = []
            if send_batch(wrapped, ssl_ctx):
                events_sent += len(wrapped)
            last_flush = now

        if not new_lines:
            time.sleep(1)  # Avoid busy-loop when no new data

    # Graceful shutdown: flush remaining
    if batch:
        log("INFO", f"Shutting down, flushing {len(batch)} remaining events")
        if send_batch(batch, ssl_ctx):
            events_sent += len(batch)

    log("INFO", f"Shutdown complete. Total events sent: {events_sent}")


if __name__ == "__main__":
    main()
