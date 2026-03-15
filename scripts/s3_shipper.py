#!/usr/bin/env python3
"""S3 log shipper for TLS Tracer.

Tails a JSON log file and ships batches to S3 using Apache Hive-style
directory partitioning. Uses IRSA for authentication on EKS.

Path format:
  s3://<bucket>/<prefix>/account=<id>/region=<region>/cluster=<name>/
    namespace=<ns>/app=<app>/env=<env>/year=YYYY/month=MM/day=DD/
    hour=HH/<node>-<timestamp>.json

Resilience:
  - Tails the file using seek offsets (no truncation, no data loss)
  - Exponential backoff on S3 upload failures (up to 5 retries)
  - Graceful shutdown flushes remaining batch
  - Handles log rotation (file shrinks or inode changes)
  - R10 fix: tracks file inode to detect tee restarts
"""

import os
import sys
import time
import signal
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, BotoCoreError


def _parse_int_env(name, default, min_val=1, max_val=None):
    """S8 fix: parse integer env var with validation and bounds checking."""
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except ValueError:
        print(f"[s3-shipper] ERROR: {name}={raw!r} is not a valid integer, "
              f"using default {default}", file=sys.stderr, flush=True)
        return default
    if val < min_val:
        print(f"[s3-shipper] WARN: {name}={val} below minimum {min_val}, "
              f"clamping", file=sys.stderr, flush=True)
        return min_val
    if max_val is not None and val > max_val:
        print(f"[s3-shipper] WARN: {name}={val} above maximum {max_val}, "
              f"clamping", file=sys.stderr, flush=True)
        return max_val
    return val


BUCKET = os.environ.get("S3_BUCKET", "")
PREFIX = os.environ.get("S3_PREFIX", "tls-tracer-logs")
FLUSH_INTERVAL = _parse_int_env("FLUSH_INTERVAL", 60, min_val=1, max_val=3600)
BATCH_SIZE = _parse_int_env("BATCH_SIZE", 1000, min_val=1, max_val=100000)
AWS_REGION = os.environ.get("AWS_REGION", "eu-west-1")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "unknown")
CLUSTER = os.environ.get("CLUSTER_NAME", "unknown")
NAMESPACE = os.environ.get("TARGET_NAMESPACE", "unknown")
APP_NAME = os.environ.get("APP_NAME", "unknown")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
NODE_NAME = os.environ.get("NODE_NAME", "unknown")
MAX_RETRIES = 5
MAX_LINE_LEN = 65536  # Skip lines larger than 64KB to prevent memory exhaustion
LOG_FILE = "/var/log/tls-tracer/events.json"

running = True


def signal_handler(signum, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def log(level, msg):
    print(f"[s3-shipper] {level}: {msg}", file=sys.stderr, flush=True)


def build_s3_key(now):
    """Build Apache Hive-style S3 key."""
    parts = [
        PREFIX,
        f"account={ACCOUNT_ID}",
        f"region={AWS_REGION}",
        f"cluster={CLUSTER}",
        f"namespace={NAMESPACE}",
        f"app={APP_NAME}",
        f"env={ENVIRONMENT}",
        f"year={now.year:04d}",
        f"month={now.month:02d}",
        f"day={now.day:02d}",
        f"hour={now.hour:02d}",
        f"{NODE_NAME}-{now.strftime('%Y%m%dT%H%M%S')}.json",
    ]
    return "/".join(parts)


def flush_batch(s3_client, batch):
    """Upload a batch of JSON lines to S3 with retry and backoff."""
    if not batch or not BUCKET:
        return True

    now = datetime.now(timezone.utc)
    key = build_s3_key(now)
    body = "\n".join(batch) + "\n"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            s3_client.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
            )
            log("INFO", f"Uploaded {len(batch)} records to s3://{BUCKET}/{key}")
            return True
        except (ClientError, BotoCoreError) as e:
            delay = min(2 ** attempt, 60)
            log("WARN", f"Upload attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                log("INFO", f"Retrying in {delay}s...")
                time.sleep(delay)
        except Exception as e:
            log("ERROR", f"Unexpected error: {e}")
            return False

    log("ERROR", f"Failed to upload after {MAX_RETRIES} attempts, "
        f"writing {len(batch)} records to dead-letter file")
    # S9 fix: use restrictive permissions (0o600) on dead-letter file
    try:
        dlq_path = "/var/log/tls-tracer/dead-letter.json"
        fd = os.open(dlq_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as dlq:
            dlq.write(body)
        log("INFO", f"Wrote {len(batch)} records to {dlq_path}")
    except Exception as dlq_err:
        log("ERROR", f"Dead-letter write failed: {dlq_err}, dropping {len(batch)} records")
    return False


def tail_file(path, offset, last_inode):
    """Read new lines from file starting at offset. Returns (lines, new_offset, inode).

    Handles log rotation: if file inode changes or file shrinks, resets offset.
    R10 fix: track inode to detect tee restarts (new file = new inode).
    """
    lines = []
    try:
        stat = os.stat(path)
        current_inode = stat.st_ino
        size = stat.st_size

        # R10: inode changed means tee restarted and created a new file
        if last_inode is not None and current_inode != last_inode:
            log("INFO", "Log file inode changed (tee restart), resetting offset")
            offset = 0

        if size < offset:
            log("INFO", "Log file rotated/truncated, resetting offset")
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


def main():
    if not BUCKET:
        log("ERROR", "S3_BUCKET not set")
        sys.exit(1)

    s3 = boto3.client("s3", region_name=AWS_REGION)
    batch = []
    last_flush = time.time()
    offset = 0
    last_inode = None

    log("INFO", f"Tailing {LOG_FILE}, shipping to s3://{BUCKET}/{PREFIX}/...")

    while running:
        new_lines, offset, last_inode = tail_file(LOG_FILE, offset, last_inode)
        batch.extend(new_lines)

        now = time.time()
        if len(batch) >= BATCH_SIZE or (now - last_flush >= FLUSH_INTERVAL and batch):
            flush_batch(s3, batch)
            batch = []
            last_flush = now

        time.sleep(1)

    # Graceful shutdown: flush remaining
    if batch:
        log("INFO", f"Shutting down, flushing {len(batch)} remaining records")
        flush_batch(s3, batch)

    log("INFO", "Shutdown complete")


if __name__ == "__main__":
    main()
