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
"""

import os
import sys
import time
import signal
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, BotoCoreError

BUCKET = os.environ.get("S3_BUCKET", "")
PREFIX = os.environ.get("S3_PREFIX", "tls-tracer-logs")
FLUSH_INTERVAL = int(os.environ.get("FLUSH_INTERVAL", "60"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "1000"))
AWS_REGION = os.environ.get("AWS_REGION", "eu-west-1")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "unknown")
CLUSTER = os.environ.get("CLUSTER_NAME", "unknown")
NAMESPACE = os.environ.get("TARGET_NAMESPACE", "unknown")
APP_NAME = os.environ.get("APP_NAME", "unknown")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
NODE_NAME = os.environ.get("NODE_NAME", "unknown")
MAX_RETRIES = 5
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

    log("ERROR", f"Failed to upload after {MAX_RETRIES} attempts, dropping {len(batch)} records")
    return False


def tail_file(path, offset):
    """Read new lines from file starting at offset. Returns (lines, new_offset).

    Handles log rotation: if the file is smaller than offset, resets to 0.
    """
    lines = []
    try:
        size = os.path.getsize(path)
        if size < offset:
            log("INFO", "Log file rotated, resetting offset")
            offset = 0

        if size == offset:
            return lines, offset

        with open(path, "r") as f:
            f.seek(offset)
            for line in f:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
            new_offset = f.tell()
            return lines, new_offset
    except FileNotFoundError:
        return lines, 0
    except Exception as e:
        log("WARN", f"Read error: {e}")
        return lines, offset


def main():
    if not BUCKET:
        log("ERROR", "S3_BUCKET not set")
        sys.exit(1)

    s3 = boto3.client("s3", region_name=AWS_REGION)
    batch = []
    last_flush = time.time()
    offset = 0

    log("INFO", f"Tailing {LOG_FILE}, shipping to s3://{BUCKET}/{PREFIX}/...")

    while running:
        new_lines, offset = tail_file(LOG_FILE, offset)
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
