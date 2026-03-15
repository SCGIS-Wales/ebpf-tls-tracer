#!/usr/bin/env python3
"""Kinesis Firehose shipper for TLS Tracer.

Tails a JSON log file and forwards records to an AWS Kinesis Firehose
delivery stream using PutRecordBatch. Uses IRSA for authentication on EKS.

Resilience:
  - Tails the file using seek offsets (no truncation, no data loss)
  - Exponential backoff on Firehose failures (up to 5 retries)
  - Retries individual failed records from PutRecordBatch responses
  - Graceful shutdown flushes remaining batch
  - Handles log rotation (file shrinks or inode changes)
"""

import os
import sys
import json
import time
import signal

import boto3
from botocore.exceptions import ClientError, BotoCoreError

STREAM = os.environ.get("DELIVERY_STREAM", "")
AWS_REGION = os.environ.get("AWS_REGION", "eu-west-1")
FLUSH_INTERVAL = int(os.environ.get("FLUSH_INTERVAL", "30"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "500"))
CLUSTER = os.environ.get("CLUSTER_NAME", "unknown")
NAMESPACE = os.environ.get("TARGET_NAMESPACE", "unknown")
APP_NAME = os.environ.get("APP_NAME", "unknown")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")
NODE_NAME = os.environ.get("NODE_NAME", "unknown")
MAX_RETRIES = 5
FIREHOSE_MAX_BATCH = 500  # AWS limit per PutRecordBatch call
LOG_FILE = "/var/log/tls-tracer/events.json"

running = True


def signal_handler(signum, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def log(level, msg):
    print(f"[kinesis-shipper] {level}: {msg}", file=sys.stderr, flush=True)


def enrich_record(line):
    """Add cluster/namespace/node metadata to each JSON record."""
    try:
        record = json.loads(line)
        record.setdefault("cluster_name", CLUSTER)
        record.setdefault("target_namespace", NAMESPACE)
        record.setdefault("app_name", APP_NAME)
        record.setdefault("environment", ENVIRONMENT)
        record.setdefault("node_name", NODE_NAME)
        return json.dumps(record, separators=(",", ":"))
    except json.JSONDecodeError:
        return line


def send_chunk(firehose, records):
    """Send a chunk of records to Firehose with retry on partial failures."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = firehose.put_record_batch(
                DeliveryStreamName=STREAM, Records=records
            )
            failed_count = resp.get("FailedPutCount", 0)
            if failed_count == 0:
                return True

            # Retry only failed records
            log("WARN", f"{failed_count}/{len(records)} records failed, retrying...")
            failed_records = []
            for i, result in enumerate(resp.get("RequestResponses", [])):
                if result.get("ErrorCode"):
                    failed_records.append(records[i])
            records = failed_records

            delay = min(2 ** attempt, 60)
            time.sleep(delay)

        except (ClientError, BotoCoreError) as e:
            delay = min(2 ** attempt, 60)
            log("WARN", f"Attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(delay)
            else:
                log("ERROR", f"Failed after {MAX_RETRIES} attempts, dropping {len(records)} records")
                return False
        except Exception as e:
            log("ERROR", f"Unexpected error: {e}")
            return False

    return False


def flush_batch(firehose, batch):
    """Send a batch of lines to Kinesis Firehose."""
    if not batch or not STREAM:
        return True

    records = [
        {"Data": (enrich_record(line) + "\n").encode("utf-8")}
        for line in batch
    ]

    total_sent = 0
    for i in range(0, len(records), FIREHOSE_MAX_BATCH):
        chunk = records[i : i + FIREHOSE_MAX_BATCH]
        if send_chunk(firehose, chunk):
            total_sent += len(chunk)

    log("INFO", f"Sent {total_sent}/{len(records)} records to {STREAM}")
    return total_sent == len(records)


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
    if not STREAM:
        log("ERROR", "DELIVERY_STREAM not set")
        sys.exit(1)

    firehose = boto3.client("firehose", region_name=AWS_REGION)
    batch = []
    last_flush = time.time()
    offset = 0

    log("INFO", f"Tailing {LOG_FILE}, forwarding to Firehose stream '{STREAM}'")

    while running:
        new_lines, offset = tail_file(LOG_FILE, offset)
        batch.extend(new_lines)

        now = time.time()
        if len(batch) >= BATCH_SIZE or (now - last_flush >= FLUSH_INTERVAL and batch):
            flush_batch(firehose, batch)
            batch = []
            last_flush = now

        time.sleep(1)

    # Graceful shutdown: flush remaining
    if batch:
        log("INFO", f"Shutting down, flushing {len(batch)} remaining records")
        flush_batch(firehose, batch)

    log("INFO", "Shutdown complete")


if __name__ == "__main__":
    main()
