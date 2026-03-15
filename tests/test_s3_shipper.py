#!/usr/bin/env python3
"""Unit tests for S3 log shipper."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestS3ShipperTailFile(unittest.TestCase):
    """Test tail_file() function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.tmpdir, "events.json")

    def tearDown(self):
        if os.path.exists(self.log_file):
            os.unlink(self.log_file)
        os.rmdir(self.tmpdir)

    def test_tail_new_lines(self):
        """Should read new lines from the file."""
        import s3_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n')
            f.write('{"event":"second"}\n')

        lines, offset, inode = s3_shipper.tail_file(self.log_file, 0, None)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], '{"event":"first"}')
        self.assertEqual(lines[1], '{"event":"second"}')
        self.assertGreater(offset, 0)
        self.assertIsNotNone(inode)

    def test_tail_incremental(self):
        """Should only read lines added after the last offset."""
        import s3_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n')

        lines, offset, inode = s3_shipper.tail_file(self.log_file, 0, None)
        self.assertEqual(len(lines), 1)

        # Append more data
        with open(self.log_file, "a") as f:
            f.write('{"event":"second"}\n')

        lines, new_offset, _ = s3_shipper.tail_file(self.log_file, offset, inode)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"event":"second"}')
        self.assertGreater(new_offset, offset)

    def test_tail_no_new_data(self):
        """Should return empty list when no new data."""
        import s3_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n')

        lines, offset, inode = s3_shipper.tail_file(self.log_file, 0, None)
        self.assertEqual(len(lines), 1)

        # No new data
        lines, same_offset, _ = s3_shipper.tail_file(self.log_file, offset, inode)
        self.assertEqual(len(lines), 0)
        self.assertEqual(same_offset, offset)

    def test_tail_file_not_found(self):
        """Should return empty list and offset 0 for missing file."""
        import s3_shipper

        lines, offset, inode = s3_shipper.tail_file("/nonexistent/path", 0, None)
        self.assertEqual(lines, [])
        self.assertEqual(offset, 0)
        self.assertIsNone(inode)

    def test_tail_log_rotation(self):
        """Should reset offset when file shrinks (rotation)."""
        import s3_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n' * 10)

        _, offset, inode = s3_shipper.tail_file(self.log_file, 0, None)

        # Simulate rotation: write smaller file
        with open(self.log_file, "w") as f:
            f.write('{"event":"rotated"}\n')

        lines, new_offset, _ = s3_shipper.tail_file(self.log_file, offset, inode)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"event":"rotated"}')

    def test_tail_skip_empty_lines(self):
        """Should skip empty lines."""
        import s3_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n\n\n{"event":"second"}\n')

        lines, _, _ = s3_shipper.tail_file(self.log_file, 0, None)
        self.assertEqual(len(lines), 2)

    def test_tail_inode_change_detection(self):
        """R10: should reset offset when inode changes (tee restart)."""
        import s3_shipper

        # Write enough data to get a large offset
        with open(self.log_file, "w") as f:
            for i in range(20):
                f.write(f'{{"event":"line_{i}"}}\n')

        _, offset, inode = s3_shipper.tail_file(self.log_file, 0, None)
        self.assertGreater(offset, 100)

        # Simulate tee restart: write a small new file
        # Use a different path + rename to guarantee a different inode
        alt_file = self.log_file + ".new"
        with open(alt_file, "w") as f:
            f.write('{"event":"after_restart"}\n')
        os.unlink(self.log_file)
        os.rename(alt_file, self.log_file)

        lines, new_offset, new_inode = s3_shipper.tail_file(
            self.log_file, offset, inode
        )
        # Either inode changed (reset to 0) or file shrunk (size < offset reset)
        # In both cases, we should read the full new file content
        self.assertGreaterEqual(len(lines), 1)
        self.assertIn('{"event":"after_restart"}', lines)


class TestS3ShipperParseIntEnv(unittest.TestCase):
    """S8: test _parse_int_env validation."""

    def test_valid_int(self):
        import s3_shipper
        with patch.dict(os.environ, {"TEST_VAR": "42"}):
            val = s3_shipper._parse_int_env("TEST_VAR", 10)
            self.assertEqual(val, 42)

    def test_invalid_int_uses_default(self):
        import s3_shipper
        with patch.dict(os.environ, {"TEST_VAR": "abc"}):
            val = s3_shipper._parse_int_env("TEST_VAR", 10)
            self.assertEqual(val, 10)

    def test_below_min_clamps(self):
        import s3_shipper
        with patch.dict(os.environ, {"TEST_VAR": "0"}):
            val = s3_shipper._parse_int_env("TEST_VAR", 10, min_val=1)
            self.assertEqual(val, 1)

    def test_above_max_clamps(self):
        import s3_shipper
        with patch.dict(os.environ, {"TEST_VAR": "99999"}):
            val = s3_shipper._parse_int_env("TEST_VAR", 10, max_val=100)
            self.assertEqual(val, 100)


class TestS3ShipperBuildKey(unittest.TestCase):
    """Test build_s3_key() function."""

    @patch.dict(os.environ, {
        "S3_PREFIX": "logs",
        "AWS_ACCOUNT_ID": "123456",
        "AWS_REGION": "us-east-1",
        "CLUSTER_NAME": "prod",
        "TARGET_NAMESPACE": "apigee",
        "APP_NAME": "gateway",
        "ENVIRONMENT": "production",
        "NODE_NAME": "node-1",
    })
    def test_hive_style_key(self):
        """Should produce Apache Hive-style partitioned path."""
        # Re-import to pick up env vars
        import importlib
        import s3_shipper
        importlib.reload(s3_shipper)

        from datetime import datetime, timezone
        now = datetime(2026, 3, 15, 14, 30, 45, tzinfo=timezone.utc)
        key = s3_shipper.build_s3_key(now)

        self.assertIn("account=123456", key)
        self.assertIn("region=us-east-1", key)
        self.assertIn("cluster=prod", key)
        self.assertIn("namespace=apigee", key)
        self.assertIn("app=gateway", key)
        self.assertIn("env=production", key)
        self.assertIn("year=2026", key)
        self.assertIn("month=03", key)
        self.assertIn("day=15", key)
        self.assertIn("hour=14", key)
        self.assertIn("node-1-", key)
        self.assertTrue(key.endswith(".json"))


class TestS3ShipperFlushBatch(unittest.TestCase):
    """Test flush_batch() function."""

    def test_flush_success(self):
        """Should upload batch to S3."""
        import s3_shipper
        s3_shipper.BUCKET = "test-bucket"

        mock_s3 = MagicMock()
        batch = ['{"event":"test1"}', '{"event":"test2"}']

        result = s3_shipper.flush_batch(mock_s3, batch)

        self.assertTrue(result)
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        self.assertEqual(call_kwargs["Bucket"], "test-bucket")
        self.assertEqual(call_kwargs["ContentType"], "application/json")
        body = call_kwargs["Body"].decode("utf-8")
        self.assertIn('{"event":"test1"}', body)
        self.assertIn('{"event":"test2"}', body)

    def test_flush_empty_batch(self):
        """Should return True for empty batch without calling S3."""
        import s3_shipper
        mock_s3 = MagicMock()
        result = s3_shipper.flush_batch(mock_s3, [])
        self.assertTrue(result)
        mock_s3.put_object.assert_not_called()

    def test_flush_retry_on_failure(self):
        """Should retry on ClientError."""
        import s3_shipper
        from botocore.exceptions import ClientError
        s3_shipper.BUCKET = "test-bucket"

        mock_s3 = MagicMock()
        error_response = {"Error": {"Code": "500", "Message": "Internal Error"}}
        mock_s3.put_object.side_effect = [
            ClientError(error_response, "PutObject"),
            None,  # Success on second attempt
        ]

        result = s3_shipper.flush_batch(mock_s3, ['{"event":"test"}'])
        self.assertTrue(result)
        self.assertEqual(mock_s3.put_object.call_count, 2)

    def test_flush_fails_after_max_retries(self):
        """Should return False after exhausting retries."""
        import s3_shipper
        from botocore.exceptions import ClientError
        s3_shipper.BUCKET = "test-bucket"
        s3_shipper.MAX_RETRIES = 2  # Reduce for fast test

        mock_s3 = MagicMock()
        error_response = {"Error": {"Code": "500", "Message": "Internal Error"}}
        mock_s3.put_object.side_effect = ClientError(error_response, "PutObject")

        result = s3_shipper.flush_batch(mock_s3, ['{"event":"test"}'])
        self.assertFalse(result)
        self.assertEqual(mock_s3.put_object.call_count, 2)


class TestS3ShipperMain(unittest.TestCase):
    """Test main() lifecycle."""

    def test_exits_without_bucket(self):
        """Should exit with error if S3_BUCKET not set."""
        import s3_shipper
        s3_shipper.BUCKET = ""

        with self.assertRaises(SystemExit) as ctx:
            s3_shipper.main()
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
