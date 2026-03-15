#!/usr/bin/env python3
"""Unit tests for Kinesis Firehose log shipper."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestKinesisShipperTailFile(unittest.TestCase):
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
        import kinesis_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n')
            f.write('{"event":"second"}\n')

        lines, offset = kinesis_shipper.tail_file(self.log_file, 0)
        self.assertEqual(len(lines), 2)
        self.assertGreater(offset, 0)

    def test_tail_incremental(self):
        """Should only read lines added after the last offset."""
        import kinesis_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"first"}\n')

        lines, offset = kinesis_shipper.tail_file(self.log_file, 0)
        self.assertEqual(len(lines), 1)

        with open(self.log_file, "a") as f:
            f.write('{"event":"second"}\n')

        lines, new_offset = kinesis_shipper.tail_file(self.log_file, offset)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"event":"second"}')

    def test_tail_log_rotation(self):
        """Should reset offset when file shrinks."""
        import kinesis_shipper

        with open(self.log_file, "w") as f:
            f.write('{"event":"data"}\n' * 10)

        _, offset = kinesis_shipper.tail_file(self.log_file, 0)

        with open(self.log_file, "w") as f:
            f.write('{"event":"rotated"}\n')

        lines, _ = kinesis_shipper.tail_file(self.log_file, offset)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"event":"rotated"}')

    def test_tail_file_not_found(self):
        """Should return empty list and offset 0."""
        import kinesis_shipper

        lines, offset = kinesis_shipper.tail_file("/nonexistent", 0)
        self.assertEqual(lines, [])
        self.assertEqual(offset, 0)


class TestKinesisShipperEnrichRecord(unittest.TestCase):
    """Test enrich_record() function."""

    @patch.dict(os.environ, {
        "CLUSTER_NAME": "prod-cluster",
        "TARGET_NAMESPACE": "apigee",
        "APP_NAME": "gateway",
        "ENVIRONMENT": "production",
        "NODE_NAME": "node-1",
    })
    def test_enrich_adds_metadata(self):
        """Should add cluster/namespace/app metadata to JSON record."""
        import importlib
        import kinesis_shipper
        importlib.reload(kinesis_shipper)

        result = kinesis_shipper.enrich_record('{"pid":1234,"direction":"REQUEST"}')
        parsed = json.loads(result)

        self.assertEqual(parsed["pid"], 1234)
        self.assertEqual(parsed["cluster_name"], "prod-cluster")
        self.assertEqual(parsed["target_namespace"], "apigee")
        self.assertEqual(parsed["app_name"], "gateway")
        self.assertEqual(parsed["environment"], "production")
        self.assertEqual(parsed["node_name"], "node-1")

    def test_enrich_does_not_overwrite_existing(self):
        """Should not overwrite existing metadata fields."""
        import kinesis_shipper

        input_line = '{"cluster_name":"existing-cluster"}'
        result = kinesis_shipper.enrich_record(input_line)
        parsed = json.loads(result)

        self.assertEqual(parsed["cluster_name"], "existing-cluster")

    def test_enrich_invalid_json(self):
        """Should return line as-is for invalid JSON."""
        import kinesis_shipper

        result = kinesis_shipper.enrich_record("not json")
        self.assertEqual(result, "not json")


class TestKinesisShipperSendChunk(unittest.TestCase):
    """Test send_chunk() function."""

    def test_send_success(self):
        """Should send chunk successfully."""
        import kinesis_shipper
        kinesis_shipper.STREAM = "test-stream"

        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0, "RequestResponses": []}

        records = [{"Data": b'{"event":"test"}\n'}]
        result = kinesis_shipper.send_chunk(mock_firehose, records)

        self.assertTrue(result)
        mock_firehose.put_record_batch.assert_called_once()

    def test_send_retries_partial_failures(self):
        """Should retry only failed records on partial failure."""
        import kinesis_shipper
        kinesis_shipper.STREAM = "test-stream"

        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.side_effect = [
            {
                "FailedPutCount": 1,
                "RequestResponses": [
                    {},  # success
                    {"ErrorCode": "ServiceUnavailable"},  # failed
                ],
            },
            {"FailedPutCount": 0, "RequestResponses": [{}]},  # retry succeeds
        ]

        records = [{"Data": b"rec1\n"}, {"Data": b"rec2\n"}]
        result = kinesis_shipper.send_chunk(mock_firehose, records)

        self.assertTrue(result)
        self.assertEqual(mock_firehose.put_record_batch.call_count, 2)
        # Second call should only have the failed record
        second_call_records = mock_firehose.put_record_batch.call_args_list[1][1]["Records"]
        self.assertEqual(len(second_call_records), 1)

    def test_send_fails_after_max_retries(self):
        """Should return False after exhausting retries."""
        import kinesis_shipper
        from botocore.exceptions import ClientError
        kinesis_shipper.STREAM = "test-stream"
        kinesis_shipper.MAX_RETRIES = 2

        mock_firehose = MagicMock()
        error_response = {"Error": {"Code": "500", "Message": "Error"}}
        mock_firehose.put_record_batch.side_effect = ClientError(error_response, "PutRecordBatch")

        records = [{"Data": b"test\n"}]
        result = kinesis_shipper.send_chunk(mock_firehose, records)

        self.assertFalse(result)


class TestKinesisShipperFlushBatch(unittest.TestCase):
    """Test flush_batch() function."""

    def test_flush_empty_batch(self):
        """Should return True for empty batch."""
        import kinesis_shipper
        mock_firehose = MagicMock()
        result = kinesis_shipper.flush_batch(mock_firehose, [])
        self.assertTrue(result)
        mock_firehose.put_record_batch.assert_not_called()

    def test_flush_respects_batch_limit(self):
        """Should split large batches into 500-record chunks."""
        import kinesis_shipper
        kinesis_shipper.STREAM = "test-stream"
        kinesis_shipper.FIREHOSE_MAX_BATCH = 500

        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0, "RequestResponses": []}

        # 750 records should result in 2 API calls (500 + 250)
        batch = [f'{{"event":{i}}}' for i in range(750)]
        kinesis_shipper.flush_batch(mock_firehose, batch)

        self.assertEqual(mock_firehose.put_record_batch.call_count, 2)


class TestKinesisShipperMain(unittest.TestCase):
    """Test main() lifecycle."""

    def test_exits_without_stream(self):
        """Should exit with error if DELIVERY_STREAM not set."""
        import kinesis_shipper
        kinesis_shipper.STREAM = ""

        with self.assertRaises(SystemExit) as ctx:
            kinesis_shipper.main()
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
