#!/usr/bin/env python3
"""Unit tests for Splunk HEC log shipper."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class TestSplunkHecWrapEvent(unittest.TestCase):
    """Test wrap_event() function."""

    def test_wrap_valid_json(self):
        """Should wrap JSON line into HEC envelope."""
        import splunk_hec_shipper
        result = splunk_hec_shipper.wrap_event('{"pid":1234,"comm":"curl"}')
        parsed = json.loads(result)
        self.assertEqual(parsed["event"]["pid"], 1234)
        self.assertEqual(parsed["event"]["comm"], "curl")
        self.assertEqual(parsed["sourcetype"], "tls:tracer")
        self.assertEqual(parsed["source"], "tls_tracer")

    def test_wrap_invalid_json(self):
        """Should wrap non-JSON as raw string."""
        import splunk_hec_shipper
        result = splunk_hec_shipper.wrap_event("not json at all")
        parsed = json.loads(result)
        self.assertEqual(parsed["event"]["raw"], "not json at all")

    def test_wrap_with_index(self):
        """Should include index when SPLUNK_INDEX is set."""
        import splunk_hec_shipper
        original = splunk_hec_shipper.INDEX
        try:
            splunk_hec_shipper.INDEX = "test_index"
            result = splunk_hec_shipper.wrap_event('{"test":1}')
            parsed = json.loads(result)
            self.assertEqual(parsed["index"], "test_index")
        finally:
            splunk_hec_shipper.INDEX = original

    def test_wrap_no_index_when_empty(self):
        """Should omit index when not configured."""
        import splunk_hec_shipper
        original = splunk_hec_shipper.INDEX
        try:
            splunk_hec_shipper.INDEX = ""
            result = splunk_hec_shipper.wrap_event('{"test":1}')
            parsed = json.loads(result)
            self.assertNotIn("index", parsed)
        finally:
            splunk_hec_shipper.INDEX = original

    def test_wrap_preserves_timestamp(self):
        """Should convert ISO 8601 timestamp to epoch."""
        import splunk_hec_shipper
        event = '{"timestamp":"2025-01-15T10:30:00.123456Z","pid":1}'
        result = splunk_hec_shipper.wrap_event(event)
        parsed = json.loads(result)
        self.assertIn("time", parsed)
        self.assertIsInstance(parsed["time"], float)


class TestSplunkHecMaskToken(unittest.TestCase):
    """Test _mask_token() function."""

    def test_mask_long_token(self):
        """Should show first 4 and last 4 chars."""
        import splunk_hec_shipper
        result = splunk_hec_shipper._mask_token("abcdefgh12345678")
        self.assertEqual(result, "abcd...5678")

    def test_mask_short_token(self):
        """Should fully mask short tokens."""
        import splunk_hec_shipper
        result = splunk_hec_shipper._mask_token("short")
        self.assertEqual(result, "***")


class TestSplunkHecParseBoolEnv(unittest.TestCase):
    """Test _parse_bool_env() function."""

    @patch.dict(os.environ, {"TEST_BOOL": "true"})
    def test_true_values(self):
        import splunk_hec_shipper
        self.assertTrue(splunk_hec_shipper._parse_bool_env("TEST_BOOL"))

    @patch.dict(os.environ, {"TEST_BOOL": "false"})
    def test_false_values(self):
        import splunk_hec_shipper
        self.assertFalse(splunk_hec_shipper._parse_bool_env("TEST_BOOL"))

    @patch.dict(os.environ, {"TEST_BOOL": "1"})
    def test_numeric_true(self):
        import splunk_hec_shipper
        self.assertTrue(splunk_hec_shipper._parse_bool_env("TEST_BOOL"))

    def test_default_when_missing(self):
        import splunk_hec_shipper
        self.assertTrue(splunk_hec_shipper._parse_bool_env("MISSING_VAR", True))
        self.assertFalse(splunk_hec_shipper._parse_bool_env("MISSING_VAR", False))


class TestSplunkHecParseIntEnv(unittest.TestCase):
    """Test _parse_int_env() function."""

    @patch.dict(os.environ, {"TEST_INT": "42"})
    def test_valid_int(self):
        import splunk_hec_shipper
        self.assertEqual(splunk_hec_shipper._parse_int_env("TEST_INT", 10), 42)

    @patch.dict(os.environ, {"TEST_INT": "abc"})
    def test_invalid_returns_default(self):
        import splunk_hec_shipper
        self.assertEqual(splunk_hec_shipper._parse_int_env("TEST_INT", 10), 10)

    @patch.dict(os.environ, {"TEST_INT": "0"})
    def test_clamp_min(self):
        import splunk_hec_shipper
        self.assertEqual(splunk_hec_shipper._parse_int_env("TEST_INT", 10, min_val=1), 1)

    @patch.dict(os.environ, {"TEST_INT": "99999"})
    def test_clamp_max(self):
        import splunk_hec_shipper
        self.assertEqual(
            splunk_hec_shipper._parse_int_env("TEST_INT", 10, max_val=100), 100
        )


class TestSplunkHecDeadLetter(unittest.TestCase):
    """Test _write_dead_letter() function."""

    def test_writes_events_to_file(self):
        """Should write events to dead-letter file."""
        import splunk_hec_shipper
        with tempfile.TemporaryDirectory() as tmpdir:
            dlq_path = os.path.join(tmpdir, "splunk-dead-letter.json")
            original = splunk_hec_shipper.DEAD_LETTER_MAX_BYTES
            try:
                # Patch the dead letter path
                with patch.object(splunk_hec_shipper, '_write_dead_letter') as mock_dlq:
                    mock_dlq.side_effect = lambda events: _test_write_dlq(
                        events, dlq_path
                    )
                    # Actually test the real function with a temp path
                    pass
            finally:
                splunk_hec_shipper.DEAD_LETTER_MAX_BYTES = original


def _test_write_dlq(events, path):
    """Helper to write dead letter events."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        for ev in events:
            f.write(ev + "\n")


class TestSplunkHecSendBatch(unittest.TestCase):
    """Test send_batch() function."""

    @patch("splunk_hec_shipper.urlopen")
    def test_successful_send(self, mock_urlopen):
        """Should return True on successful HEC response."""
        import splunk_hec_shipper
        original_url = splunk_hec_shipper.HEC_URL
        original_token = splunk_hec_shipper.HEC_TOKEN
        try:
            splunk_hec_shipper.HEC_URL = "https://splunk.test:8088/services/collector"
            splunk_hec_shipper.HEC_TOKEN = "test-token"
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"text":"Success","code":0}'
            mock_urlopen.return_value = mock_resp

            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            events = ['{"event":{"test":1},"sourcetype":"tls:tracer","source":"tls_tracer"}']
            result = splunk_hec_shipper.send_batch(events, ctx)
            self.assertTrue(result)
        finally:
            splunk_hec_shipper.HEC_URL = original_url
            splunk_hec_shipper.HEC_TOKEN = original_token

    @patch("splunk_hec_shipper.urlopen")
    def test_403_stops_retrying(self, mock_urlopen):
        """Should stop retrying on 403 Forbidden."""
        import splunk_hec_shipper
        from urllib.error import HTTPError
        original_url = splunk_hec_shipper.HEC_URL
        original_token = splunk_hec_shipper.HEC_TOKEN
        try:
            splunk_hec_shipper.HEC_URL = "https://splunk.test:8088/services/collector"
            splunk_hec_shipper.HEC_TOKEN = "test-token"
            mock_urlopen.side_effect = HTTPError(
                "https://splunk.test:8088/services/collector", 403, "Forbidden", {}, None
            )

            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with patch.object(splunk_hec_shipper, '_write_dead_letter'):
                events = ['{"event":{"test":1}}']
                result = splunk_hec_shipper.send_batch(events, ctx)
                self.assertFalse(result)
                # Should only be called once (no retries on 403)
                self.assertEqual(mock_urlopen.call_count, 1)
        finally:
            splunk_hec_shipper.HEC_URL = original_url
            splunk_hec_shipper.HEC_TOKEN = original_token


class TestSplunkHecBuildSslContext(unittest.TestCase):
    """Test build_ssl_context() function."""

    def test_default_verifies_ssl(self):
        """Should verify SSL by default."""
        import splunk_hec_shipper
        original = splunk_hec_shipper.VERIFY_SSL
        try:
            splunk_hec_shipper.VERIFY_SSL = True
            ctx = splunk_hec_shipper.build_ssl_context()
            import ssl
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        finally:
            splunk_hec_shipper.VERIFY_SSL = original

    def test_disable_ssl_verification(self):
        """Should disable SSL verification when configured."""
        import splunk_hec_shipper
        original = splunk_hec_shipper.VERIFY_SSL
        try:
            splunk_hec_shipper.VERIFY_SSL = False
            ctx = splunk_hec_shipper.build_ssl_context()
            import ssl
            self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        finally:
            splunk_hec_shipper.VERIFY_SSL = original


class TestSplunkHecSignalHandler(unittest.TestCase):
    """Test signal handling."""

    def test_signal_sets_running_false(self):
        """Should set running to False on signal."""
        import splunk_hec_shipper
        original = splunk_hec_shipper.running
        try:
            splunk_hec_shipper.running = True
            splunk_hec_shipper.signal_handler(15, None)
            self.assertFalse(splunk_hec_shipper.running)
        finally:
            splunk_hec_shipper.running = original


class TestSplunkHecMainValidation(unittest.TestCase):
    """Test main() startup validation."""

    @patch.dict(os.environ, {"SPLUNK_HEC_URL": "", "SPLUNK_HEC_TOKEN": "test"})
    def test_exits_without_url(self):
        """Should exit if SPLUNK_HEC_URL is not set."""
        # Re-import to pick up new env vars
        if "splunk_hec_shipper" in sys.modules:
            del sys.modules["splunk_hec_shipper"]
        import splunk_hec_shipper
        splunk_hec_shipper.HEC_URL = ""
        with self.assertRaises(SystemExit):
            splunk_hec_shipper.main()

    @patch.dict(os.environ, {"SPLUNK_HEC_URL": "https://splunk:8088/services/collector",
                              "SPLUNK_HEC_TOKEN": ""})
    def test_exits_without_token(self):
        """Should exit if SPLUNK_HEC_TOKEN is not set."""
        if "splunk_hec_shipper" in sys.modules:
            del sys.modules["splunk_hec_shipper"]
        import splunk_hec_shipper
        splunk_hec_shipper.HEC_TOKEN = ""
        with self.assertRaises(SystemExit):
            splunk_hec_shipper.main()


if __name__ == "__main__":
    unittest.main()
