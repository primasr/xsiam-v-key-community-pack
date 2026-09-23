import builtins
import os
import sys
from unittest.mock import MagicMock, patch
import pytest

# Ensure repository root and integration directory are on sys.path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(TEST_DIR, "../../../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

import CommonServerPython
for attr in dir(CommonServerPython):
    if not attr.startswith("__"):
        setattr(builtins, attr, getattr(CommonServerPython, attr))

from VKey import (
    VKeyClient,
    test_module as vkey_test_module,
    fetch_events,
    safe_send_events_to_xsiam,
    get_events_command,
    main as vkey_main,
    VENDOR,
    PRODUCT
)


def test_test_module_success():
    """Test test_module when API returns valid response."""
    client = VKeyClient(base_url="https://example.com/bsi", subscription_key="test-key")
    mock_response = {
        "data": [],
        "meta": {"rowCount": 0, "executionTimeMs": 10}
    }
    with patch.object(client, "query_table_page", return_value=mock_response):
        assert vkey_test_module(client) == "ok"


def test_fetch_events_smart_schedule():
    """Test fetch_events smart scheduling, deduplication, and state update."""
    client = VKeyClient(base_url="https://example.com/bsi", subscription_key="test-key")

    mock_threat_records = [
        {
            "table": "threat",
            "request_id": "req-1",
            "customer_id": 78032,
            "device_id": "dev-1",
            "received_at": "2026-09-23T10:00:00.000Z",
            "threat_info": "Rooted.ANDROID.SuperSU"
        }
    ]

    with patch.object(client, "fetch_all_table_records", return_value=mock_threat_records):
        next_run, events = fetch_events(client, last_run={}, first_fetch_window=15, max_fetch=100)

        assert len(events) > 0
        assert "threat:req-1" in next_run.get("seen_ids", [])
        assert events[0]["table"] == "threat"
        assert events[0]["threat_info"] == "Rooted.ANDROID.SuperSU"
        assert next_run["event_count"] == len(events)


def test_safe_send_events_to_xsiam():
    """Test safe_send_events_to_xsiam forwards events to Cortex XSIAM dataset."""
    events = [{"table": "threat", "request_id": "req-100"}]
    with patch("VKey.send_events_to_xsiam") as mock_send:
        safe_send_events_to_xsiam(events, VENDOR, PRODUCT)
        mock_send.assert_called_once_with(
            events=events,
            vendor=VENDOR,
            product=PRODUCT,
            data_format="json"
        )


def test_get_events_command():
    """Test manual !vkey-get-events command in preview and push mode."""
    client = VKeyClient(base_url="https://example.com/bsi", subscription_key="test-key")

    mock_data = [
        {
            "table": "threat",
            "request_id": "req-123",
            "device_id": "dev-456",
            "received_at": "2026-09-23T10:00:00.000Z",
            "threat_info": "Frida.Hooking"
        }
    ]

    with patch.object(client, "fetch_all_table_records", return_value=mock_data), \
         patch("VKey.send_events_to_xsiam") as mock_send:

        # 1. Preview mode (should_push_events=false)
        res_preview = get_events_command(client, {"limit": "5", "table": "threat", "should_push_events": "false"})
        assert res_preview.outputs_prefix == "VKey.Telemetry"
        assert "(preview only, not pushed)" in res_preview.readable_output
        mock_send.assert_not_called()

        # 2. Push mode (should_push_events=true)
        res_push = get_events_command(client, {"limit": "5", "table": "threat", "should_push_events": "true"})
        assert "(pushed to dataset vkey_vos_raw)" in res_push.readable_output
        mock_send.assert_called_once()


def test_main_test_module_string_key():
    """Test main() execution with string subscription_key."""
    params = {
        "url": "https://example.com/bsi",
        "subscription_key": "raw-string-key"
    }
    with patch.object(demisto, "params", return_value=params), \
         patch.object(demisto, "command", return_value="test-module"), \
         patch.object(demisto, "results") as mock_results, \
         patch("VKey.test_module", return_value="ok"):
        vkey_main()
        mock_results.assert_called_once_with("ok")


def test_main_test_module_dict_key():
    """Test main() execution with encrypted/dict subscription_key."""
    params = {
        "url": "https://example.com/bsi",
        "subscription_key": {"password": "nested-dict-key"}
    }
    with patch.object(demisto, "params", return_value=params), \
         patch.object(demisto, "command", return_value="test-module"), \
         patch.object(demisto, "results") as mock_results, \
         patch("VKey.test_module", return_value="ok"):
        vkey_main()
        mock_results.assert_called_once_with("ok")
