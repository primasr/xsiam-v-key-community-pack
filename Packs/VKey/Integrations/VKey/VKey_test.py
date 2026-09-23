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
    fetch_incidents,
    get_threats_command
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


def test_fetch_incidents_smart_schedule():
    """Test fetch_incidents smart scheduling and deduplication."""
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
        next_run, incidents = fetch_incidents(client, last_run={}, first_fetch_window=15, max_fetch=100)

        assert len(incidents) > 0
        assert "threat:req-1" in next_run.get("seen_ids", [])
        assert "V-Key Threat" in incidents[0]["name"]
        assert incidents[0]["severity"] == 3


def test_get_threats_command():
    """Test manual !vkey-get-threats command."""
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

    with patch.object(client, "fetch_all_table_records", return_value=mock_data):
        results = get_threats_command(client, {"limit": "5", "table": "threat"})
        assert results.outputs_prefix == "VKey.Telemetry"
        assert len(results.outputs) == 1
        assert "Frida.Hooking" in results.readable_output
