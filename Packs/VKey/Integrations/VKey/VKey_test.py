import pytest
import json
from VKey import VKeyClient, test_module, fetch_incidents, get_threats_command


def test_test_module(requests_mock):
    """
    Tests test_module command when API returns valid response.
    """
    base_url = "https://example.com/bsi"
    client = VKeyClient(base_url=base_url, subscription_key="dummy-key")

    mock_response = {
        "data": [],
        "meta": {"rowCount": 0, "executionTimeMs": 10}
    }
    requests_mock.post(base_url, json=mock_response)

    assert test_module(client) == "ok"


def test_fetch_incidents_smart_schedule(requests_mock):
    """
    Tests fetch_incidents smart scheduling and deduplication.
    """
    base_url = "https://example.com/bsi"
    client = VKeyClient(base_url=base_url, subscription_key="dummy-key")

    mock_threat = {
        "data": [
            {
                "request_id": "req-1",
                "customer_id": 78032,
                "device_id": "dev-1",
                "received_at": "2026-09-23T10:00:00.000Z",
                "threat_info": "Rooted.ANDROID.SuperSU"
            }
        ]
    }
    requests_mock.post(base_url, json=mock_threat)

    next_run, incidents = fetch_incidents(client, last_run={}, first_fetch_window=15, max_fetch=100)

    assert len(incidents) > 0
    assert "threat:req-1" in next_run.get("seen_ids", [])
    assert incidents[0]["name"].startswith("V-Key Threat")


def test_get_threats_command(requests_mock):
    """
    Tests manual !vkey-get-threats command.
    """
    base_url = "https://example.com/bsi"
    client = VKeyClient(base_url=base_url, subscription_key="dummy-key")

    mock_data = {
        "data": [
            {
                "request_id": "req-123",
                "device_id": "dev-456",
                "received_at": "2026-09-23T10:00:00.000Z",
                "threat_info": "Frida.Hooking"
            }
        ]
    }
    requests_mock.post(base_url, json=mock_data)

    results = get_threats_command(client, {"limit": "5", "table": "threat"})
    assert results.outputs_prefix == "VKey.Telemetry"
    assert len(results.outputs) == 1
