import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple


class VKeyClient(BaseClient):
    """
    Client to interact with the V-Key V-OS BSI API Gateway.
    """

    def __init__(self, base_url: str, subscription_key: str, verify: bool = True, proxy: bool = False):
        headers = {
            'Content-Type': 'application/json',
            'Ocp-Apim-Subscription-Key': subscription_key,
            'User-Agent': 'VKey-Cortex-XSIAM-Pack/1.0'
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def query_table_page(self, table_name: str, limit: int = 1000, offset: int = 0, time_window_minute: int = 15) -> Dict[str, Any]:
        """
        Sends paginated JSON request to V-Key BSI endpoint.
        """
        payload = {
            "request": {
                "table": table_name,
                "limit": limit,
                "offset": offset,
                "time_window_minute": time_window_minute,
                "format": "JSON",
                "sort": {
                    "field": "received_at",
                    "direction": "DESC"
                }
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='',
            json_data=payload
        )

    def fetch_all_table_records(self, table_name: str, time_window_minute: int, page_size: int = 1000, max_records: int = 5000) -> List[Dict[str, Any]]:
        """
        Paginates through a table and tags records with 'table': table_name.
        """
        records: List[Dict[str, Any]] = []
        offset = 0
        seen_in_batch = set()

        while len(records) < max_records:
            response = self.query_table_page(
                table_name=table_name,
                limit=page_size,
                offset=offset,
                time_window_minute=time_window_minute
            )
            data = response.get('data', [])
            if not data:
                break

            new_unique = 0
            for item in data:
                req_id = item.get('request_id')
                if req_id and req_id in seen_in_batch:
                    continue
                if req_id:
                    seen_in_batch.add(req_id)
                records.append({"table": table_name, **item})
                new_unique += 1

            if len(data) < page_size or new_unique == 0:
                break

            offset += page_size

        return records


def test_module(client: VKeyClient) -> str:
    """
    Tests API connectivity for the 'Test' button in XSIAM UI.
    """
    try:
        response = client.query_table_page(table_name="threat", limit=1, time_window_minute=5)
        if isinstance(response, dict) and "data" in response:
            return 'ok'
        raise DemistoException(f'Unexpected response: {response}')
    except Exception as e:
        return f'Failed to connect to V-Key API: {str(e)}'


def fetch_incidents(
    client: VKeyClient,
    last_run: Dict[str, Any],
    first_fetch_window: int = 15,
    max_fetch: int = 1000
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Option 1: Smart Sub-Schedules inside Cortex XSIAM polling.
    - threat:      every run (5 min cadence, 6 min window)
    - device:      every 15 min (16 min window)
    - application: every 15 min (16 min window)
    - heartbeat:   every 30 min (31 min window)
    """
    now = time.time()
    next_run = dict(last_run) if last_run else {}

    last_device_time = next_run.get('last_device_time', 0)
    last_app_time = next_run.get('last_app_time', 0)
    last_heartbeat_time = next_run.get('last_heartbeat_time', 0)
    seen_ids = set(next_run.get('seen_ids', []))

    all_raw_records: List[Dict[str, Any]] = []

    # 1. Threat Table: ALWAYS polled every execution (Cadence: 5m, Window: 6m)
    threat_window = 6 if last_run else first_fetch_window
    threat_records = client.fetch_all_table_records(table_name="threat", time_window_minute=threat_window, max_records=max_fetch)
    all_raw_records.extend(threat_records)

    # 2. Device Table: Polled every 15 minutes (Cadence: 15m, Window: 16m)
    if not last_run or (now - last_device_time) >= (15 * 60):
        dev_window = 16 if last_run else first_fetch_window
        dev_records = client.fetch_all_table_records(table_name="device", time_window_minute=dev_window, max_records=max_fetch)
        all_raw_records.extend(dev_records)
        next_run['last_device_time'] = now

    # 3. Application Table: Polled every 15 minutes (Cadence: 15m, Window: 16m)
    if not last_run or (now - last_app_time) >= (15 * 60):
        app_window = 16 if last_run else first_fetch_window
        app_records = client.fetch_all_table_records(table_name="application", time_window_minute=app_window, max_records=max_fetch)
        all_raw_records.extend(app_records)
        next_run['last_app_time'] = now

    # 4. Heartbeat Table: Polled every 30 minutes (Cadence: 30m, Window: 31m)
    if not last_run or (now - last_heartbeat_time) >= (30 * 60):
        hb_window = 31 if last_run else first_fetch_window
        hb_records = client.fetch_all_table_records(table_name="heartbeat", time_window_minute=hb_window, max_records=max_fetch)
        all_raw_records.extend(hb_records)
        next_run['last_heartbeat_time'] = now

    incidents: List[Dict[str, Any]] = []
    new_seen_ids = []

    for record in all_raw_records:
        req_id = record.get('request_id')
        table_type = record.get('table', 'unknown')
        unique_key = f"{table_type}:{req_id}" if req_id else str(hash(json.dumps(record, sort_keys=True)))

        if unique_key in seen_ids:
            continue

        occurred_time = record.get('received_at') or record.get('ts') or datetime.now(timezone.utc).isoformat()

        if table_type == "threat":
            incident_name = f"V-Key Threat: {record.get('threat_info') or record.get('threat_name', 'Security Violation')}"
            severity = 3
        elif table_type == "device":
            incident_name = f"V-Key Device: {record.get('model', 'Unknown')} ({record.get('os', '')})"
            severity = 1
        elif table_type == "application":
            incident_name = f"V-Key App: {record.get('app_bundle_id', 'App Update')} v{record.get('app_ver', '')}"
            severity = 1
        else:
            incident_name = f"V-Key Heartbeat: {record.get('device_id', 'Device Ping')}"
            severity = 1

        incident = {
            'name': incident_name,
            'occurred': occurred_time,
            'rawJSON': json.dumps(record),
            'severity': severity,
            'dbotMirrorId': unique_key,
            'details': json.dumps(record, indent=2)
        }
        incidents.append(incident)
        new_seen_ids.append(unique_key)

    next_run['seen_ids'] = (list(seen_ids) + new_seen_ids)[-2000:]

    return next_run, incidents


def get_threats_command(client: VKeyClient, args: Dict[str, Any]) -> CommandResults:
    """
    Manual War Room command: !vkey-get-threats
    """
    limit = arg_to_number(args.get('limit')) or 20
    window = arg_to_number(args.get('time_window_minute')) or 60
    table = args.get('table', 'threat')

    records = client.fetch_all_table_records(table_name=table, time_window_minute=window, max_records=limit)

    readable_output = tableToMarkdown(
        name=f"V-Key Records ({table.upper()} - Last {window} min)",
        t=records,
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='VKey.Telemetry',
        outputs_key_field='request_id',
        outputs=records
    )


def main():
    params = demisto.params()
    command = demisto.command()

    base_url = params.get('url', '').strip()
    subscription_key = params.get('subscription_key', {}).get('password', '') or params.get('subscription_key', '')
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = VKeyClient(
            base_url=base_url,
            subscription_key=subscription_key,
            verify=verify_cert,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            first_fetch_window = arg_to_number(params.get('first_fetch_time')) or 15
            max_fetch = arg_to_number(params.get('max_fetch')) or 1000

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_window=first_fetch_window,
                max_fetch=max_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'vkey-get-threats':
            return_results(get_threats_command(client, demisto.args()))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command}: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
