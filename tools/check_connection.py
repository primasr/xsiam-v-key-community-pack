#!/usr/bin/env python3
"""
V-Key V-OS Telemetry Fetcher & Unified JSON Exporter
- Fetches all tables (threat, device, application, heartbeat)
- Preserves original schemas without modification
- Adds 1 identifier field: "table": "<table_name>"
- Paginates and deduplicates on request_id
- Saves everything into 1 consolidated JSON file for Cortex XSIAM
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from dotenv import load_dotenv

# Find .env in current or parent directory
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

load_dotenv(SCRIPT_DIR / ".env")
load_dotenv(REPO_ROOT / ".env")
load_dotenv(REPO_ROOT / ".env.dev")
load_dotenv(REPO_ROOT / ".env.prod")

BASE_URL = os.getenv("Base_URL")
SUBSCRIPTION_KEY = os.getenv("Subscription_Key")

VALID_TABLES = ["threat", "device", "application", "heartbeat"]
OUTPUT_DIR = SCRIPT_DIR / "vkey_data_output"


def query_api_page(table_name: str, time_window_minute: int, limit: int, offset: int = 0, max_retries: int = 3) -> dict:
    """Sends a single paginated query to the V-Key BSI endpoint."""
    headers = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": SUBSCRIPTION_KEY,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) VKey-Client/1.0",
        "Connection": "keep-alive"
    }

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

    data_bytes = json.dumps(payload).encode("utf-8")

    for attempt in range(1, max_retries + 1):
        try:
            req = Request(BASE_URL, data=data_bytes, headers=headers, method="POST")
            with urlopen(req, timeout=30) as resp:
                raw_response = resp.read().decode("utf-8")
                return json.loads(raw_response)

        except HTTPError as e:
            error_msg = e.read().decode("utf-8", errors="replace")
            print(f"    [!] HTTP Error ({table_name}) {e.code}: {error_msg}")
            return None
        except (URLError, Exception) as e:
            if attempt < max_retries:
                print(f"    [!] Connection glitch ({e}), retrying {attempt}/{max_retries}...")
                time.sleep(1.5)
            else:
                print(f"    [!] Failed after {max_retries} attempts: {e}")
                return None


def fetch_table_records(table_name: str, time_window_minute: int, page_size: int = 1000, max_total_records: int = 10000) -> tuple:
    """
    Fetches all records for a specific table with pagination and deduplication.
    Tags each record with 'table': table_name while keeping original fields intact.
    """
    print(f"[*] Fetching table: '{table_name}' (Window: {time_window_minute}m / ~{time_window_minute // 1440}d)...")

    table_records = []
    seen_request_ids = set()
    duplicate_count = 0
    offset = 0
    page_num = 1
    total_exec_time = 0

    while True:
        result = query_api_page(
            table_name=table_name,
            time_window_minute=time_window_minute,
            limit=page_size,
            offset=offset
        )

        if not result:
            break

        data = result.get("data", [])
        meta = result.get("meta", {})
        total_exec_time += meta.get("executionTimeMs", 0)

        if not data:
            break

        new_unique_in_page = 0
        for record in data:
            req_id = record.get("request_id")
            if req_id and req_id in seen_request_ids:
                duplicate_count += 1
                continue
            if req_id:
                seen_request_ids.add(req_id)

            # Preserve original record and add the 'table' tag
            tagged_record = {"table": table_name, **record}
            table_records.append(tagged_record)
            new_unique_in_page += 1

        print(f"    Page {page_num} (Offset {offset}): {len(data)} retrieved | {new_unique_in_page} new unique")

        # Stop if last page reached, no new records, or reached max limit
        if len(data) < page_size or new_unique_in_page == 0 or len(table_records) >= max_total_records:
            break

        offset += page_size
        page_num += 1

    print(f"    -> Table '{table_name}': {len(table_records)} unique records (Duplicates filtered: {duplicate_count})")
    return table_records, duplicate_count, total_exec_time


def main():
    parser = argparse.ArgumentParser(description="Fetch V-Key telemetry and export as a single combined JSON file.")
    parser.add_argument("-w", "--window", type=int, default=10080,
                        help="Lookback window in minutes (default: 10080 / 7 days)")
    parser.add_argument("-p", "--page-size", type=int, default=1000,
                        help="Records per page batch (default: 1000)")
    parser.add_argument("-m", "--max-records", type=int, default=10000,
                        help="Max records per table (default: 10000)")

    args = parser.parse_args()

    if not BASE_URL or not SUBSCRIPTION_KEY:
        print("[!] Error: 'Base_URL' and 'Subscription_Key' must be defined in your environment or .env")
        sys.exit(1)

    print("=" * 65)
    print(" V-Key Telemetry Unified Fetcher (Single JSON Output)")
    print("=" * 65)

    combined_data = []
    summary_by_table = {}
    total_duplicates = 0
    total_time_ms = 0

    for tbl in VALID_TABLES:
        records, dup_count, exec_time = fetch_table_records(
            table_name=tbl,
            time_window_minute=args.window,
            page_size=args.page_size,
            max_total_records=args.max_records
        )
        combined_data.extend(records)
        summary_by_table[tbl] = len(records)
        total_duplicates += dup_count
        total_time_ms += exec_time

    # Build the single consolidated output
    output_payload = {
        "data": combined_data,
        "meta": {
            "totalRecords": len(combined_data),
            "breakdown": summary_by_table,
            "totalDuplicatesFiltered": total_duplicates,
            "totalServerExecutionTimeMs": total_time_ms,
            "timeWindowMinute": args.window,
            "generatedAt": datetime.now(timezone.utc).isoformat()
        }
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"vkey_combined_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    print("\n" + "=" * 65)
    print(f"[✓] Single Consolidated Output Saved -> {output_file}")
    print(f"    • Total Combined Records: {len(combined_data)}")
    for tbl, count in summary_by_table.items():
        print(f"      - {tbl:<15}: {count} records")
    print(f"    • Duplicates Filtered: {total_duplicates}")
    print("=" * 65)


if __name__ == "__main__":
    main()
