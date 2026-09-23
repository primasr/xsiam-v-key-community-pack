# V-Key V-OS Threat Intelligence Integration

Ingests mobile runtime security events, device inventory profiles, and application package integrity telemetry from **V-Key V-OS Cloud SIEM API** into **Cortex XSIAM**.

---

## Configuration Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `url` | String | True | V-Key Cloud SIEM Endpoint URL (e.g., `https://{tenant-apim-host}/{tenant}/`). |
| `subscription_key` | Encrypted / Password | True | Azure APIM Subscription Key (`Ocp-Apim-Subscription-Key`). |
| `isFetchEvents` | Boolean | False | Enable continuous scheduled telemetry polling into dataset. |
| `eventFetchInterval` | Number | False | Polling interval in minutes (Default: `5`). |
| `first_fetch_time` | String / Number | False | Initial lookback window in minutes (Default: `15`). |
| `max_fetch` | String / Number | False | Maximum records retrieved per execution run (Default: `1000`). |
| `insecure` | Boolean | False | Trust any certificate (insecure). |
| `proxy` | Boolean | False | Use system proxy settings. |

---

## Commands

### `vkey-get-events`
Manually query telemetry records from V-Key Cloud SIEM API and optionally push to dataset.

#### Input Arguments
| Argument | Description | Default |
| :--- | :--- | :--- |
| `table` | Target dataset: `threat`, `device`, `application`, or `heartbeat`. | `threat` |
| `time_window_minute` | Query lookback duration in minutes. | `60` |
| `limit` | Maximum records to retrieve. | `20` |
| `should_push_events` | Push events to dataset `vkey_vos_raw` (`true`/`false`). | `false` |

#### Context Outputs
| Path | Type | Description |
| :--- | :--- | :--- |
| `VKey.Telemetry.table` | String | Source table name. |
| `VKey.Telemetry.request_id` | String | Unique telemetry transaction UUID. |
| `VKey.Telemetry.device_id` | String | Unique V-OS device identifier hash. |
| `VKey.Telemetry.received_at` | String | Ingestion timestamp. |
| `VKey.Telemetry.threat_info` | String | Attack or violation signature description. |
