# V-Key V-OS Threat Intelligence Integration

Ingests mobile runtime security events, device inventory profiles, and application package integrity telemetry from **V-Key V-OS BSI** into **Cortex XSIAM**.

---

## Configuration Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `url` | String | True | V-Key BSI Endpoint URL (e.g., `https://stg-apim-public.azure-api.net/bsi`). |
| `subscription_key` | Encrypted / Password | True | Azure APIM Subscription Key (`Ocp-Apim-Subscription-Key`). |
| `isFetch` | Boolean | False | Enable continuous scheduled incident polling. |
| `first_fetch_time` | String / Number | False | Initial lookback window in minutes (Default: `15`). |
| `max_fetch` | String / Number | False | Maximum records retrieved per execution run (Default: `1000`). |
| `insecure` | Boolean | False | Trust any certificate (not secure). |
| `proxy` | Boolean | False | Use system proxy settings. |

---

## Commands

### `vkey-get-threats`
Manually query telemetry records from V-Key BSI.

#### Input Arguments
| Argument | Description | Default |
| :--- | :--- | :--- |
| `table` | Target dataset: `threat`, `device`, `application`, or `heartbeat`. | `threat` |
| `time_window_minute` | Query lookback duration in minutes. | `60` |
| `limit` | Maximum records to retrieve. | `20` |

#### Context Outputs
| Path | Type | Description |
| :--- | :--- | :--- |
| `VKey.Telemetry.table` | String | Source table name. |
| `VKey.Telemetry.request_id` | String | Unique telemetry transaction UUID. |
| `VKey.Telemetry.device_id` | String | Unique V-OS device identifier hash. |
| `VKey.Telemetry.received_at` | String | Ingestion timestamp. |
| `VKey.Telemetry.threat_info` | String | Attack or violation signature description. |
