# V-OS Threat Intelligence — SIEM API Guide

## Comprehensive Implementation Summary

- **Source version:** 4.11.0
- **Last updated in source:** 31 July 2026
- **Purpose:** Integrate raw V-OS Cloud threat-intelligence events with a customer SIEM, with ELK/Elastic Logstash as the reference implementation.

---

## Executive Summary

The V-OS SIEM API is a tenant-specific APIM-backed REST service that returns raw threat-intelligence data in JSON (recommended) or CEF. A reference flow is: **SIEM API → Logstash HTTP Poller → Elasticsearch → Kibana**. Logstash polls the API, parses/transforms results, deduplicates records, and indexes them for search, dashboards, alerting, and analysis.

The two implementation rules that prevent most data-quality issues are:
- **Poll on `received_at`** — the server ingestion timestamp — and never on `ts`, which is only the original event timestamp. Using `ts` can miss late-arriving events.
- **Use overlapping query windows** to avoid gaps from clock skew or delayed runs, then deduplicate every event. In JSON mode, use `request_id` as the Elasticsearch document ID.

---

## Supported Modes

### JSON Mode (Recommended)
Use JSON for field-level searches, analytics, aggregations, dashboards, alerting, schema-aware processing, and simple deduplication. Events expose structured fields, and `request_id` can be used directly as the Elasticsearch `document_id`.

### CEF Mode
Use CEF for established CEF/Syslog environments or existing parser-rule ecosystems. The API returns raw CEF strings, which need additional parsing. Extract `request_id` from the CEF extension for deduplication, or generate a fingerprint-based ID. Store the raw string by renaming `data` to `message` in Logstash.

---

## Architecture and Roles

### Components
- **SIEM API (APIM):** Tenant endpoint; runs SQL-like queries; returns JSON or CEF; enforces authentication, rate limits, and retention.
- **Logstash:** Polls the API, parses and transforms records, deduplicates, and sends events to Elasticsearch.
- **Elasticsearch:** Stores, indexes, searches, and deduplicates records through document IDs.
- **Kibana:** Provides visualizations, monitoring, dashboards, and analysis.

### Responsibilities

#### Customer
- Deploy and operate Logstash.
- Secure `SIEM_API_KEY`, `SIEM_URL`, `ES_USER`, and `ES_PASSWORD`.
- Configure polling schedules, retry behavior, and index lifecycles.
- Monitor ingestion health, validate data quality, and implement pagination for high-volume responses.

#### V-Key
- Provide the tenant endpoint and subscription key.
- Provide schema guidance, rate-limit details, retention information, and sample Logstash configurations.

#### Shared
- Verify network reachability and TLS trust.
- Coordinate key rotation.
- Investigate ingestion gaps and incidents together.

---

## Prerequisites

- Logstash 7.x or 8.x is recommended; the guide references an Elastic Logstash 9.4.2 image.
- A tenant-specific APIM subscription key.
- HTTPS POST access to the API over outbound TCP 443.
- A reachable Elasticsearch cluster, credentials, and TLS connectivity.

---

## API Interface

### Endpoint
```http
POST https://{apim-host}/{tenant}/
```

### Required Headers
```http
Ocp-Apim-Subscription-Key: <your-key>
Content-Type: application/json
```

### JSON Request Model
```json
{
  "request": {
    "table": "threat",
    "limit": 10000,
    "sort": {
      "field": "received_at",
      "direction": "DESC"
    },
    "time_window_minute": 15,
    "format": "JSON"
  }
}
```

- **Key parameters:** `table` (data source), `limit` (maximum records), `sort.field`, `sort.direction` (`ASC`/`DESC`), `time_window_minute` (query duration), and `format` (`JSON` or `CEF`).
- **Typical JSON event fields:** `ts`, `received_at`, `request_id`, `customer_id`, `device_id`, `threat_type_id`, `threat_name`, `threat_info`, `threat_additional_info`, and `threat_active`.
- **Response metadata:** `rowCount` and `executionTimeMs`.

---

## Time Semantics and Polling

### Fields
- `received_at`: Server ingestion time. This is the required polling cursor.
- `ts`: Original event time. Use it only for event correlation.

### Overlap Rule
Poll windows must intentionally overlap to prevent blind spots from clock skew, delayed execution, or transient scheduling issues. This creates duplicates, so deduplication is mandatory.

| Poll Interval | Recommended API Window |
| :--- | :--- |
| Every 5 minutes | 5–6 minutes |
| Every 15 minutes | 15–16 minutes |
| Every 30 minutes | 30–31 minutes |

### Recommended Cadence by Dataset

| Table | Cadence |
| :--- | :--- |
| `siem.threat` | Every 5 minutes |
| `siem.device` | Every 15 minutes |
| `siem.application` | Every 15 minutes |
| `siem.heartbeat` | Every 30 minutes |

---

## Logstash Reference Configuration

### JSON Pipeline Requirements
- HTTP polling with a cron schedule, for example: `schedule => { cron => "*/15 * * * *" }`.
- Set `request_timeout => 60`.
- Use `codec => "json"`.
- Split/process returned events and extract fields.
- Index JSON events as `siem-threat-json-%{+YYYY.MM.dd}`.
- Set `document_id => "%{request_id}"` in the Elasticsearch output. This is the preferred, native deduplication method.

### CEF Pipeline Requirements
- Use the same request structure as JSON but set `"format": "CEF"`.
- CEF entries start with a form such as `CEF:0|V-Key|Threat-Intelligence|4.11|...`.
- CEF includes `ts`, `received_at`, `request_id`, `customer_id`, `device_id`, `threat_type_id`, `threat_name`, `threat_info`, and `threat_active`.
- Index CEF events as `siem-threat-cef-%{+YYYY.MM.dd}`.
- Rename `data` to `message` to preserve the raw CEF entry.
- Deduplicate by parsing `request_id` and using it as `document_id`, or use a stable fingerprint-based ID.

---

## Pagination, Scale, and Reliability

### Pagination
When a response reaches its limit, page through it. For example:  
`LIMIT 10000 OFFSET 0`, then `LIMIT 10000 OFFSET 10000`.  
Continue until the returned row count is lower than `LIMIT`; that indicates the final page.

### Limits and Retention
- **API rate limit:** 100 requests per minute per tenant.
- **Retention:** 90 days for Threat, Device, Application, and Heartbeat data.

### Reliability Controls
- Enable `automatic_retries` and tune timeouts.
- Alert when no events arrive for two times the polling interval.
- Persist poll state when using fixed-window polling.
- On HTTP 429, reduce request pressure by increasing the interval and applying backoff.

---

## Deployment Structure and Procedure

### Reference Assets
- JSON pipelines: `siem-integration/Logstash/ELK/json/container/config/pipelines/`
- CEF pipelines: `siem-integration/Logstash/ELK/cef/container/config/pipelines/`
- Multi-pipeline loader: `config/pipelines.yml`
- Container startup: `docker-compose.yml`

**Recommended Docker layout:**
```text
docker-compose.yml
config/
├── pipelines.yml
└── pipelines/
    ├── datatype_threat.conf
    ├── datatype_device.conf
    ├── datatype_application.conf
    └── datatype_heartbeat.conf
```
*Use one independent Logstash pipeline per data source to simplify tuning and troubleshooting.*

### Deployment Steps
1. Copy Docker assets and configuration files.
2. Create a `.env` file.
3. Set `SIEM_URL`, `SIEM_API_KEY`, `ES_URL`, `ES_USER`, and `ES_PASSWORD`.
4. Verify pipeline references and data-source configuration.
5. Start the deployment with `docker compose up -d`.
6. Monitor startup with `docker compose logs -f logstash`.
7. Confirm documents arrive in Elasticsearch and validate deduplication.

---

## Security Requirements

- Secrets are customer-managed.
- Never commit `.env` to source control.
- If credentials are exposed, immediately rotate API keys, Elasticsearch credentials, and any other exposed secrets.
- Validate TLS trust and outbound network access before production operation.

---

## Onboarding Checklist

1. Obtain the tenant endpoint and API key.
2. Choose JSON or CEF; choose JSON unless CEF compatibility is required.
3. Configure the Logstash pipelines and environment variables.
4. Validate connectivity and TLS.
5. Verify initial ingestion and Elasticsearch indexing.
6. Confirm overlap-window deduplication.
7. Enable monitoring and alerting.
8. Document recovery procedures and an operational runbook.

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
| :--- | :--- | :--- |
| Empty ingestion | Invalid API key or tenant path | Verify APIM URL and subscription key. |
| Recent events missing | Query is using `ts` | Change the polling cursor to `received_at`. |
| Duplicate records | Deduplication is absent | Use `request_id` as the Elasticsearch `document_id`; for CEF, parse it or use a fingerprint. |
| HTTP 429 errors | Request rate is too high | Increase poll interval and implement backoff. |
| CEF parser failures | Unescaped CEF separators | Sanitize or escape CEF extension values. |

---

## Critical Implementation Checklist

- Use JSON by default.
- Poll on `received_at`, never `ts`.
- Overlap time windows and deduplicate every record.
- Prefer `request_id` as the Elasticsearch document ID.
- Keep requests below 100 per minute per tenant.
- Plan for 90-day source-data retention.
- Keep `.env` out of source control and rotate compromised credentials immediately.
- Separate data types into independent pipelines.