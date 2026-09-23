# V-Key V-OS Threat Intelligence Content Pack

The **V-Key V-OS Threat Intelligence** Content Pack enables seamless ingestion of mobile application security violations, device inventory profiles, and application package integrity telemetry from the **V-Key V-OS Cloud SIEM API Gateway** into **Cortex XSIAM**.

---

## Key Features

- **Runtime Threat Detection**: Ingests real-time mobile security events including Root/Jailbreak detection, Hooking frameworks (Frida, Xposed), Debugger attachments, App tampering, and malware indicators.
- **Device & Application Context**: Gathers device hardware metadata (OS version, device model, CPU architecture) and application binary telemetry (package bundle ID, app version, V-Guard SDK version).
- **Smart Ingestion Sub-Schedules**: Optimizes API polling by querying high-velocity threat alerts every 5 minutes and lower-velocity device/app inventory every 15 minutes.
- **Built-in Deduplication**: Uses `request_id` to eliminate duplicate events across overlapping query windows.
- **Interactive War Room Commands**: Enables SOC analysts to query recent telemetry directly using the `!vkey-get-events` command.

---

## What Does This Pack Include?

- **Integrations**:
  - **VKey**: Connects to the V-Key V-OS Cloud API gateway and fetches threat, device, application, and heartbeat telemetry.

---

## Author & Support
- **Author**: Prima Secondary Ramadhan
- **Support**: Community Support
- **Repository**: [https://github.com/primasr](https://github.com/primasr)
