# Cortex XSIAM Content Pack: V-Key V-OS Threat Intelligence

[![Demisto SDK Validated](https://img.shields.io/badge/Demisto%20SDK-Validated-brightgreen.svg)](#)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#)
[![Cortex XSIAM](https://img.shields.io/badge/Cortex-XSIAM-orange.svg)](#)

Community-developed **Cortex XSIAM Content Pack** for integrating **V-Key V-OS Mobile Application Protection & Threat Intelligence (BSI)**.

---

## 📦 What's Inside?

| Component | Path | Description |
| :--- | :--- | :--- |
| **Pack Metadata** | `Packs/VKey/pack_metadata.json` | Marketplace registration, author info, keywords, and tags. |
| **Integration Code** | `Packs/VKey/Integrations/VKey/VKey.py` | Full `BaseClient` implementation with smart sub-scheduling and pagination. |
| **Integration YAML** | `Packs/VKey/Integrations/VKey/VKey.yml` | Cortex XSIAM parameters & `!vkey-get-threats` command definition. |
| **Unit Tests** | `Packs/VKey/Integrations/VKey/VKey_test.py` | Pytest test suite covering client requests, parsing, and commands. |
| **Deployment Automation** | `deploy.sh` | Interactive CLI for validating, packaging, and deploying to XSIAM. |
| **Local Test CLI** | `check_connection.py` | Standalone tester to query V-Key BSI API and save combined JSON. |

---

## 🚀 Quick Start & Deployment

### 1. Prerequisites
Ensure you have `venv-demisto` created as described in [`install_demisto.md`](install_demisto.md).

### 2. Validate Pack
```bash
./deploy.sh validate
```

### 3. Run Unit Tests
```bash
./venv-demisto/bin/pytest Packs/VKey/Integrations/VKey/VKey_test.py
```

### 4. Build Standalone Zip Package
```bash
./deploy.sh zip
```
The compiled archive is generated at:
`Packs/uploadable_packs/VKey.zip`

### 5. Deploy directly to your Cortex XSIAM Tenant
```bash
# Configure your credentials in .env or .env.dev
./deploy.sh dev
```

---

## 🛡️ Telemetry Ingested

- **`threat`**: Jailbreak/Root, Frida/Xposed hooks, Debuggers, Tampering, Malware.
- **`device`**: Device Model, Manufacturer, OS Version, Architecture, DD Hash.
- **`application`**: App Bundle ID, Version, V-Guard SDK version, V-OS Processor version.
- **`heartbeat`**: Liveness pings & session continuity.

---

## 👨‍💻 Author & Support
- **Author**: Prima Secondary Ramadhan
- **GitHub**: [@primasr](https://github.com/primasr)
- **Support**: Community
