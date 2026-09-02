# Chassis Tamper Sensor Interlock

> **Domain:** Clinical Decision Support & Biomedical Computing  
> **Reference Guidelines & Standards:** `Standard Clinical Formulations & ISO/IEC Quality Frameworks`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

Chassis Tamper Sensor Interlock Application Entry Point

Chassis Intrusion Detection & Zeroization Interlock Engine
==========================================================
Implements FIPS 140-3 Level 3/4 Physical Security, NIST SP 800-88 Rev 1 Cryptographic
Zeroization, Active Anti-Tamper Enclosure Monitoring, and Hardware Interlock FSM.

Author: Dr. Abu Suraih Sakhri
License: MIT

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`InterlockState`** — dedicated module for interlock state evaluation and state verification.
- **`TamperSeverity`** — dedicated module for tamper severity evaluation and state verification.
- **`SensorTelemetry`** — dedicated module for sensor telemetry evaluation and state verification.
- **`BreachDetail`** — dedicated module for breach detail evaluation and state verification.
- **`ZeroizationProof`** — dedicated module for zeroization proof evaluation and state verification.
- **`InterlockEvaluationResult`** — dedicated module for interlock evaluation result evaluation and state verification.

---

## 📐 Mathematical Formulation & Logic

```text
  calculate_metrics,
  "calculate_metrics",
  res = calculate_metrics(**r)
```

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --- <value> --microswitch-open <value> --mesh-ohms <value> --light-lux <value>
```

### Parameter Reference
- `---`: Specifies input measurement or parameter value.
- `--microswitch-open`: Specifies input measurement or parameter value.
- `--mesh-ohms`: Specifies input measurement or parameter value.
- `--light-lux`: Specifies input measurement or parameter value.
- `--accel-g`: Specifies input measurement or parameter value.
- `--temp-c`: Specifies input measurement or parameter value.
- `--magnetic-gauss`: Specifies input measurement or parameter value.
- `--rail-v`: Specifies input measurement or parameter value.
- `--battery-v`: Specifies input measurement or parameter value.
- `--json`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `timestamp` | Parameter / observation metric | Required |
| `microswitch_open` | Parameter / observation metric | Required |
| `mesh_resistance_ohms` | Parameter / observation metric | Required |
| `internal_light_lux` | Parameter / observation metric | Required |
| `accelerometer_g` | Parameter / observation metric | Required |
| `temperature_c` | Parameter / observation metric | Required |
| `magnetic_field_gauss` | Parameter / observation metric | Required |
| `rail_voltage_v` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t chassis-tamper-sensor-interlock .
docker run -p 8000:8000 chassis-tamper-sensor-interlock
```
