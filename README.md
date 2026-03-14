# AgentAudit Sentinel (v5.0)
**Infrastructure-Level Admission Control & DLP for Agentic AI**

---

## Overview

AgentAudit is a high-performance security proxy designed to intercept and audit Model Context Protocol (MCP) and agentic tool-calls. It functions as an Admission Controller, preventing unauthorized data egress (exfiltration) by validating manifests and inspecting LLM reasoning cycles in real-time. Purpose-built for 2026 threat landscapes and India's DPDP Act compliance.

---

## Key Features

* **Recursive Decoding Pipeline:** Normalizes Base64, Hex, and URL-encoded payloads to bypass obfuscation attempts.
* **$H_{rel}$ Entropy Engine:** Mathematically identifies cryptographic secrets (API keys, tokens) using Normalized Shannon Entropy:
H_{rel} = frac{H}{\log_2 N}
* **Regional PII Scanners:** Parallelized Regex optimized for Indian identifiers (Aadhaar, PAN).
* **MCP Admission Control:** Static and dynamic manifest validation to prevent "Capability Creep."
* **Session-Locked Sentinels:** Conditional logic that revokes outbound permissions during sensitive reasoning blocks.

---

## Performance Metrics

| Metric | Specification |
| :--- | :--- |
| **Latency** | < 15ms overhead (Asynchronous FastAPI/Redis) |
| **Observability** | Native Prometheus telemetry (`/metrics`) |
| **Concurrency** | Stress-tested for 100+ simultaneous tool-calls |

---

## Quick Start

**Production Environment (Linux / macOS)**
```bash
git clone [https://github.com/A-T4/AgentAudit](https://github.com/A-T4/AgentAudit)
cd AgentAudit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

**Local Development (Windows PowerShell)**
```powershell
git clone [https://github.com/A-T4/AgentAudit](https://github.com/A-T4/AgentAudit)
cd AgentAudit
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
python main.py
```