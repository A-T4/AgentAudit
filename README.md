# AgentAudit Sentinel OS

**Zero-Trust Identity, Access Management (IAM), and DLP Proxy for Autonomous AI Agents**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Eval Score](https://img.shields.io/badge/eval-100%2F100-brightgreen.svg)](#evaluation)
[![DPDP](https://img.shields.io/badge/DPDP-aligned-orange.svg)](#regulatory-compliance-dpdp-act-2025)

AgentAudit is an infrastructure-level admission control and Data Loss Prevention (DLP) proxy engineered specifically for **Agentic AI**. It sits between an autonomous Large Language Model (LLM) and enterprise infrastructure, mathematically verifying that tool-calls executed via the Model Context Protocol (MCP) remain securely within their bounded autonomy.

Unlike legacy human-input DLP, AgentAudit is designed to withstand volumetric attacks, semantic prompt hijacking, and multi-layered cryptographic obfuscation from compromised AI agents.

---

## Core Architecture & Defense Layers

### Layer 0: Volumetric Guardrails (Anti-DoS)
* Enforces a strict 50KB payload ceiling on all incoming MCP tool arguments.
* Returns HTTP 413 on overflow, severing connections attempting bulk proprietary code dumps or algorithmic DoS attacks.

### Layer 1: Deep Payload Inspection & Cryptographic Decoupling
* **Recursive Decoding Engine:** Unwraps nested obfuscation (URL-encoding → Hexadecimal → Base64) natively in memory, up to 5 layers deep, to expose hidden exfiltration payloads.
* **Pre-Execution Scrubbing:** Surgically excises benign structural data (v4 UUIDs, AWS ARNs with path separators, K8s Cluster IDs, semver tags, public `ssh-rsa` keys) prior to entropy analysis to eliminate false positives on legitimate DevOps pipelines.
* **Sliding Window Entropy Scanner:** Calculates normalized Shannon Entropy ($H_{rel}$) across a 24-character moving window. Terminates payloads exceeding the **0.90** threshold when intent overlap is below the Jaccard floor.
* **Secret Pattern Library:** 12 high-confidence patterns covering AWS Access Keys, Stripe Live Keys, Bearer Tokens, PEM Private Keys, GitHub PAT/OAuth/Server tokens, Slack Bot Tokens, Slack Webhooks, and MongoDB/PostgreSQL/Redis connection strings.
* **Indian PII Detection:** Native regex enforcement for **Aadhaar** and **PAN** identifiers, scrubbed against benign UUID/ARN data to eliminate false matches.

### Layer 2: Semantic Intent Verification (Jaccard Drift)
* Calculates the Jaccard similarity coefficient between the user's natural language intent and the agent's executed API payload.
* Ten domain-specific heuristic maps (SQL, IAM, Kubernetes, GitHub Actions, Email/HTML, JSON APIs, Jira, Slack, transaction logs, feedback workflows) prevent false positives on legitimate enterprise traffic.
* Blocks **"Instruction Override"** prompt injections when tool payload deviates beyond the configured Jaccard floor (default **0.50**).
* Hard floor at **0.10** triggers `TOTAL_PILOT_DEVIATION` for catastrophic intent mismatch.

### Layer 3: Forensic Audit Trail (HMAC-Signed)
* Every interception decision (BLOCK or SAFE) is written to an append-only JSONL log.
* Each entry is signed with **HMAC-SHA256** using a server-side key, producing a tamper-evident chain.
* Payloads are SHA-256 hashed; raw arguments are **never** persisted to disk.
* `verify_log_entry()` provides per-entry integrity checking for compliance auditors.
* DPDP-ready: this is the artifact a Data Protection Officer hands to a regulator.

### Hardening
* Container runs as non-root **`sentinel`** system user.
* API key authentication on `/audit` endpoint (`X-API-Key` header).
* CORS middleware with configurable allowed origins.
* `/health` liveness probe for container orchestration.
* Manifest cached at startup — zero disk I/O on the request hot path.

---

## Regulatory Compliance: DPDP Act 2025

AgentAudit v10.4 is specifically architected to satisfy the **"Reasonable Security Safeguards"** mandated by **Rule 7** of the Digital Personal Data Protection (DPDP) Rules, 2025.

### Technical Enforcement of 'Reasonable Security':
* **Recursive De-obfuscation:** Flattens Base64/Hex/URL-smuggled payloads to prevent unauthorized exfiltration.
* **Deterministic Admission Control:** Uses normalized Shannon Entropy ($H_{rel} > 0.90$) and Jaccard Semantic Drift ($J < 0.50$) to sever connections before tool-call execution.
* **Indian PII Enforcement:** Aadhaar and PAN detection runs as a FATAL block ahead of entropy analysis.
* **Forensic Integrity (Rule 6):** HMAC-signed JSONL audit log for mandatory breach notification and regulatory audits.

---

## Quick Start (Dockerized Deployment)

AgentAudit deploys as an immutable container. Ensure Docker Desktop (Compose V2) is running on your host machine.

```bash
# 1. Clone the repository
git clone https://github.com/A-T4/AgentAudit.git
cd AgentAudit

# 2. Create the host-mounted log directory
mkdir -p logs

# 3. Build and deploy the Sentinel OS
docker compose up --build -d

# 4. Verify container health
docker ps                         # status should show (healthy)
curl http://localhost:8000/health
```

### Run the End-to-End Test Suite

```bash
python test_e2e.py
```

Expected output: `15/15 tests passed`.

### Run the Detection Evaluation Harness

```bash
python compare_engines.py --verbose
```

Expected output: `COMPOSITE: 100.0 / 100`.

---

## Configuration

AgentAudit reads three environment variables. All have safe defaults for local development; **all must be overridden in production.**

| Variable | Default | Description |
|---|---|---|
| `AGENTAUDIT_HMAC_KEY` | `dev-signing-key-change-in-production` | HMAC-SHA256 signing key for the forensic audit trail. Must be a long, random secret in production. If rotated, previously signed log entries will no longer verify. |
| `AGENTAUDIT_API_KEY` | *(unset)* | Required value for the `X-API-Key` header on all `/audit` requests. If unset or empty, authentication is **disabled** (dev mode). Set to a strong random string in production. |
| `AGENTAUDIT_CORS_ORIGINS` | `http://localhost:3000,http://localhost:8000` | Comma-separated list of allowed CORS origins. In production, restrict this to your client application domains only. |
| `AGENTAUDIT_LOG_PATH` | `audit_trail.jsonl` | File path for the append-only audit log. The Docker deployment overrides this to `/app/logs/audit_trail.jsonl` and mounts the directory as a host volume. |
| `AGENTAUDIT_RATE_LIMIT` | `60` | Maximum requests per window per `session_id`. Set to `0` to disable rate limiting entirely. |
| `AGENTAUDIT_RATE_WINDOW_SECONDS` | `60` | Sliding window size in seconds for the rate limiter. |

### Production Configuration Example

Create a `.env` file in the repository root (do **not** commit this file):

```bash
AGENTAUDIT_HMAC_KEY=$(openssl rand -hex 32)
AGENTAUDIT_API_KEY=$(openssl rand -hex 24)
AGENTAUDIT_CORS_ORIGINS=https://your-client.example.com
```

`docker-compose.yml` will pick these up automatically.

---

## API Reference

### `GET /health`
Liveness probe. Returns container status, version, and uptime in seconds. No authentication required.

### `POST /audit`
Submits a tool-call for inspection. Requires the `X-API-Key` header in production.

**Request body:**
```json
{
  "session_id": "string",
  "user_intent": "string (natural language)",
  "tool_name": "string",
  "tool_arguments": "string (JSON or raw)",
  "target_domain": "string (optional)"
}
```

**Response (SAFE):**
```json
{
  "status": "SAFE",
  "session_id": "...",
  "scores": {
    "entropy": 0.7234,
    "jaccard": 0.8000,
    "pii": [],
    "secret_match": false
  },
  "decode_layers": []
}
```

**Response (BLOCKED):**
```json
{
  "status": "BLOCKED",
  "session_id": "...",
  "violations": ["PII_DETECTED:PAN"],
  "scores": { "...": "..." },
  "decode_layers": []
}
```

**Possible HTTP status codes:**
- `200` — Inspection complete (verdict in body)
- `401` — Missing or invalid API key
- `403` — Tool or target domain rejected by admission control
- `413` — Payload exceeds 50KB volumetric ceiling
- `429` — Per-session rate limit exceeded (includes `Retry-After` header)

---

## Evaluation

The detection engine is benchmarked against a 32-case eval harness (14 benign, 18 attack):

| Metric | Value |
|---|---|
| Composite Score | **100.0 / 100** |
| Benign Pass Rate | 14/14 (100%) |
| Attack Detection Rate | 18/18 (100%) |
| False Positives | 0 |
| False Negatives | 0 |

Run `python compare_engines.py --verbose` to reproduce.

---

## Repository

**GitHub:** [https://github.com/A-T4/AgentAudit](https://github.com/A-T4/AgentAudit)