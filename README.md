# AgentAudit Sentinel OS
**Zero-Trust Identity, Access Management (IAM), and DLP Proxy for Autonomous AI Agents**

AgentAudit is an infrastructure-level admission control and Data Loss Prevention (DLP) proxy engineered specifically for **Agentic AI**. It sits between an autonomous Large Language Model (LLM) and enterprise infrastructure, mathematically verifying that tool-calls executed via the Model Context Protocol (MCP) remain securely within their bounded autonomy.

Unlike legacy human-input DLP, AgentAudit is designed to withstand volumetric attacks, semantic prompt hijacking, and multi-layered cryptographic obfuscation from compromised AI agents.

## Core Architecture & Defense Layers

### Layer 0: Volumetric Guardrails (Anti-DoS)
* Enforces a strict 50KB payload ceiling on all incoming MCP tool arguments.
* Instantly severs connections attempting bulk proprietary code dumps or algorithmic DoS attacks, protecting the core CPU threading.

### Layer 1: Deep Payload Inspection & Cryptographic Decoupling
* **Recursive Decoding Engine:** Unwraps nested obfuscation (URL-encoding $\rightarrow$ Hexadecimal $\rightarrow$ Base64) natively in memory to expose hidden exfiltration payloads.
* **Pre-Execution Scrubbing:** Surgically excises benign structural data (e.g., standard v4 UUIDs, AWS ARNs, K8s Cluster IDs, public `ssh-rsa` keys) prior to entropy analysis to eliminate False Positives on legitimate DevOps pipelines.
* **Sliding Window Entropy Scanner:** Calculates Shannon Entropy ($H_{rel}$) across a 24-character moving window. Instantly terminates payloads exceeding the $0.85$ threshold, blocking zero-day credential leaks and proprietary keys.

### Layer 2: Semantic Intent Verification (Jaccard Drift)
* Calculates the Jaccard similarity coefficient between the user's initial natural language intent and the agent's executed API payload.
* Automatically detects and blocks **"Instruction Override"** prompt injections when the tool payload deviates $>90\%$ from the authorized context.

### Layer 3: Immutable Deployment
* Fully containerized Python 3.11/FastAPI core operating inside a sterile Docker environment.
* Configured with automated `curl` health checks and strict port binding for High-Availability (HA) enterprise clusters.

## ⚖️ Regulatory Compliance: DPDP Act 2025

AgentAudit v9.8 is specifically architected to satisfy the **"Reasonable Security Safeguards"** mandated by **Rule 7** of the Digital Personal Data Protection (DPDP) Rules, 2025.

### Technical Enforcement of 'Reasonable Security':
* **Recursive De-obfuscation:** Flattens Base64/Hex/URL-smuggled payloads to prevent unauthorized exfiltration.
* **Deterministic Admission Control:** Uses Normalized Shannon Entropy ($H_{rel} \geq 0.85$) and Jaccard Semantic Drift ($J \leq 0.20$) to sever connections before tool-call execution.
* **Forensic Integrity (Rule 6):** Generates immutable JSON audit logs for mandatory breach notification and regulatory audits.

**Live Forensic Trace (Case ID: 6a8a2678):** [View Sentinel Interception Log](https://gist.github.com/A-T4/6a8a2678e7114e1f21482719193dd568)

## Quick Start (Dockerized Production Deployment)

AgentAudit is deployed as an immutable container. Ensure Docker Desktop (Compose V2) is running on your host machine.

```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/AgentAudit.git](https://github.com/yourusername/AgentAudit.git)
cd AgentAudit

# 2. Build and deploy the Sentinel OS
docker compose up --build -d

# 3. Verify container health and port binding (0.0.0.0:8000)
docker ps