"""
AgentAudit End-to-End Integration Test
=======================================
Runs against a live Dockerized container. Tests:
  1. /health endpoint responds
  2. /audit accepts a SAFE payload and logs it
  3. /audit BLOCKS an attack payload and logs it
  4. Audit trail JSONL file contains valid HMAC-signed entries
  5. Tamper detection works
 
Usage:
  # Start container first:
  docker compose up --build -d
 
  # Wait 10 seconds for startup, then:
  python test_e2e.py
"""
 
import json
import os
import sys
import time
import urllib.request
import urllib.error
 
BASE_URL = "http://localhost:8000"
AUDIT_LOG_PATH = "./logs/audit_trail.jsonl"
 
 
def http_get(path):
    try:
        with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))
    except Exception as e:
        return 0, {"error": str(e)}
 
 
def http_post(path, body):
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))
    except Exception as e:
        return 0, {"error": str(e)}
 
 
def test(name, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}")
    if detail:
        print(f"         {detail}")
    return condition
 
 
def main():
    print("=" * 70)
    print("  AgentAudit End-to-End Integration Test")
    print("=" * 70)
    print()
 
    results = []
 
    # --- TEST 1: /health endpoint ---
    print("[1/5] Health Check")
    status, body = http_get("/health")
    results.append(test(
        "GET /health returns 200",
        status == 200,
        f"status={status}, body={body}"
    ))
    results.append(test(
        "Health response contains version",
        isinstance(body, dict) and "version" in body,
        f"version={body.get('version') if isinstance(body, dict) else 'N/A'}"
    ))
    print()
 
    # --- TEST 2: SAFE payload is accepted ---
    print("[2/5] SAFE Payload Handling")
    safe_payload = {
        "session_id": "e2e-test-safe-001",
        "user_intent": "Get meeting notes from yesterday's standup",
        "tool_name": "mcp_calendar_read",
        "tool_arguments": '{"meeting_id": "standup-2026-04-07", "attendees": ["alice", "bob"], "discussion": "sprint review"}',

    }
    status, body = http_post("/audit", safe_payload)
    results.append(test(
        "POST /audit with benign payload returns 200",
        status == 200,
        f"status={status}"
    ))
    results.append(test(
        "Benign payload verdict is SAFE",
        isinstance(body, dict) and body.get("status") == "SAFE",
        f"verdict={body.get('status') if isinstance(body, dict) else 'N/A'}"
    ))
    print()
 
    # --- TEST 3: Attack payload is BLOCKED ---
    print("[3/5] Attack Payload Handling")
    attack_payload = {
        "session_id": "e2e-test-attack-001",
        "user_intent": "Update the tax filing record",
        "tool_name": "mcp_database_write",
        "tool_arguments": '{"taxpayer": "ABCDE1234F", "year": "2025-26", "status": "filed"}',

    }
    status, body = http_post("/audit", attack_payload)
    results.append(test(
        "POST /audit with PAN payload returns 200",
        status == 200,
        f"status={status}"
    ))
    results.append(test(
        "PAN payload verdict is BLOCKED",
        isinstance(body, dict) and body.get("status") == "BLOCKED",
        f"verdict={body.get('status') if isinstance(body, dict) else 'N/A'}"
    ))
    results.append(test(
        "Violations include PII_DETECTED:PAN",
        isinstance(body, dict) and any("PAN" in v for v in body.get("violations", [])),
        f"violations={body.get('violations') if isinstance(body, dict) else 'N/A'}"
    ))
    print()
 
    # --- TEST 4: Audit trail file exists and has entries ---
    print("[4/5] Audit Trail Persistence")
    # Give the container a moment to flush to disk
    time.sleep(0.5)
    results.append(test(
        f"Audit log file exists at {AUDIT_LOG_PATH}",
        os.path.exists(AUDIT_LOG_PATH),
        f"path={os.path.abspath(AUDIT_LOG_PATH)}"
    ))
 
    entries = []
    if os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
 
    results.append(test(
        "Audit log has at least 2 entries",
        len(entries) >= 2,
        f"found {len(entries)} entries"
    ))
 
    safe_entry = next((e for e in entries if e.get("session_id") == "e2e-test-safe-001"), None)
    attack_entry = next((e for e in entries if e.get("session_id") == "e2e-test-attack-001"), None)
    results.append(test(
        "SAFE request recorded in audit trail",
        safe_entry is not None and safe_entry.get("verdict") == "SAFE",
        f"found: {safe_entry is not None}"
    ))
    results.append(test(
        "BLOCKED request recorded in audit trail",
        attack_entry is not None and attack_entry.get("verdict") == "BLOCKED",
        f"found: {attack_entry is not None}"
    ))
    results.append(test(
        "Audit entries contain HMAC signature",
        all("hmac_sha256" in e for e in entries),
        f"all {len(entries)} entries signed"
    ))
    results.append(test(
        "Audit entries contain payload hash (not raw payload)",
        all("payload_hash" in e for e in entries),
    ))
    print()
 
    # --- TEST 5: HMAC verification ---
    print("[5/5] HMAC Signature Verification")
    # Import the verification function from the audit module
    try:
        sys.path.insert(0, '.')
        from audit import verify_log_entry
 
        if entries:
            # Verify a clean entry
            with open(AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
 
            results.append(test(
                "Clean log entry signature verifies",
                verify_log_entry(first_line),
            ))
 
            # Tamper with the entry and verify it fails
            tampered = first_line.replace('"SAFE"', '"TAMPERED"').replace('"BLOCKED"', '"TAMPERED"')
            if tampered != first_line:
                results.append(test(
                    "Tampered log entry signature REJECTED",
                    not verify_log_entry(tampered),
                ))
            else:
                print("  [SKIP] Tamper test (couldn't modify entry)")
    except ImportError as e:
        print(f"  [SKIP] Could not import audit.verify_log_entry: {e}")
    print()
 
    # --- SUMMARY ---
    passed = sum(1 for r in results if r)
    total = len(results)
    print("=" * 70)
    print(f"  RESULTS: {passed}/{total} tests passed")
    print("=" * 70)
 
    if passed == total:
        print("\n  All tests passed. Audit trail is working end-to-end.\n")
        return 0
    else:
        print(f"\n  {total - passed} tests FAILED. Review output above.\n")
        return 1
 
 
if __name__ == "__main__":
    sys.exit(main())
