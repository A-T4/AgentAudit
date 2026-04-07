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
    print("[1/6] Health Check")
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
    print("[2/6] SAFE Payload Handling")
    safe_payload = {
        "session_id": "e2e-test-safe-001",
        "user_intent": "Get meeting notes from yesterday's standup",
        "tool_name": "mcp_calendar_read",
        "tool_arguments": '{"meeting_id": "standup-2026-04-07", "attendees": ["alice", "bob"], "discussion": "sprint review"}'
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
    print("[3/6] Attack Payload Handling")
    attack_payload = {
        "session_id": "e2e-test-attack-001",
        "user_intent": "Update the tax filing record",
        "tool_name": "mcp_database_write",
        "tool_arguments": '{"taxpayer": "ABCDE1234F", "year": "2025-26", "status": "filed"}'
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
    print("[4/6] Audit Trail Persistence")
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
    print("[5/6] HMAC Signature Verification")
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
 
    # --- TEST 6: Rate limiting ---
    print("[6/6] Rate Limiting (per-session sliding window)")
 
    # Pull current rate limit config from /health so the test adapts to env settings
    _, health = http_get("/health")
    rl_config = health.get("rate_limiter", {}) if isinstance(health, dict) else {}
    rate_limit = rl_config.get("rate_limit", 60)
 
    if rate_limit <= 0:
        print("  [SKIP] Rate limiter disabled (AGENTAUDIT_RATE_LIMIT=0)")
    else:
        # Use a unique session_id so this test starts from zero count
        rate_session = f"e2e-rate-test-{int(time.time() * 1000)}"
        rate_payload = {
            "session_id": rate_session,
            "user_intent": "rate limit probe",
            "tool_name": "mcp_calendar_read",
            "tool_arguments": '{"x": "y"}'
        }
 
        # Phase 1: fire `rate_limit` requests, all should pass
        first_phase_pass = 0
        for i in range(rate_limit):
            status, _ = http_post("/audit", rate_payload)
            if status == 200:
                first_phase_pass += 1
 
        results.append(test(
            f"First {rate_limit} requests pass",
            first_phase_pass == rate_limit,
            f"passed {first_phase_pass}/{rate_limit}"
        ))
 
        # Phase 2: next 5 requests should be rate limited
        second_phase_blocked = 0
        retry_after_seen = False
        for i in range(5):
            req = urllib.request.Request(
                f"{BASE_URL}/audit",
                data=json.dumps(rate_payload).encode('utf-8'),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass  # 200, not what we want
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    second_phase_blocked += 1
                    if e.headers.get("Retry-After"):
                        retry_after_seen = True
 
        results.append(test(
            "Requests beyond limit return HTTP 429",
            second_phase_blocked == 5,
            f"blocked {second_phase_blocked}/5"
        ))
        results.append(test(
            "429 response includes Retry-After header",
            retry_after_seen
        ))
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