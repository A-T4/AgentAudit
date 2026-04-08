"""
AgentAudit End-to-End Integration Test
=======================================
Runs against a live Dockerized container. Tests:
  1. /health endpoint responds
  2. /audit accepts a SAFE payload and logs it
  3. /audit BLOCKS an attack payload and logs it
  4. Audit trail JSONL file contains valid HMAC-signed entries
  5. Tamper detection works
  6. Per-session rate limiting returns 429 + Retry-After
  7. SSE /events stream broadcasts live decisions
 
Usage:
  # Start container first:
  docker compose up --build -d
 
  # Wait 10 seconds for startup, then:
  python test_e2e.py
"""
 
import json
import os
import sys
import threading
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
    print("[1/7] Health Check")
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
    print("[2/7] SAFE Payload Handling")
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
    print("[3/7] Attack Payload Handling")
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
    print("[4/7] Audit Trail Persistence")
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
    print("[5/7] HMAC Signature Verification")
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
    print("[6/7] Rate Limiting (per-session sliding window)")
 
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
 
    # --- TEST 7: SSE live event stream ---
    print("[7/7] SSE Live Event Stream (/events)")
 
    sse_events = []
    sse_connected = threading.Event()
    sse_error = []
 
    def sse_listener():
        try:
            resp = urllib.request.urlopen(f"{BASE_URL}/events", timeout=10)
            buffer = b""
            # Read up to ~8KB of stream data — enough for connected frame + a few decisions
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    chunk = resp.fp.read1(4096)
                except Exception:
                    break
                if not chunk:
                    break
                buffer += chunk
                # Split into SSE frames on \n\n
                while b"\n\n" in buffer:
                    frame, buffer = buffer.split(b"\n\n", 1)
                    event_type = None
                    for line in frame.split(b"\n"):
                        if line.startswith(b"event: "):
                            event_type = line[7:].decode('utf-8', errors='replace').strip()
                        elif line.startswith(b"data: "):
                            try:
                                payload = json.loads(line[6:].decode('utf-8'))
                                if event_type:
                                    payload["_sse_event"] = event_type
                                sse_events.append(payload)
                                if payload.get("type") == "stream_connected":
                                    sse_connected.set()
                            except json.JSONDecodeError:
                                pass
            try:
                resp.close()
            except Exception:
                pass
        except Exception as e:
            sse_error.append(str(e))
 
    listener_thread = threading.Thread(target=sse_listener, daemon=True)
    listener_thread.start()
 
    # Give the stream a moment to connect and receive the opening frame
    sse_connected.wait(timeout=2.0)
 
    results.append(test(
        "SSE /events connection established",
        sse_connected.is_set(),
        f"error={sse_error[0] if sse_error else 'none'}"
    ))
    results.append(test(
        "Stream emits 'connected' hello frame",
        any(e.get("type") == "stream_connected" for e in sse_events)
    ))
 
    # Fire a SAFE and a BLOCKED audit request — the listener should receive both as events
    sse_safe_session = f"sse-test-safe-{int(time.time() * 1000)}"
    sse_attack_session = f"sse-test-attack-{int(time.time() * 1000)}"
 
    http_post("/audit", {
        "session_id": sse_safe_session,
        "user_intent": "Get meeting notes from yesterday's standup",
        "tool_name": "mcp_calendar_read",
        "tool_arguments": '{"meeting_id": "standup-2026-04-08", "attendees": ["alice"], "discussion": "sprint review"}'
    })
    http_post("/audit", {
        "session_id": sse_attack_session,
        "user_intent": "Update the tax filing record",
        "tool_name": "mcp_database_write",
        "tool_arguments": '{"taxpayer": "ABCDE1234F", "year": "2025-26", "status": "filed"}'
    })
 
    # Wait for the listener thread to pick up the events (it reads for up to 5s)
    listener_thread.join(timeout=6.0)
 
    decision_events = [e for e in sse_events if e.get("type") == "audit_decision"]
    results.append(test(
        "At least 2 decision events received via SSE",
        len(decision_events) >= 2,
        f"received {len(decision_events)} decision events"
    ))
 
    safe_event = next((e for e in decision_events if e.get("session_id") == sse_safe_session), None)
    attack_event = next((e for e in decision_events if e.get("session_id") == sse_attack_session), None)
 
    results.append(test(
        "SAFE /audit request streamed with verdict=SAFE",
        safe_event is not None and safe_event.get("verdict") == "SAFE",
        f"event={safe_event}"
    ))
    results.append(test(
        "BLOCKED /audit request streamed with verdict=BLOCKED",
        attack_event is not None and attack_event.get("verdict") == "BLOCKED",
        f"event={attack_event}"
    ))
    results.append(test(
        "Streamed BLOCKED event includes PII violation",
        attack_event is not None and any("PAN" in v for v in attack_event.get("violations", []))
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