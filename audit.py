"""
AgentAudit Forensic Audit Trail
================================
Append-only JSONL logging with HMAC-SHA256 signing.
Each log entry is independently verifiable and tamper-evident.
 
DPDP Act compliance: provides the cryptographic audit trail
that a DPO can hand directly to a regulator.
"""
 
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
 
# HMAC signing key — load from env or generate a default for dev
_HMAC_KEY = os.environ.get("AGENTAUDIT_HMAC_KEY", "dev-signing-key-change-in-production").encode('utf-8')
 
# Audit log file path
_AUDIT_LOG_PATH = os.environ.get("AGENTAUDIT_LOG_PATH", "audit_trail.jsonl")
 
 
def _compute_payload_hash(payload: str) -> str:
    """SHA-256 hash of the raw tool_arguments. Never store raw payloads in the log."""
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()
 
 
def _sign_entry(entry_json: str) -> str:
    """HMAC-SHA256 signature of the serialized log entry."""
    return hmac.new(_HMAC_KEY, entry_json.encode('utf-8'), hashlib.sha256).hexdigest()
 
 
def log_audit_event(
    session_id: str,
    tool_name: str,
    target_domain: str,
    user_intent: str,
    tool_arguments: str,
    verdict: str,
    violations: list,
    scores: dict,
    decode_layers: list,
) -> dict:
    """
    Write a signed, structured audit entry to the JSONL log.
    Returns the entry dict (without raw payload — only hash).
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "epoch_ms": int(time.time() * 1000),
        "session_id": session_id,
        "tool_name": tool_name,
        "target_domain": target_domain,
        "user_intent_preview": user_intent[:100],
        "payload_hash": _compute_payload_hash(tool_arguments),
        "payload_size_bytes": len(tool_arguments.encode('utf-8')),
        "verdict": verdict,
        "violations": violations,
        "scores": scores,
        "decode_layers": decode_layers,
    }
 
    # Serialize without signature first, then sign
    entry_json = json.dumps(entry, separators=(',', ':'), sort_keys=True)
    signature = _sign_entry(entry_json)
    entry["hmac_sha256"] = signature
 
    # Append to JSONL — one line per entry, atomic write
    signed_line = json.dumps(entry, separators=(',', ':'), sort_keys=True)
    try:
        with open(_AUDIT_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(signed_line + '\n')
    except IOError:
        pass  # fail open — don't crash the proxy if log write fails
 
    return entry
 
 
def verify_log_entry(entry_json_line: str) -> bool:
    """
    Verify a single JSONL log line's HMAC signature.
    Used by compliance auditors to prove log integrity.
    """
    try:
        entry = json.loads(entry_json_line)
        stored_sig = entry.pop("hmac_sha256", None)
        if not stored_sig:
            return False
        recomputed_json = json.dumps(entry, separators=(',', ':'), sort_keys=True)
        expected_sig = _sign_entry(recomputed_json)
        return hmac.compare_digest(stored_sig, expected_sig)
    except (json.JSONDecodeError, KeyError):
        return False