import os
import time
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import uvicorn
from detectors import calculate_jaccard, get_max_substring_entropy, detect_and_decode, contains_known_secret, contains_pii
from validator import validate_agent_action
from audit import log_audit_event
 
app = FastAPI(title="AgentAudit Sentinel OS v10.3")
_START_TIME = time.time()
 
# --- Layer 0: Volumetric Guardrail ---
MAX_PAYLOAD_BYTES = 51200  # 50KB ceiling
 
# --- API Key Auth ---
# Set AGENTAUDIT_API_KEY env var in production. If unset, auth is disabled (dev mode).
_API_KEY = os.environ.get("AGENTAUDIT_API_KEY", None)
 
async def verify_api_key(x_api_key: str = Header(default=None)):
    """API key check. Skipped if AGENTAUDIT_API_KEY is not set (dev mode)."""
    if _API_KEY is None:
        return
    if x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: Invalid or missing X-API-Key header")
 
 
class AuditRequest(BaseModel):
    session_id: str
    user_intent: str
    tool_name: str
    tool_arguments: str
    target_domain: str = None
 
 
@app.get("/health")
async def health_check():
    """Liveness probe for container orchestration."""
    return {
        "status": "healthy",
        "version": "10.3",
        "uptime_seconds": round(time.time() - _START_TIME, 1)
    }
 
 
@app.post("/audit", dependencies=[Depends(verify_api_key)])
async def audit_mcp_action(request: AuditRequest):
    # 0. LAYER 0 — Volumetric Guardrail (50KB ceiling)
    payload_size = len(request.tool_arguments.encode('utf-8'))
    if payload_size > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"PAYLOAD_CEILING_EXCEEDED: {payload_size} bytes exceeds {MAX_PAYLOAD_BYTES} byte limit"
        )
 
    # 1. Admission Control
    admission = validate_agent_action(request.tool_name, request.target_domain)
    if not admission["is_authorized"]:
        raise HTTPException(status_code=403, detail=f"SESSION_REVOKED: {admission['reason']}")
 
    # 2. Recursive Decode & Normalization
    decoder_result = await detect_and_decode(request.tool_arguments)
    norm_args = decoder_result["decoded_payload"]
 
    # 3. Deep Inspection
    jaccard_score = calculate_jaccard(request.user_intent, norm_args)
    max_entropy = get_max_substring_entropy(norm_args)
    has_secret = contains_known_secret(norm_args)
    pii_matches = contains_pii(norm_args)
 
    # --- ENFORCEMENT MATRIX ---
    should_block = False
    violations = []
 
    if has_secret:
        should_block = True
        violations.append("CONFIRMED_DATA_EXFILTRATION_PATTERN")
 
    if pii_matches:
        should_block = True
        violations.append(f"PII_DETECTED:{','.join(pii_matches)}")
 
    if not should_block and max_entropy > 0.90 and jaccard_score < 0.5:
        should_block = True
        violations.append("UNAUTHORIZED_HIGH_ENTROPY_DRIFT")
 
    if not should_block and jaccard_score < 0.10:
        should_block = True
        violations.append("TOTAL_PILOT_DEVIATION")
 
    verdict = "BLOCKED" if should_block else "SAFE"
    scores = {
        "entropy": round(max_entropy, 4),
        "jaccard": round(jaccard_score, 4),
        "pii": pii_matches,
        "secret_match": has_secret,
    }
 
    # 4. FORENSIC AUDIT TRAIL — every decision logged and HMAC-signed
    log_audit_event(
        session_id=request.session_id,
        tool_name=request.tool_name,
        target_domain=request.target_domain,
        user_intent=request.user_intent,
        tool_arguments=request.tool_arguments,
        verdict=verdict,
        violations=violations,
        scores=scores,
        decode_layers=decoder_result["layers"],
    )
 
    response = {
        "status": verdict,
        "session_id": request.session_id,
        "scores": scores,
        "decode_layers": decoder_result["layers"],
    }
    if should_block:
        response["violations"] = violations
 
    return response
 
 
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)