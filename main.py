import asyncio
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn
from detectors import calculate_jaccard, get_max_substring_entropy, detect_and_decode, contains_known_secret, contains_pii
from validator import validate_agent_action
 
app = FastAPI(title="AgentAudit Sentinel OS v10.2")
 
# --- Layer 0: Volumetric Guardrail ---
MAX_PAYLOAD_BYTES = 51200  # 50KB ceiling
 
class AuditRequest(BaseModel):
    session_id: str
    user_intent: str
    tool_name: str
    tool_arguments: str
    target_domain: str = None
 
@app.post("/audit")
async def audit_mcp_action(request: AuditRequest):
    # 0. LAYER 0 — Volumetric Guardrail (50KB ceiling)
    payload_size = len(request.tool_arguments.encode('utf-8'))
    if payload_size > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"PAYLOAD_CEILING_EXCEEDED: {payload_size} bytes exceeds {MAX_PAYLOAD_BYTES} byte limit"
        )
 
    # 1. Synchronous Admission Control (Thread Aligned)
    admission = validate_agent_action(request.tool_name, request.target_domain)
    if not admission["is_authorized"]:
        raise HTTPException(status_code=403, detail=f"SESSION_REVOKED: {admission['reason']}")
 
    # 2. Asynchronous Normalization
    decoder_result = await detect_and_decode(request.tool_arguments)
    norm_args = decoder_result["decoded_payload"]
 
    # 3. Parallel Deep Inspection
    jaccard_score = calculate_jaccard(request.user_intent, norm_args)
    max_entropy = get_max_substring_entropy(norm_args)
    has_secret = contains_known_secret(norm_args)
    pii_matches = contains_pii(norm_args)
 
    # --- ENFORCEMENT MATRIX ---
    should_block = False
    violations = []
 
    # FATAL: Regex found a credential.
    if has_secret:
        should_block = True
        violations.append("CONFIRMED_DATA_EXFILTRATION_PATTERN")
 
    # FATAL: PII detected — DPDP Act compliance enforcement.
    if pii_matches:
        should_block = True
        violations.append(f"PII_DETECTED:{','.join(pii_matches)}")
 
    # SUSPICIOUS: High Entropy without context (tuned v10.0: 0.85→0.90, 0.6→0.5)
    if not should_block and max_entropy > 0.90 and jaccard_score < 0.5:
        should_block = True
        violations.append("UNAUTHORIZED_HIGH_ENTROPY_DRIFT")
 
    # HIJACK: Total Pilot Deviation — intent and payload share almost nothing.
    if not should_block and jaccard_score < 0.10:
        should_block = True
        violations.append("TOTAL_PILOT_DEVIATION")
 
    if should_block:
        return {
            "status": "BLOCKED",
            "session_id": request.session_id,
            "violations": violations,
            "scores": {
                "entropy": round(max_entropy, 4),
                "jaccard": round(jaccard_score, 4),
                "pii": pii_matches,
                "secret_match": has_secret,
                "decode_layers": decoder_result["layers"]
            }
        }
 
    return {
        "status": "SAFE",
        "session_id": request.session_id,
        "scores": {
            "entropy": round(max_entropy, 4),
            "jaccard": round(jaccard_score, 4),
            "pii": pii_matches,
            "secret_match": has_secret,
            "decode_layers": decoder_result["layers"]
        }
    }
 
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)