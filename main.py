import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from detectors import calculate_jaccard, get_max_substring_entropy, detect_and_decode, contains_known_secret
from validator import validate_agent_action

app = FastAPI(title="AgentAudit Sentinel OS v9.5")

class AuditRequest(BaseModel):
    session_id: str
    user_intent: str
    tool_name: str
    tool_arguments: str
    target_domain: str = None

@app.post("/audit")
async def audit_mcp_action(request: AuditRequest):
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
    
    # --- ENFORCEMENT MATRIX ---
    should_block = False
    violations = []

    # FATAL: Regex found a credential.
    if has_secret:
        should_block = True
        violations.append("CONFIRMED_DATA_EXFILTRATION_PATTERN")

    # SUSPICIOUS: High Entropy without context (ignores whitelisted IDs).
    elif max_entropy > 0.85 and jaccard_score < 0.6:
        should_block = True
        violations.append("UNAUTHORIZED_HIGH_ENTROPY_DRIFT")

    # HIJACK: Recalibrated Floor (0.10) for Total Pilot Deviation.
    elif jaccard_score < 0.10:
        should_block = True
        violations.append("TOTAL_PILOT_DEVIATION")

    if should_block:
        return {"status": "BLOCKED", "session_id": request.session_id, "violations": violations}

    return {"status": "SAFE", "session_id": request.session_id}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)