import asyncio
import json
import os
import time
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn
from detectors import calculate_jaccard, get_max_substring_entropy, detect_and_decode, contains_known_secret, contains_pii
from validator import validate_agent_action
from audit import log_audit_event
from rate_limiter import check_rate_limit, get_rate_limit_config
from event_bus import publish as publish_event, subscribe as subscribe_events, get_subscriber_count
 
app = FastAPI(title="AgentAudit Sentinel OS v10.6")
_START_TIME = time.time()
 
# --- CORS Middleware ---
# Configurable origins via env. Defaults to localhost for dev safety.
# In production set AGENTAUDIT_CORS_ORIGINS="https://client1.com,https://client2.com"
_cors_origins_env = os.environ.get("AGENTAUDIT_CORS_ORIGINS", "http://localhost:3000,http://localhost:8000")
_CORS_ORIGINS = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)
 
# --- Layer 0: Volumetric Guardrail ---
MAX_PAYLOAD_BYTES = 51200  # 50KB ceiling
 
# --- API Key Auth ---
# Set AGENTAUDIT_API_KEY env var in production. If unset or empty, auth is disabled (dev mode).
_API_KEY = os.environ.get("AGENTAUDIT_API_KEY") or None
 
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
        "version": "10.6",
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "rate_limiter": get_rate_limit_config(),
        "sse_subscribers": get_subscriber_count()
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
 
    # 0.5. RATE LIMIT — per-session sliding window (default 60 req/60s)
    await check_rate_limit(request.session_id)
 
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
 
    # 5. LIVE STREAM — fan-out to connected SSE clients (dashboard)
    await publish_event({
        "type": "audit_decision",
        "timestamp_ms": int(time.time() * 1000),
        "session_id": request.session_id,
        "tool_name": request.tool_name,
        "target_domain": request.target_domain,
        "user_intent_preview": request.user_intent[:120],
        "payload_size_bytes": payload_size,
        "verdict": verdict,
        "violations": violations,
        "scores": scores,
        "decode_layers": decoder_result["layers"],
    })
 
    response = {
        "status": verdict,
        "session_id": request.session_id,
        "scores": scores,
        "decode_layers": decoder_result["layers"],
    }
    if should_block:
        response["violations"] = violations
 
    return response
 
 
@app.get("/events")
async def stream_events(request: Request):
    """
    Server-Sent Events stream of live audit decisions.
 
    Format: text/event-stream per WHATWG SSE spec.
    Each decision is emitted as a single `data:` frame with a JSON payload.
    A keepalive comment is sent every 15 seconds so idle connections
    survive proxy/LB idle timeouts.
 
    Authentication: respects AGENTAUDIT_API_KEY if set. Pass as X-API-Key header.
    """
    # Manual API key check — SSE clients pass headers differently, and Depends
    # wraps the response object in a way that confuses StreamingResponse.
    if _API_KEY is not None:
        client_key = request.headers.get("x-api-key")
        if client_key != _API_KEY:
            raise HTTPException(status_code=401, detail="UNAUTHORIZED: Invalid or missing X-API-Key header")
 
    async def event_generator():
        # Opening frame — tells the client the stream is live
        hello = {
            "type": "stream_connected",
            "timestamp_ms": int(time.time() * 1000),
            "version": "10.6",
        }
        yield f"event: connected\ndata: {json.dumps(hello)}\n\n"
 
        try:
            queue, unsubscribe = await subscribe_events()
        except RuntimeError as e:
            err = {"type": "error", "detail": str(e)}
            yield f"event: error\ndata: {json.dumps(err)}\n\n"
            return
 
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # Wait up to 15s for the next event. If nothing arrives,
                    # emit an SSE comment line as a keepalive and loop.
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await unsubscribe()
 
    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",  # disable nginx buffering if proxied
    }
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)
 
 
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
 