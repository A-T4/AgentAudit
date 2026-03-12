import math
import re
from collections import Counter
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="AgentAudit Core Engine v3.1 (Stable)")

class AuditRequest(BaseModel):
    prompt: str

def calculate_shannon_entropy(chunk: str) -> dict:
    """Calculates raw and normalized Shannon entropy for a specific text chunk."""
    length = len(chunk)
    if length <= 1:
        return {"raw": 0.0, "normalized": 0.0}
        
    counts = Counter(chunk)
    raw_entropy = -sum(
        (count / length) * math.log2(count / length) 
        for count in counts.values()
    )
    
    max_possible_entropy = math.log2(length)
    normalized_entropy = raw_entropy / max_possible_entropy if max_possible_entropy > 0 else 0.0
    
    return {
        "raw": round(raw_entropy, 2),
        "normalized": round(normalized_entropy, 2)
    }

def scan_sliding_window(text: str, window_size: int = 32) -> dict:
    """Slides a window across the text to isolate the highest local entropy."""
    if len(text) <= window_size:
        return calculate_shannon_entropy(text)
        
    peak_raw = 0.0
    peak_normalized = 0.0
    
    for i in range(len(text) - window_size + 1):
        chunk = text[i:i + window_size]
        metrics = calculate_shannon_entropy(chunk)
        
        if metrics["raw"] > peak_raw:
            peak_raw = metrics["raw"]
        if metrics["normalized"] > peak_normalized:
            peak_normalized = metrics["normalized"]
            
    return {"raw": peak_raw, "normalized": peak_normalized}

def execute_regex_scan(text: str) -> list:
    """Scans for structured PII patterns."""
    found_patterns = []
    pan_pattern = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b')
    aadhaar_pattern = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
    
    if pan_pattern.search(text):
        found_patterns.append("PAN_CARD")
    if aadhaar_pattern.search(text):
        found_patterns.append("AADHAAR_CARD")
        
    return found_patterns

@app.post("/audit")
async def audit_prompt(request: AuditRequest):
    text = request.prompt
    
    entropy_metrics = scan_sliding_window(text)
    regex_matches = execute_regex_scan(text)
    
    detected_flags = []
    
    if entropy_metrics["normalized"] > 0.85:
        detected_flags.append("VECTOR_A: HIGH_RISK_RATIO_SHORT_STRING")
    if entropy_metrics["raw"] > 4.5:
        detected_flags.append("VECTOR_A: HIGH_RAW_ENTROPY_LONG_SECRET")
    if regex_matches:
        detected_flags.append(f"VECTOR_B: REGEX_MATCH_{'_'.join(regex_matches)}")
        
    overall_status = "BLOCK / REDACT" if detected_flags else "SAFE"
    
    return {
        "peak_raw_entropy": entropy_metrics["raw"],
        "peak_normalized_entropy": entropy_metrics["normalized"],
        "overall_status": overall_status,
        "detected_flags": detected_flags
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)