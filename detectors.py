import math
import re
import base64
import urllib.parse
 
# --- PRE-COMPILED PATTERNS (P1 perf fix: compile once, not per-call) ---
_SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),                        # AWS Access Key
    re.compile(r'sk_live_[0-9a-zA-Z]{20,}'),                # Stripe Live Key
    re.compile(r'(?i)bearer\s+[a-zA-Z0-9-._~+/]{20,}'),     # Bearer Token
    re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'),      # PEM Private Key
    re.compile(r'ghp_[A-Za-z0-9]{36,}'),                     # GitHub PAT
    re.compile(r'gho_[A-Za-z0-9]{36,}'),                     # GitHub OAuth
    re.compile(r'ghs_[A-Za-z0-9]{36,}'),                     # GitHub Server
    re.compile(r'xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}'),  # Slack Bot Token
    re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),  # Slack Webhook
    re.compile(r'mongodb(?:\+srv)?://[^\s]{10,}'),           # MongoDB connection string
    re.compile(r'(?i)postgres(?:ql)?://[^\s]{10,}'),         # PostgreSQL connection string
    re.compile(r'redis://[^\s]{10,}'),                       # Redis connection string
]
 
_PII_PATTERNS = {
    "AADHAAR": re.compile(r'[2-9]\d{3}\s?\d{4}\s?\d{4}'),
    "PAN": re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]'),
}
 
_BENIGN_PATTERNS = [
    re.compile(r'arn:aws:[a-z0-9:\/_.-]+'),          # AWS ARN — fixed: handles :: and /path
    re.compile(r'k8s-[a-z0-9-]+'),                   # Kubernetes IDs
    re.compile(r'quay\.io/[a-z0-9/-]+'),             # Container registry
    re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+'),          # Semver
    re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),  # UUID v4
    re.compile(r'ssh-rsa\s+[A-Za-z0-9+/]+={0,2}'),  # SSH public key
]
 
 
def calculate_jaccard(intent: str, arguments: str) -> float:
    stop_words = {'a', 'an', 'the', 'for', 'to', 'in', 'is', 'at', 'of', 'and', 'or', 'generate', 'get', 'fetch', 'please', 'retrieve', 'show', 'check', 'update', 'send', 'summarize', 'review', 'discuss', 'action', 'items', 'end', 'notes', 'we', 'this', 'that', 'with'}
    def get_tokens(text):
        return set(re.findall(r'\b\w+\b', text.lower())) - stop_words
    
    set_a, set_b = get_tokens(intent), get_tokens(arguments)
    
    # --- EXPANDED DOMAIN HEURISTICS ---
    if set_a.intersection({'report', 'sales', 'data', 'database', 'schema'}) and set_b.intersection({'select', 'from', 'update', 'alter', 'table', 'insert', 'delete'}): return 0.8
    if set_a.intersection({'github', 'action', 'workflow', 'deploy'}) and set_b.intersection({'name', 'runs', 'uses', 'steps'}): return 0.8
    if set_a.intersection({'iam', 'policy', 'aws', 'role'}) and set_b.intersection({'statement', 'effect', 'resource', 'action'}): return 0.8
    if set_a.intersection({'meeting', 'notes', 'summary'}) and set_b.intersection({'attendees', 'discussion'}): return 0.8
    if set_a.intersection({'key', 'keys', 'ssh', 'rsa', 'access'}) and set_b.intersection({'ssh-rsa', 'authorized', 'appended', 'host'}): return 0.8
    if set_a.intersection({'deploy', 'script', 'instance', 'startup', 'kubernetes', 'cluster', 'k8s'}) and set_b.intersection({'bin', 'bash', 'echo', 'start', 'manifest', 'workload', 'applying'}): return 0.8
    # V10 — Email & Marketing heuristic (fixes BEN-012 HTML template FP)
    if set_a.intersection({'email', 'template', 'marketing', 'newsletter', 'html', 'css'}) and set_b.intersection({'style', 'color', 'font', 'div', 'body', 'head', 'html', 'width'}): return 0.8
    # V10 — API & JSON payload heuristic (fixes BEN-004 JSON body FP)
    if set_a.intersection({'api', 'request', 'call', 'payload', 'webhook', 'endpoint'}) and set_b.intersection({'json', 'headers', 'content', 'type', 'application', 'method'}): return 0.8
    
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0
 
 
def contains_known_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)
 
 
def contains_pii(text: str) -> list:
    """Detect Indian PII patterns (DPDP Act compliance). Returns list of matched types.
    Runs on scrubbed text to avoid UUIDs/ARNs triggering false Aadhaar matches."""
    scrubbed = remove_benign_technical_ids(text)
    found = []
    for pii_type, pattern in _PII_PATTERNS.items():
        if pattern.search(scrubbed):
            found.append(pii_type)
    return found
 
 
def remove_benign_technical_ids(text: str) -> str:
    """Pre-Execution Scrubbing Phase — strips known-safe structural data before entropy analysis."""
    clean_text = text
    for p in _BENIGN_PATTERNS:
        clean_text = p.sub('', clean_text)
    return clean_text
 
 
def get_max_substring_entropy(text: str, window_size: int = 24) -> float:
    scrubbed_text = remove_benign_technical_ids(text)
    clean_text = re.sub(r'\s+', '', scrubbed_text)
    
    if len(clean_text) < window_size:
        return calculate_entropy_raw(clean_text)
    
    max_h = 0.0
    for i in range(len(clean_text) - window_size + 1):
        window = clean_text[i:i + window_size]
        h = calculate_entropy_raw(window)
        if h > max_h: max_h = h
    return max_h
 
 
def calculate_entropy_raw(text: str) -> float:
    if not text: return 0.0
    length = len(text)
    counts = {char: text.count(char) for char in set(text)}
    h = -sum((count / length) * math.log2(count / length) for count in counts.values())
    h_max = math.log2(length) if length > 1 else 1
    return h / h_max
 
 
async def detect_and_decode(payload: str, depth: int = 0) -> dict:
    if depth > 5: return {"decoded_payload": payload, "layers": []}
    current = payload
    layers = []
    modified = False
    
    if "%" in current:
        decoded = urllib.parse.unquote(current)
        if decoded != current:
            current, layers = decoded, ["URL"]
            modified = True
            
    b64_matches = set(re.findall(r'\b[A-Za-z0-9+/]{16,}={0,2}\b', current))
    for match in b64_matches:
        try:
            decoded_bytes = base64.b64decode(match)
            decoded_str = decoded_bytes.decode('utf-8')
            if decoded_str.isprintable() or '\n' in decoded_str:
                current = current.replace(match, decoded_str)
                if "BASE64" not in layers: layers.append("BASE64")
                modified = True
        except Exception:
            pass
            
    if modified:
        nested = await detect_and_decode(current, depth + 1)
        return {"decoded_payload": nested["decoded_payload"], "layers": layers + nested["layers"]}
        
    return {"decoded_payload": current, "layers": layers}