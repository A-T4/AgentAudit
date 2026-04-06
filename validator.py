import json
import os
 
MANIFEST_PATH = os.path.join(os.path.dirname(__file__), 'manifest.json')
 
def _load_manifest() -> dict:
    """Load manifest once. Called at module import time."""
    try:
        with open(MANIFEST_PATH, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {"allowed_domains": [], "restricted_tools": []}
 
# Cache at startup — no disk I/O on hot path
_MANIFEST = _load_manifest()
 
def validate_agent_action(tool_name: str, target_domain: str = None) -> dict:
    if tool_name in _MANIFEST.get("restricted_tools", []):
        return {"is_authorized": False, "reason": f"Tool '{tool_name}' is restricted."}
    if target_domain and target_domain not in _MANIFEST.get("allowed_domains", []):
        return {"is_authorized": False, "reason": f"Domain '{target_domain}' is unauthorized."}
    return {"is_authorized": True, "reason": "Cleared"}
 
def reload_manifest():
    """Call this if manifest.json is updated at runtime."""
    global _MANIFEST
    _MANIFEST = _load_manifest()
 