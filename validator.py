import json
import os

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), 'manifest.json')

def load_manifest() -> dict:
    try:
        with open(MANIFEST_PATH, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {"allowed_domains": [], "restricted_tools": []}

def validate_agent_action(tool_name: str, target_domain: str = None) -> dict:
    manifest = load_manifest()
    
    if tool_name in manifest.get("restricted_tools", []):
        return {"is_authorized": False, "reason": f"Tool '{tool_name}' is restricted."}
        
    if target_domain and target_domain not in manifest.get("allowed_domains", []):
        return {"is_authorized": False, "reason": f"Domain '{target_domain}' is unauthorized."}
        
    return {"is_authorized": True, "reason": "Cleared"}