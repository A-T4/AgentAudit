import json
import os

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), 'manifest.json')

def load_manifest() -> dict:
    """Loads the static security manifest."""
    try:
        with open(MANIFEST_PATH, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # Fail secure: If the manifest is missing, deny all.
        return {"allowed_domains": [], "restricted_tools": []}

def validate_agent_action(tool_name: str, target_domain: str = None) -> dict:
    """
    Admission Controller: Evaluates tool execution and domain requests 
    against the static manifest. Default posture is DENY.
    """
    manifest = load_manifest()
    
    # 1. Check for restricted tool execution
    if tool_name in manifest.get("restricted_tools", []):
        return {
            "is_authorized": False,
            "reason": f"Tool '{tool_name}' is explicitly restricted by manifest."
        }
        
    # 2. Check for unauthorized external domain access
    if target_domain and target_domain not in manifest.get("allowed_domains", []):
        return {
            "is_authorized": False,
            "reason": f"Domain '{target_domain}' is not in the allowed domains registry."
        }
        
    return {
        "is_authorized": True,
        "reason": "Action cleared by Admission Controller."
    }