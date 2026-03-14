import logging
from typing import Any, Callable

# AgentAudit Core Imports
from detectors import detect_and_decode
from main import scan_sliding_window, execute_regex_scan
from validator import validate_agent_action

logging.basicConfig(level=logging.INFO, format='%(message)s')

class ZeronSentinel:
    """
    AgentAudit Middleware Hook for Zeron ADK.
    Intercepts and deeply inspects tool payloads before execution.
    """
    @staticmethod
    def inspect_payload(tool_name: str, kwargs: dict[str, Any]) -> bool:
        print(f"\n[AgentAudit] Intercepting execution request for tool: '{tool_name}'...")
        
        # 1. Static Admission Control (Capability Creep Check)
        admission = validate_agent_action(tool_name)
        if not admission["is_authorized"]:
            print(f"[AgentAudit FATAL] Manifest Deny: {admission['reason']}")
            return False

        # 2. Dynamic Payload Inspection
        for key, value in kwargs.items():
            if not isinstance(value, str):
                continue
            
            # Recursive Decoding
            decoder_res = detect_and_decode(value)
            decoded_text = decoder_res["decoded_payload"]
            if decoder_res["encoding_layers"]:
                print(f"[AgentAudit WARN] Obfuscation stripped. Layers: {decoder_res['encoding_layers']}")

            # H_rel Entropy Engine
            entropy = scan_sliding_window(decoded_text)
            if entropy["normalized"] > 0.85:
                print(f"[AgentAudit FATAL] Payload Blocked. High Entropy detected in '{key}': H_rel={entropy['normalized']}")
                return False
            
            # Regional PII Scanners
            compliance_flags = execute_regex_scan(decoded_text)
            if compliance_flags:
                print(f"[AgentAudit FATAL] Exfiltration Blocked. PII detected in '{key}': {compliance_flags}")
                return False
        
        print("[AgentAudit] Payload cleared. Bounded autonomy verified.")
        return True

    @classmethod
    def wrap_execution(cls, target_function: Callable) -> Callable:
        """Decorator to wrap any framework's tool execution functions."""
        def wrapper(tool_name: str, **kwargs):
            if not cls.inspect_payload(tool_name, kwargs):
                raise PermissionError(f"AgentAudit blocked execution of '{tool_name}' due to policy violation.")
            return target_function(tool_name, **kwargs)
        return wrapper