import re
import base64
import urllib.parse

def detect_and_decode(payload: str, depth: int = 0) -> dict:
    """
    Recursively detects and decodes Base64, Hex, and URL-encoded strings.
    Maintains an audit trail of stripped encoding layers.
    """
    max_recursion = 3
    if depth > max_recursion:
        return {"decoded_payload": payload, "encoding_layers": []}

    detected_encoding = None
    decoded_text = payload

    # 1. URL Encoding Validation
    if '%' in payload and re.search(r'(?:%[0-9A-Fa-f]{2})+', payload):
        try:
            unquoted = urllib.parse.unquote(payload)
            if unquoted != payload:
                detected_encoding = "URL_ENCODED"
                decoded_text = unquoted
        except Exception:
            pass

    # 2. Hex Encoding Validation (Length constraint prevents false positives)
    elif re.match(r'^[0-9A-Fa-f]+$', payload) and len(payload) >= 16 and len(payload) % 2 == 0:
        try:
            decoded_text = bytes.fromhex(payload).decode('utf-8')
            detected_encoding = "HEX"
        except Exception:
            pass

    # 3. Base64 Encoding Validation
    elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload) and len(payload) >= 16 and len(payload) % 4 == 0:
        try:
            decoded_text = base64.b64decode(payload).decode('utf-8')
            detected_encoding = "BASE64"
        except Exception:
            pass

    # Base Case: No obfuscation detected, return the payload
    if not detected_encoding:
        return {
            "decoded_payload": decoded_text,
            "encoding_layers": []
        }

    # Recursive Case: Peel the next layer of encoding
    nested_result = detect_and_decode(decoded_text, depth + 1)
    
    current_layers = [detected_encoding] + nested_result["encoding_layers"]
    
    return {
        "decoded_payload": nested_result["decoded_payload"],
        "encoding_layers": current_layers
    }