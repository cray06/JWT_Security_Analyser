import jwt
import json
from datetime import datetime
from modules import crypto, claims, privacy, injection

def analyze_token(token: str, secret=None, public_key=None, bruteforce=False, wordlist=None):
    results = []
    
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError:
        return {"header": {}, "payload": {}, "results": [{"type": "Critical", "msg": "Invalid Header", "risk": "Parse Fail", "fix": "Check Format"}]}

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.DecodeError:
         return {"header": header, "payload": {}, "results": [{"type": "Critical", "msg": "Invalid Payload", "risk": "Parse Fail", "fix": "Check Format"}]}

    results.extend(crypto.check_crypto(header, payload, token, secret, public_key, bruteforce, wordlist))
    results.extend(claims.check_claims(payload))
    results.extend(privacy.check_privacy(payload))
    results.extend(injection.check_injection(header))
    
    if len(json.dumps(payload)) > 1500:
        results.append({
            "type": "Warning",
            "msg": "Large Payload Detected",
            "risk": "Performance/Bandwidth.",
            "fix": "Reduce payload."
        })

    return {"header": header, "payload": payload, "results": results}
