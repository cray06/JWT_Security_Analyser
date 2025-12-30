from datetime import datetime

def check_claims(payload):
    results = []
    now = datetime.now()

    if "exp" not in payload:
        results.append({
            "type": "High",
            "msg": "Missing Expiration (exp)",
            "risk": "Token valid forever if stolen.",
            "fix": "Add 'exp' claim."
        })
    else:
        exp = payload["exp"]
        if isinstance(exp, int):
            exp_dt = datetime.fromtimestamp(exp)
            if exp_dt < now:
                results.append({
                    "type": "Info",
                    "msg": "Token Expired",
                    "risk": "Token invalid.",
                    "fix": "Refresh token."
                })
            
            if "iat" in payload and isinstance(payload["iat"], int):
                iat_dt = datetime.fromtimestamp(payload["iat"])
                duration = (exp_dt - iat_dt).total_seconds() / 3600 
                if duration > 24:
                     results.append({
                        "type": "Warning",
                        "msg": f"Long Lived Token ({int(duration)} hours)",
                        "risk": "Increased window of opportunity for attackers.",
                        "fix": "Shorten TTL, use Refresh Tokens."
                    })

    if "nbf" in payload:
        if isinstance(payload["nbf"], int):
             if datetime.fromtimestamp(payload["nbf"]) > now:
                results.append({
                    "type": "Info",
                    "msg": "Token Not Valid Yet (nbf)",
                    "risk": "Token invalid.",
                    "fix": "Wait for nbf."
                })

    if "iat" in payload:
         if isinstance(payload["iat"], int):
             if datetime.fromtimestamp(payload["iat"]) > now:
                  results.append({
                    "type": "Warning",
                    "msg": "Issued in Future (iat)",
                    "risk": "Clock synchronization issue.",
                    "fix": "Check server clocks."
                })

    return results
