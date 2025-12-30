def check_privacy(payload):
    results = []
    
    pii_keys = ["email", "phone", "address", "birthdate", "social_security", "user_metadata", "lastname", "firstname"]
    for key in pii_keys:
        if key in payload or (isinstance(payload.get(key), dict)): 
            results.append({
                "type": "Warning",
                "msg": f"PII Exposed: '{key}'",
                "risk": "GDPR/Privacy violation if leaked.",
                "fix": "Remove PII from token."
            })

    infra_keys = ["role", "permissions", "scope", "realm_access", "internal", "secret", "password", "hash"]
    for key in infra_keys:
        if key in payload:
            results.append({
                "type": "Warning",
                "msg": f"Sensitive Logic/Infra: '{key}'",
                "risk": "Exposing authorization logic/roles.",
                "fix": "Store roles in DB, use ID to lookup."
            })

    return results
