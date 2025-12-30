def check_injection(header):
    results = []
    
    dangerous_headers = ["jku", "jwk", "x5u", "x5c"]
    for h in dangerous_headers:
        if h in header:
            results.append({
                "type": "Critical",
                "msg": f"Dangerous Header: '{h}'",
                "risk": "Remote Key Injection. Attacker can force server to use their key.",
                "fix": "Disable support for dynamic key headers."
            })

    if "kid" in header:
        kid = str(header["kid"])
        if "../" in kid or "..\\" in kid:
             results.append({
                "type": "High",
                "msg": "Path Traversal in 'kid'",
                "risk": "File system access via key lookup.",
                "fix": "Sanitize 'kid'."
            })
        if any(x in kid.lower() for x in ["union", "select", "drop", "insert", "--", ";"]):
             results.append({
                "type": "High",
                "msg": "SQL Injection in 'kid'",
                "risk": "Database compromise via key lookup.",
                "fix": "Sanitize 'kid' and use prepared statements."
            })
        if "`" in kid or "$(" in kid:
             results.append({
                "type": "High",
                "msg": "Command Injection in 'kid'",
                "risk": "RCE potential.",
                "fix": "Sanitize 'kid'."
            })

    return results
