import jwt

def check_crypto(header, payload, token, secret=None, public_key=None, bruteforce=False, wordlist=None):
    results = []
    alg = header.get("alg", "none").lower()

    if alg == "none":
        results.append({
            "type": "Critical",
            "msg": "Algorithm 'none' allowed",
            "risk": "Signature validation bypassed. Token forgery possible.",
            "fix": "Reject tokens with alg: none."
        })

    if alg == "hs256" and public_key:
        results.append({
            "type": "Critical",
            "msg": "RS256 Public Key used with HS256",
            "risk": "Key Confusion Attack. Attackers can sign tokens with the public key as HMAC secret.",
            "fix": "Enforce explicit algorithm checks on verification."
        })

    if secret or public_key:
        key = secret if secret else public_key
        try:
            jwt.decode(token, key, algorithms=[header.get("alg")])
            results.append({
                "type": "Success",
                "msg": "Signature Verified",
                "risk": "Token is authentic.",
                "fix": "None"
            })
        except jwt.InvalidSignatureError:
            results.append({
                "type": "Critical",
                "msg": "Invalid Signature",
                "risk": "Token modified or forged.",
                "fix": "Discard token."
            })
        except Exception as e:
             results.append({
                "type": "Error",
                "msg": f"Verification failed: {str(e)}",
                "risk": "Unknown error.",
                "fix": "Check key format."
            })

    if bruteforce:
        if alg.startswith("hs"):
            common_secrets = [
                "secret", "password", "123456", "admin", "jwt", "key", "12345", "test",
                "supersecret", "pass", "1234", "qwerty", "mysecret", "changeme", "legacy",
                "auth", "token", "dev", "staging", "prod"
            ]
            
            if wordlist:
                try:
                    with open(wordlist, "r") as f:
                        common_secrets = [line.strip() for line in f]
                except Exception:
                    results.append({
                        "type": "Error",
                        "msg": f"Could not read wordlist: {wordlist}",
                        "risk": "Brute-force aborted.",
                        "fix": "Check file path."
                    })
            
            found_secret = None
            count = 0
            for s in common_secrets:
                count += 1
                try:
                    jwt.decode(token, s, algorithms=[header.get("alg", "HS256")])
                    found_secret = s
                    break
                except (jwt.InvalidSignatureError, jwt.DecodeError):
                    continue
            
            if found_secret:
                 results.append({
                    "type": "Critical",
                    "msg": f"Weak Secret Found: '{found_secret}'",
                    "risk": "Secret key was brute-forced easily.",
                    "fix": "Use a complex, random 256-bit key."
                })
            else:
                 results.append({
                    "type": "Info",
                    "msg": f"Brute-force failed ({count} attempts)",
                    "risk": "Secret not found in current dictionary.",
                    "fix": "Try using a larger --wordlist (e.g., rockyou.txt)."
                })
        else:
             results.append({
                "type": "Info",
                "msg": f"Algorithm '{alg}' is asymmetric and cannot be brute-forced (only HMAC allowed)",
                "risk": "Brute-force targets symmetric (HMAC) keys.",
                "fix": "Private keys (RSA/EC) are not susceptible to simple wordlist attacks."
            })

    return results
