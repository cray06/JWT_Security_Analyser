# 🔐 JWT Security Analyzer

[English](#english-version) | [Français](#version-française)

---

## English Version

A robust, educational CLI tool to analyze JWT tokens for security flaws, privacy leaks, and configuration errors.

### 📂 Project Structure

```
JWT_Security_Analyser/
├── core.py           # Orchestrator: Calls all modules
├── display.py        # UI: Handles Rich output
├── main.py           # Entry Point: CLI arguments
├── modules/          # Security Checks
│   ├── claims.py     # Temporal & Logic checks
│   ├── crypto.py     # Algorithms, Signatures, Brute-force
│   ├── injection.py  # Header Injection (SQLi, Kid, etc.)
│   └── privacy.py    # PII & Sensitive Data
└── requirements.txt  # Dependencies
```

### 🚀 Installation

```bash
pip install -r requirements.txt
```

### 🛠️ Usage

#### 1. Basic Analysis
Performs static, semantic, and privacy analysis.

```bash
python main.py <YOUR_JWT_TOKEN>
```

#### 2. Verify Signature
Validate the token integrity if you know the secret or public key.

**HMAC (HS256):**
```bash
python main.py <TOKEN> --secret "mySuperSecretKey"
```

**RSA/ECDSA (RS256, ES256...):**
```bash
python main.py <TOKEN> --public-key ./public.pem
```

#### 3. Brute-force Attack
Attempt to crack the HMAC secret key. Only works for symmetric algos (HS256/384/512).
*Output:* Shows ONLY the result (Success/Fail/Skipped).

```bash
# It'll give you the result (Success/Fail/Skipped) with 20 common secrets
python main.py <TOKEN> --bruteforce

# It'll give you the result (Success/Fail/Skipped) with your custom wordlist
python main.py <TOKEN> --bruteforce --wordlist list.txt
```

### 🛡️ Modules Overview

| Module | Features |
|--------|----------|
| **Crypto** | `alg: none`, Key Confusion, Weak signatures, Brute-force |
| **Claims** | `exp` vs `iat` consistency, Long-lived tokens (>24h), Future dating |
| **Privacy** | Detects PII (email, phone), Auth metadata (`amr`, `session_id`) |
| **Injection**| Vulnerabilities in `kid`, `jku`, `x5u` (SQLi, Command Injection) |

### 📊 Output Example

**Normal Mode:**
```text
╭── Header ───╮ ╭── Payload ───╮
│ {"alg":...} │ │ {"sub":...}  │
╰─────────────╯ ╰──────────────╯

[CRITICAL] Algorithm 'none' allowed
   Risk: Signature validation bypassed.
   Fix: Reject tokens with alg: none.

[WARNING] PII Exposed: 'email'
   Risk: GDPR/Privacy violation if leaked.
   Fix: Remove PII from token.
```

**Brute-force Mode:**
```text
SUCCESS: Weak Secret Found: 'secret'
# OR
FAILED: Brute-force failed (20 attempts)
Tip: Try using a larger --wordlist (e.g., rockyou.txt)
# OR
INFO: Algorithm 'ES256' is asymmetric and cannot be brute-forced
```

---

## Version Française

Un outil CLI pédagogique et robuste pour analyser les vulnérabilités, les fuites de données et les erreurs de configuration dans les tokens JWT.

### 📂 Organisation du Projet

```
JWT_Security_Analyser/
├── core.py           # Chef d'orchestre : Appelle les modules
├── display.py        # Interface : Gère l'affichage stylisé 
├── main.py           # Point d'entrée : Arguments CLI
├── modules/          # Vérifications de sécurité
│   ├── claims.py     # Vérifications temporelles et logiques
│   ├── crypto.py     # Algorithmes, Signatures, Brute-force
│   ├── injection.py  # Injections d'en-tête (SQLi, Kid, etc.)
│   └── privacy.py    # Données personnelles et sensibles
└── requirements.txt  # Dépendances
```

### 🚀 Installation

```bash
pip install -r requirements.txt
```

### 🛠️ Utilisation

#### 1. Analyse de base
Effectue une analyse statique, sémantique et de confidentialité.

```bash
python main.py <VOTRE_TOKEN_JWT>
```

#### 2. Vérifier la signature
Valider l'intégrité du token si vous connaissez le secret ou la clé publique.

**HMAC (HS256):**
```bash
python main.py <TOKEN> --secret "monSuperSecret"
```

**RSA/ECDSA (RS256, ES256...):**
```bash
python main.py <TOKEN> --public-key ./public.pem
```

#### 3. Attaque Brute-force
Tentative de craquage de la clé secrète HMAC. Ne fonctionne que pour les algos symétriques.
*Sortie:* Affiche UNIQUEMENT le résultat (Succès/Échec/Ignoré).

```bash
# Tentative avec les 20 secrets les plus communs
python main.py <TOKEN> --bruteforce

# Tentative avec votre propre liste de mots (wordlist)
python main.py <TOKEN> --bruteforce --wordlist rockyou.txt
```

### 🛡️ Description des Modules

| Module | Fonctionnalités |
|--------|-----------------|
| **Crypto** | `alg: none`, Confusion de clé, Signatures faibles, Brute-force |
| **Claims** | Cohérence `exp`/`iat`, Tokens longue durée (>24h), Dates futures |
| **Privacy** | Détecte les PII (email, tel), Métadonnées d'auth (`amr`, `session_id`) |
| **Injection**| Vulnérabilités dans `kid`, `jku`, `x5u` (SQLi, Injection de commande) |

### 📊 Exemple de Sortie

**Mode Normal :**
```text
╭── Header ───╮ ╭── Payload ───╮
│ {"alg":...} │ │ {"sub":...}  │
╰─────────────╯ ╰──────────────╯

[CRITICAL] Algorithm 'none' allowed
   Risk: Signature validation bypassed.
   Fix: Reject tokens with alg: none.

[WARNING] PII Exposed: 'email'
   Risk: GDPR/Privacy violation if leaked.
   Fix: Remove PII from token.
```

**Mode Brute-force :**
```text
SUCCESS: Weak Secret Found: 'secret'
# OU
FAILED: Brute-force failed (20 attempts)
Tip: Try using a larger --wordlist (e.g., rockyou.txt)
# OU
INFO: Algorithm 'ES256' is asymmetric and cannot be brute-forced
```