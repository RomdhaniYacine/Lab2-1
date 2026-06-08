# Lab 2 — SAST avec Semgrep

**Durée :** 1h &nbsp;|&nbsp; **Stack :** Python / Flask &nbsp;|&nbsp; **Outil :** Semgrep &nbsp;|&nbsp; **Niveau :** Développeur

---

## Contexte

L'équipe Architecture de Free Mobile prépare la mise en production d'une nouvelle API interne : `freemobile-netops-api`, utilisée par les équipes NOC (Network Operations Center) pour gérer les équipements réseau.

Avant le passage en prod, un **audit SAST** est requis. Vous êtes chargé de :
1. Identifier les vulnérabilités dans le code via Semgrep
2. Comprendre comment écrire des règles custom adaptées à votre contexte
3. Mettre en place les garde-fous (pre-commit, pipeline CI)
4. Corriger le code

**Impact potentiel :** Les 6 vulnérabilités présentes permettent — selon leur exploitation — une exécution de code à distance (RCE), une extraction de données (SQLi), ou une compromission des comptes (cryptographie faible).

---

## Prérequis

### Outils (vérifier avant de commencer)

```bash
# Docker
docker --version && docker compose version

# Semgrep
semgrep --version
# Si absent :
pip install semgrep
# ou : brew install semgrep

# pre-commit
pre-commit --version
# Si absent :
pip install pre-commit
```

---

## Lancement de l'application

```bash
git clone https://github.com/RomdhaniYacine/Lab2.git
cd Lab2
docker compose up
```

L'API démarre sur `http://localhost:5000`.

### Tester les routes

```bash
# Health
curl http://localhost:5000/health

# Liste des équipements
curl http://localhost:5000/api/v1/equipment

# Recherche (paramètre vulnérable)
curl "http://localhost:5000/api/v1/equipment/search?q=paris"

# Ping d'un équipement
curl -X POST http://localhost:5000/api/v1/equipment/ping \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.10.1.1"}'

# Authentification
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "netops2024!"}'

# Génération de token
curl http://localhost:5000/api/v1/token/generate
```

---

## Étape 1 — Explorer le code (10 min)

Ouvrez `app.py`. Six vulnérabilités sont présentes, chacune annotée dans le code.

**Exercice :** Avant de lancer Semgrep, identifiez-les manuellement et classez-les selon l'OWASP Top 10 2021.

| # | Ligne approx. | Type de vulnérabilité | OWASP catégorie |
|---|---|---|---|
| 1 | ~60 | ? | ? |
| 2 | ~73 | ? | ? |
| 3 | ~88 | ? | ? |
| 4 | ~100 | ? | ? |
| 5 | ~111 | ? | ? |
| 6 | ~121 | ? | ? |

**Questions :**
- Laquelle permet une exécution de code arbitraire sur le serveur ?
- Laquelle est la plus facile à exploiter via `curl` ?
- Pourquoi MD5 est-il insuffisant pour les mots de passe, même avec un hash ?

---

## Étape 2 — Scan avec les règles community (10 min)

Semgrep propose des milliers de règles maintenues par la communauté. Le pack `p/python` couvre les vulnérabilités Python courantes.

```bash
# Scan avec les règles community
semgrep --config p/python app.py

# Version verbeuse (affiche le code incriminé)
semgrep --config p/python app.py --verbose

# Export JSON pour traitement ultérieur
semgrep --config p/python app.py --json | python3 -m json.tool
```

**Questions :**
- Combien de vulnérabilités Semgrep a-t-il détectées ?
- Lesquelles ont été **manquées** ? Pourquoi ?
- Quelle est la différence entre une règle `ERROR` et `WARNING` ?

> **Note :** Semgrep community détecte les patterns connus. Pour les règles métier spécifiques (comme l'usage de MD5 pour les passwords dans votre contexte), il faut des règles custom.

---

## Étape 3 — Règles custom Free Mobile (10 min)

Le fichier `.semgrep.yml` contient 2 règles spécifiques à Free Mobile.

```bash
# Scan avec les règles custom uniquement
semgrep --config .semgrep.yml app.py

# Scan combiné : community + custom
semgrep --config p/python --config .semgrep.yml app.py
```

**Exercice — Écrire votre propre règle :**

Ajoutez une 3e règle dans `.semgrep.yml` pour détecter l'usage de `random.randint` dans des contextes de sécurité :

```yaml
  - id: freemobile-no-insecure-random
    pattern: random.randint(...)
    message: >
      [Free Mobile Security] random.randint() est prévisible.
      Pour les tokens de sécurité, utilisez secrets.token_hex() ou secrets.token_urlsafe().
    languages: [python]
    severity: WARNING
    metadata:
      owasp: "A02:2021 - Cryptographic Failures"
```

```bash
# Vérifier que la règle détecte bien le problème
semgrep --config .semgrep.yml app.py
```

**Questions :**
- Quelle est la différence entre `pattern` et `patterns` dans une règle Semgrep ?
- Comment ignorer un finding précis sans désactiver la règle ? (`# nosemgrep`)
- Quand utiliser `severity: ERROR` vs `WARNING` vs `INFO` ?

---

## Étape 4 — Corriger le code (15 min)

Appliquez les 6 corrections dans `app.py`. Le guide ci-dessous indique l'approche pour chaque vulnérabilité.

### Correction 1 — SQL Injection

```python
# Avant (vulnérable)
rows = conn.execute(
    f"SELECT * FROM equipment WHERE hostname LIKE '%{query}%'"
).fetchall()

# Après (sécurisé)
rows = conn.execute(
    "SELECT * FROM equipment WHERE hostname LIKE ? OR site LIKE ?",
    (f"%{query}%", f"%{query}%")
).fetchall()
```

### Correction 2 — OS Command Injection

```python
import ipaddress

# Avant (vulnérable)
result = subprocess.run(f"ping -c 2 {ip}", shell=True, ...)

# Après (sécurisé)
try:
    ipaddress.ip_address(ip)  # Valide que c'est bien une IP
except ValueError:
    return jsonify({"error": "IP invalide"}), 400

result = subprocess.run(["ping", "-c", "2", ip], capture_output=True, text=True, timeout=10)
```

### Correction 3 — MD5 → SHA-256 avec sel

```python
import os

# Avant (vulnérable)
hashed = hashlib.md5(password.encode()).hexdigest()

# Après (acceptable — bcrypt/argon2 est recommandé en production)
salt = os.urandom(16).hex()
hashed = hashlib.sha256((salt + password).encode()).hexdigest()
# Stocker : f"{salt}:{hashed}"
```

### Correction 4 — pickle → json

```python
import json

# Avant (vulnérable)
config = pickle.loads(raw)

# Après (sécurisé)
try:
    config = json.loads(raw)
except json.JSONDecodeError:
    return jsonify({"error": "JSON invalide"}), 400
```

### Correction 5 — eval() → ast.literal_eval()

```python
import ast

# Avant (vulnérable)
result = eval(rule)

# Après (sécurisé pour les types Python simples)
try:
    result = ast.literal_eval(rule)
except (ValueError, SyntaxError):
    return jsonify({"error": "Expression invalide"}), 400
```

### Correction 6 — random → secrets

```python
import secrets

# Avant (vulnérable)
token = str(random.randint(100000, 999999))

# Après (sécurisé)
token = secrets.token_hex(32)  # 64 caractères hexadécimaux, cryptographiquement sûr
```

---

## Étape 5 — Vérifier + Pre-commit (10 min)

### Re-scanner après correction

```bash
# Les deux scans doivent retourner 0 finding
semgrep --config p/python --config .semgrep.yml app.py
echo "Exit code: $?"
```

**Résultat attendu :** `Findings: 0` et exit code `0`.

### Installer le pre-commit hook

```bash
pre-commit install

# Tester le blocage — ajouter intentionnellement une vuln
echo "result = eval(request.args.get('x'))" >> test_vuln.py
git add test_vuln.py
git commit -m "test"
# → Doit être bloqué par Semgrep

# Nettoyer
rm test_vuln.py
git restore --staged . 2>/dev/null || true
```

**Question :** Le hook bloque-t-il le commit si `.semgrep.yml` est mal formé ? Testez.

---

## Étape 6 — Pipeline CI + SARIF (5 min)

Ouvrez `.github/workflows/security.yml` et décommentez le bloc `TODO étape 6`.

```bash
git add .github/workflows/security.yml app.py .semgrep.yml
git commit -m "fix: corrections SAST + pipeline Semgrep activé"
git push
```

Observez le pipeline sur `https://github.com/RomdhaniYacine/Lab2/actions`.

### SARIF → GitHub Security tab

Une fois le pipeline exécuté avec les findings, allez dans :
`GitHub → Security → Code scanning alerts`

Chaque finding Semgrep apparaît avec :
- Le fichier et la ligne exacte
- Le niveau de sévérité
- Le message de remédiation
- Un lien vers la règle

**Questions :**
- Comment configurer GitHub pour bloquer un merge si Semgrep trouve des `ERROR` ?
- Quelle est la différence entre un finding Semgrep en CI et en pre-commit local ?
- Comment gérer un faux positif dans le Security tab GitHub ?

---

## Checklist de réussite

```
[ ] semgrep --config p/python --config .semgrep.yml app.py  →  exit code 0 (0 finding)
[ ] SQL Injection corrigée   : requête paramétrée avec (?)
[ ] Command Injection corrigée : liste d'args + validation ipaddress
[ ] MD5 remplacé             : sha256 avec sel (ou bcrypt)
[ ] pickle remplacé          : json.loads avec gestion d'erreur
[ ] eval() remplacé          : ast.literal_eval() avec try/except
[ ] random remplacé          : secrets.token_hex(32)
[ ] Pre-commit hook installé : cat .git/hooks/pre-commit
[ ] Pipeline CI vert         : github.com/RomdhaniYacine/Lab2/actions
```

---

## Troubleshooting

**`semgrep: command not found`**
→ `pip install semgrep` puis vérifier que `~/.local/bin` est dans le PATH.

**Semgrep ne détecte pas la SQL injection**
→ Certaines règles community nécessitent un contexte Flask. Essayez `p/flask` en plus de `p/python`.

**`docker compose up` échoue sur port 5000**
→ `lsof -i :5000` pour identifier le processus, puis `kill <PID>`.

**Le hook pre-commit ne se déclenche pas**
→ Vérifiez que `pre-commit install` a bien été exécuté dans ce repo : `cat .git/hooks/pre-commit`.

**Semgrep timeout sur les règles community**
→ Utilisez `--timeout 30` pour augmenter le délai, ou scannez uniquement `app.py` au lieu de `.`.

---

## Solution

Le code corrigé et le pipeline complet sont dans `solution/`.
