# Lab 2 — SAST avec Semgrep

**Durée estimée : 1h30** &nbsp;|&nbsp; **Stack : Python / Flask** &nbsp;|&nbsp; **Outil : Semgrep**

---

## Contexte

L'API `freemobile-netops-api` (gestion d'équipements réseau NOC) va passer en production.
Un audit SAST est requis avant le déploiement.

Contrairement au DAST qui teste l'application en cours d'exécution, le SAST analyse le **code source statiquement** — sans lancer l'application. C'est une première ligne de défense rapide, intégrable dès le commit.

---

## Prérequis

| Outil | Vérification |
|-------|-------------|
| Docker | `docker --version` |
| Semgrep | `semgrep --version` |
| Compte GitHub | accès à l'onglet Actions |

**Installer Semgrep (Python 3.9+ requis) :**

```bash
# macOS
brew install semgrep

# Linux / WSL
pip install semgrep

# Vérification
semgrep --version
```

> Si votre environnement ne dispose pas de Python 3.9+, utilisez Docker directement :
> ```bash
> docker run --rm -v "$(pwd)":/src semgrep/semgrep semgrep --config p/python --config p/security-audit /src/app.py
> ```

---

## Structure du projet

```
Lab2/
├── app.py                        ← API Flask (vulnérabilités intentionnelles)
├── requirements.txt
├── docker-compose.yml
└── .github/
    └── workflows/
        └── security.yml          ← Pipeline CI à compléter
```

---

## Étape 0 — Lancer l'application

```bash
docker compose up -d
curl http://localhost:5000/health
```

---

## Étape 1 — Scanner avec Semgrep

```bash
semgrep --config p/python --config p/security-audit app.py
echo "Exit code: $?"
```

> `0` = aucun finding &nbsp;|&nbsp; `1` = finding(s) détecté(s)

**Questions :**
- Combien de vulnérabilités Semgrep a-t-il détectées ?
- Quels types de vulnérabilités sont signalés ?
- Y a-t-il des vulnérabilités dans le code que Semgrep n'a **pas** détectées ? Pourquoi ?
- Quelle est la différence entre un scan SAST et un scan DAST ?

---

## Étape 2 — Construire la pipeline CI

Complétez `.github/workflows/security.yml` pour que la pipeline lance Semgrep à chaque push et échoue si des vulnérabilités sont détectées.

> **Référence :** [semgrep.dev/docs](https://semgrep.dev/docs/semgrep-ci/running-semgrep-ci-with-a-third-party-ci-provider/)

```bash
git add .github/workflows/security.yml
git commit -m "ci: pipeline Semgrep"
git push
```

Observez le résultat sur l'onglet **Actions**. La pipeline doit échouer — le code contient des vulnérabilités.

---

## Étape 3 — Corriger le code

Corrigez chaque vulnérabilité identifiée dans `app.py`. Après chaque correction, relancez le scan :

```bash
semgrep --config p/python --config p/security-audit app.py
```

Une fois les corrections terminées :

```bash
git add app.py
git commit -m "fix: vulnérabilités corrigées"
git push
```

La pipeline doit maintenant passer.

---

## Livrables attendus

- La sortie de `semgrep` avant correction.
- La pipeline CI en échec sur le code vulnérable (screenshot GitHub Actions).
- La pipeline CI en succès après correction (screenshot GitHub Actions).
- Réponses aux questions de l'étape 1.
