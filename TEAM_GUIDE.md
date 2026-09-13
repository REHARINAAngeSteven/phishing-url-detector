# 👥 Guide de l'équipe — Phishing URL Detector

> 📖 Ce guide complète le [CONTRIBUTING.md](./CONTRIBUTING.md).
>
> - **CONTRIBUTING.md** = conventions à respecter (commits, branches)
> - **TEAM_GUIDE.md** = contexte du projet + démarrage + qui fait quoi

---

## 📚 Contexte du projet

**Objectif** : détecter les URLs de phishing par Machine Learning,
en se basant **uniquement sur la chaîne de caractères de l'URL**
(aucune requête réseau, aucun HTML).

**Cursus** : M1 Informatique Générale — ENI Fianarantsoa
**Équipe** : 6 membres
**Repo** : https://github.com/REHARINAAngeSteven/phishing-url-detector
**Branche active** : `feature/ml`

### Architecture

```text
URL brute
   │
   ▼
src/feature_extractor.py     (52 features URL-only)
   │
   ▼
models/best_model.joblib     (Random Forest, 90.2% accuracy)
   │
   ▼
api/main.py (FastAPI) ─── app/app.py (Gradio)
   │
   ▼
Hugging Face Spaces
```

### État actuel

| Composant | État | Propriétaire |
|-----------|------|--------------|
| Dataset Kaggle | ✅ | Membre 1 |
| Notebook EDA (87 features) | ✅ | Membre 1 |
| Notebook pipeline final (52 features) | ✅ | Membre 1 |
| Modèle entraîné (90.2% accuracy) | ✅ | Membre 1 |
| `src/feature_extractor.py` | ✅ | Membre 1/2 |
| `src/predict.py` | ⚠️ Warning `feature names` à corriger | Membre 2 |
| `api/main.py` (FastAPI) | ⏳ À faire | Membre 3 |
| `app/app.py` (Gradio) | ⏳ À faire | Membre 4 |
| `tests/` | ⏳ À faire | Membre 5 |
| Déploiement Hugging Face | ⏳ À faire | Membre 6 |

---

## 🚀 Setup pour tous les membres

### 1. Cloner le repo

**Option HTTPS** :

```bash
git clone https://github.com/REHARINAAngeSteven/phishing-url-detector.git
cd phishing-url-detector
```

### 2. Créer l'environnement virtuel

**Prérequis** : Python 3.12

```bash
python3 -m venv .venv

# Linux/Mac
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Vérifier que tout fonctionne

```bash
# Test 1 : le modèle est bien présent
ls -lh models/

# Test 2 : le stress test
python tools/stress_test.py
```

**Attendu** :
- 3 fichiers `.joblib` + `feature_list.json` dans `models/`
- Score autour de **87%** sur le stress test

> **Le modèle est déjà versionné sur GitHub** — pas besoin de télécharger
> le dataset Kaggle ni de réentraîner !

### 5. Configurer Git

```bash
git config user.name "Votre Nom"
git config user.email "votre.email@example.com"
```

---

## 🎯 Rôles et tâches détaillées

### 👤 Membre 1 — ML & Dataset (terminé)

**Pseudo** : `Steven`

**Branche** : `feature/ml`

**Ce qui est fait** :
- Dataset Kaggle téléchargé et exploré
- Notebook EDA (87 features) → `notebooks/01_*.ipynb`
- Pipeline final (52 features URL-only) → `notebooks/02_*.ipynb`
- Modèle Random Forest (90.2% accuracy)
- Documentation complète dans README

**Reste à faire** :
- Aider les autres membres en cas de blocage
- Review des Pull Requests

---

### 👤 Membre 2 — Feature extraction & `src/predict.py`

**Pseudo** : `@____________`
**Branche** : `feature/predict`

**Fichiers à modifier/créer** :
- `src/predict.py` (existe, à améliorer)
- `src/feature_extractor.py` (ne pas casser !)

**Tâches** :
- [ ] Corriger le warning `UserWarning: X does not have valid feature names`
      → Utiliser `pd.DataFrame` au lieu de `np.array` dans `predict_url()`
- [ ] Ajouter un mode CLI : `python src/predict.py "http://..."`
- [ ] Documenter chaque fonction avec docstrings
- [ ] Créer un test rapide dans `tests/test_predict.py`

**Ressources** :
- Notebook : `notebooks/02_url_only_52_features.ipynb` (cellule 14)
- Code existant : `src/predict.py`

**Dépendances** : aucune (peut commencer tout de suite)

---

### 👤 Membre 3 — API FastAPI 🔥 (priorité)

**Pseudo** : `@____________`
**Branche** : `feature/api`

**Fichiers à créer** :
```
api/
├── __init__.py
├── main.py         # Point d'entrée FastAPI
├── schemas.py      # Modèles Pydantic
└── README.md       # Doc de l'API
```

**Tâches** :
- [ ] `POST /predict` : reçoit `{"url": "..."}`, retourne
      `{"url": "...", "prediction": "phishing"|"legitimate", "confidence": 0.95}`
- [ ] `GET /health` : vérifier que l'API tourne
- [ ] Charger le modèle **une seule fois** au démarrage
- [ ] Documenter automatiquement avec FastAPI (OpenAPI / Swagger)
- [ ] Tester : `uvicorn api.main:app --reload` puis `curl`

**Ressources** :
- Modèle : `models/best_model.joblib`
- Feature extractor : `src/feature_extractor.py`
- Notebook : `notebooks/02_url_only_52_features.ipynb` (cellule 14)

**Dépendances à ajouter** :
```bash
pip install fastapi uvicorn pydantic
```

**⚠️ Priorité** : Membre 4 (Gradio fa tsy voatery hoy Mr t@'izay) et Membre 6 (Déploiement) dépendent de cette API.

**Exemple de code** :
Exemple io fa tsy hoe io ny code main API ntsika, ze responsable an'io no tokony mahay ze anaovany azy de raha mety de mba ataovy mazava tsara ny code mba hisy ianarana azy.
```python
# api/main.py
from fastapi import FastAPI
from pydantic import BaseModel
import joblib, json
import sys
sys.path.insert(0, 'src')
from feature_extractor import extract_features

app = FastAPI(title="Phishing URL Detector API")

# Charger le modèle une seule fois
MODEL = joblib.load('models/best_model.joblib')
SCALER = joblib.load('models/scaler.joblib')
ENCODER = joblib.load('models/label_encoder.joblib')
FEATURES = json.load(open('models/feature_list.json'))

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    prediction: str
    confidence: float

@app.post("/predict", response_model=URLResponse)
def predict(req: URLRequest):
    x = SCALER.transform([extract_features(req.url, feature_order=FEATURES)])
    pred = ENCODER.inverse_transform(MODEL.predict(x))[0]
    proba = MODEL.predict_proba(x)[0].max()
    return URLResponse(url=req.url, prediction=pred, confidence=float(proba))

@app.get("/health")
def health():
    return {"status": "ok"}
```

---

### 👤 Membre 4 — Interface Gradio

**Pseudo** : `@____________`
**Branche** : `feature/gradio-ui`

**Fichiers à créer** :
```
app/
├── app.py          # Interface Gradio
├── requirements.txt # Dépendances spécifiques
└── README.md       # Doc de l'interface
```

**Tâches** :
- [ ] Champ texte URL + bouton "Analyser"
- [ ] Affichage clair : ✅ LEGITIMATE ou ⚠️ PHISHING
- [ ] Barre de confiance (0-100%)
- [ ] Exemples cliquables (Google, PayPal phishing, etc.)
- [ ] Mode sombre / clair

**Ressources** :
- Modèle : `models/best_model.joblib`
- Feature extractor : `src/feature_extractor.py`

**Dépendances** :
Avereniko : TSY voatery fa gradio no nomeny sy nataony Mr exemple.
```bash
pip install gradio
```

**⚠️ Peut commencer** avec une interface mockée (résultats factices), puis brancher le vrai modèle.

---

### 👤 Membre 5 — Tests & Documentation

**Pseudo** : `@____________`
**Branche** : `feature/tests`

**Fichiers à créer** :
```
tests/
├── __init__.py
├── test_feature_extractor.py
├── test_predict.py
└── test_api.py         # (si l'API existe)
```

**Tâches** :
- [ ] Tests unitaires pour `feature_extractor.py` (au moins 5)
- [ ] Tests pour `predict.py` (au moins 3)
- [ ] Test d'intégration : URL → prédiction
- [ ] Configurer `pytest` (`pytest.ini` ou `pyproject.toml`)
- [ ] Documenter l'API dans `docs/API.md`

**Ressources** :
- Code à tester : `src/feature_extractor.py`, `src/predict.py`

**Dépendances** :
```bash
pip install pytest pytest-cov
```

**⚠️ Peut commencer tout de suite** sur les tests de `feature_extractor.py`.

**Exemple de test** :
```python
# tests/test_feature_extractor.py
import sys
sys.path.insert(0, 'src')
from feature_extractor import extract_features

def test_extract_returns_52_features():
    feats = extract_features("https://www.google.com")
    assert len(feats) == 52

def test_extract_handles_empty_url():
    try:
        extract_features("")
        assert False, "Should raise ValueError"
    except ValueError:
        pass
```

---

### 👤 Membre 6 — Déploiement Hugging Face

**Pseudo** : `@____________`
**Branche** : `feature/deploy`

**Fichiers à créer** :
```
deploy/
├── README.md
├── requirements.txt
├── app.py          # Copie de app/app.py
├── models/         # Modèle à uploader
└── .gitignore
```

**Tâches** :
- [ ] Créer un compte [Hugging Face](https://huggingface.co/join)
- [ ] Créer un Space (type Gradio)
- [ ] Copier `app/app.py` + `models/best_model.joblib`
- [ ] Configurer `requirements.txt` pour le Space
- [ ] Déployer et tester
- [ ] Récupérer le lien public et l'ajouter au README

**Ressources** :
- Modèle : `models/best_model.joblib`
- Interface : `app/app.py` (à faire par Membre 4)

**Dépendances** :
```bash
pip install huggingface_hub
```

**⚠️ Attend Membre 4** (interface) avant de déployer.

---

## 🔀 Workflow Git

### Créer sa branche

```bash
# Se placer sur la branche principale et récupérer les modifs
git checkout main
git pull origin main

# Créer sa branche (nom selon CONTRIBUTING.md)
git checkout -b feature/<votre-domaine>
```

### Travailler et commiter

```bash
# Voir l'état
git status

# Ajouter les fichiers
git add <fichiers>

# Commit (Conventional Commits)
git commit -m "feat(scope): description courte"

# Pousser
git push -u origin feature/<votre-domaine>
```

**Types de commits** (voir [CONTRIBUTING.md](./CONTRIBUTING.md)) :

| Type | Usage |
|------|-------|
| `feat` | Nouvelle fonctionnalité |
| `fix` | Correction de bug |
| `docs` | Documentation |
| `refactor` | Refactoring sans changement de comportement |
| `test` | Ajout/modification de tests |
| `chore` | Config, dépendances, nettoyage |

**Exemples** :
- `feat(api): ajouter l'endpoint POST /predict`
- `fix(predict): corriger le warning feature names`
- `test(features): ajouter tests unitaires extract_features`

### Ouvrir une Pull Request

1. Aller sur GitHub → votre branche
2. Cliquer sur **"Compare & pull request"**
3. Remplir titre + description
4. Demander une review à `@REHARINAAngeSteven`
5. Après approbation : **"Merge pull request"**

---

## Ressources

| Ressource | Lien |
|-----------|------|
| README principal | [README.md](./README.md) |
| Conventions | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Notebook EDA (87f) | `notebooks/01_phishing_detector_pipeline.ipynb` |
| Notebook final (52f) | `notebooks/02_url_only_52_features.ipynb` |
| Feature extractor | `src/feature_extractor.py` |
| Prédiction | `src/predict.py` |
| Stress test | `tools/stress_test.py` |

### Contact

- **Chef de projet** : `@REHARINAAngeSteven`
- **Repo GitHub** : https://github.com/REHARINAAngeSteven/phishing-url-detector

---

## Checklist de démarrage

Pour chaque nouveau membre :

- [ ] J'ai cloné le repo
- [ ] J'ai créé mon `.venv` et installé les dépendances
- [ ] J'ai lancé `python tools/stress_test.py` → ça marche
- [ ] J'ai lu le README
- [ ] J'ai lu le CONTRIBUTING
- [ ] J'ai lu ce TEAM_GUIDE
- [ ] J'ai créé ma branche `feature/<mon-domaine>`
- [ ] J'ai identifié mes tâches ci-dessus
- [ ] J'ai contacté le chef de projet en cas de doute
