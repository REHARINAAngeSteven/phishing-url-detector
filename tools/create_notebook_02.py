#!/usr/bin/env python3
"""
Génère notebooks/02_url_only_52_features.ipynb programmatiquement.

Usage (depuis la racine du projet) :
    python tools/create_notebook_02.py

Le script peut être lancé depuis n'importe où : les chemins sont résolus
à partir de l'emplacement du script lui-même.
"""
import json
import os
from pathlib import Path

# Racine du projet = dossier parent de tools/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
NOTEBOOKS_DIR = PROJECT_ROOT / 'notebooks'

def md(text):
    return {"cell_type": "markdown", "metadata": {}, "source": text.splitlines(keepends=True)}

def code(text):
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": text.splitlines(keepends=True)}

cells = [
    md("""#  Pipeline URL-Only — 52 features

**Projet** : Phishing URL Detector (M1 Informatique — ENI Fianarantsoa)
**Auteur** : REHARINA Ange Steven
**Rôle** : Machine Learning & Dataset

---

##  Objectif de ce notebook

Ce notebook documente **le pipeline final retenu pour le projet** :

- Passage de **87 features originales** à **52 features URL-only**
- Entraînement du modèle final (Random Forest)
- Évaluation et export pour la production

**Différence avec `01_phishing_detector_pipeline.ipynb`** :

| Notebook | Features | Usage |
|----------|----------|-------|
| `01` | 87 (dont 21 HTML) | Exploration initiale |
| **`02`** | **52 URL-only** | **Pipeline final** |

### Pourquoi réduire ?

1. **21 features HTML** nécessitent une requête HTTP → URLs de phishing mortes
2. **Certaines features lexicales** non reproductibles (47-53% de correspondance)
3. **Résultat** : modèle qui ne dépend QUE de la chaîne URL
"""),

    code("""# Imports standards
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
import sys
import joblib
import warnings

# Imports scikit-learn
import sklearn
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)

# Imports du projet
sys.path.append('..')
sys.path.append('../src')
from src.feature_extractor import extract_features

warnings.filterwarnings('ignore')

print(f" Python     : {sys.version.split()[0]}")
print(f" pandas     : {pd.__version__}")
print(f" sklearn    : {sklearn.__version__}")
print(f" numpy      : {np.__version__}")"""),

    md("""##  Chargement du dataset réextrait

Le fichier `data/processed/dataset_reextracted_url_only.csv` a été généré par
`tools/retrain_url_only.py`. Il contient les **52 features URL-only** réextraites
depuis les URLs brutes du dataset original."""),

    code("""DATASET_PROCESSED = '../data/processed/dataset_reextracted_url_only.csv'
FEATURE_LIST      = '../models/feature_list.json'

with open(FEATURE_LIST, 'r') as f:
    feature_list = json.load(f)

print(f" Nombre de features : {len(feature_list)}")
print(f" 10 premières       : {feature_list[:10]}")

df = pd.read_csv(DATASET_PROCESSED)
print(f"\\n Dataset : {df.shape[0]} lignes × {df.shape[1]} colonnes")
df.head()"""),

    md("##  Vérification de cohérence"),

    code("""missing_features = [f for f in feature_list if f not in df.columns]
extra_features   = [c for c in df.columns if c not in feature_list + ['url', 'status']]

print(" Vérification :")
print(f"  - Manquantes : {missing_features if missing_features else ' aucune'}")
print(f"  - En trop    : {extra_features if extra_features else ' aucune'}")
print(f"\\n Valeurs manquantes : {df.isnull().sum().sum()}")
print(f"\\n Distribution :")
print(df['status'].value_counts())"""),

    md("## Visualisation de la cible"),

    code("""plt.figure(figsize=(8, 5))
counts = df['status'].value_counts()
colors = ['#2ecc71' if s == 'legitimate' else '#e74c3c' for s in counts.index]
plt.bar(counts.index, counts.values, color=colors, edgecolor='black')
plt.title('Distribution des URLs — Phishing vs Légitimes', fontsize=14)
plt.xlabel('Statut')
plt.ylabel('Nombre d\\'URLs')
for i, v in enumerate(counts.values):
    plt.text(i, v + 50, str(v), ha='center', fontweight='bold')
plt.tight_layout()
plt.show()"""),

    md("## Préparation X / y"),

    code("""X = df[feature_list].copy()
y = df['status'].copy()

le = LabelEncoder()
y_encoded = le.fit_transform(y)

print(f" X : {X.shape}")
print(f" y : {y_encoded.shape}")
print(f"   - {le.classes_[0]} → 0")
print(f"   - {le.classes_[1]} → 1")"""),

    md("##  Split Train / Test (80 / 20)"),

    code("""X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f" Split :")
print(f"  - Train : {X_train.shape[0]} lignes")
print(f"  - Test  : {X_test.shape[0]} lignes")"""),

    md("## Standardisation"),

    code("""scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

print(f" Train : mean={X_train_scaled.mean():.3f}, std={X_train_scaled.std():.3f}")
print(f" Test  : mean={X_test_scaled.mean():.3f}, std={X_test_scaled.std():.3f}")"""),

    md("## Entraînement du Random Forest"),

    code("""rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train_scaled, y_train)
y_pred = rf.predict(X_test_scaled)

print("=" * 60)
print(" RÉSULTATS — RANDOM FOREST (52 features URL-only)")
print("=" * 60)
print(f"Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision : {precision_score(y_test, y_pred):.4f}")
print(f"Recall    : {recall_score(y_test, y_pred):.4f}")
print(f"F1-Score  : {f1_score(y_test, y_pred):.4f}")
print(f"AUC-ROC   : {roc_auc_score(y_test, y_pred):.4f}")

print("\\n Classification Report :")
print(classification_report(y_test, y_pred, target_names=le.classes_))"""),

    md("## Matrice de confusion"),

    code("""cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Matrice de confusion — Random Forest (52 features)', fontsize=13)
plt.ylabel('Vrai')
plt.xlabel('Prédit')
plt.tight_layout()
plt.show()"""),

    md("## Importance des features"),

    code("""importance = pd.DataFrame({
    'feature'    : feature_list,
    'importance' : rf.feature_importances_
}).sort_values('importance', ascending=False)

print(" TOP 20 :")
print(importance.head(20).to_string(index=False))

plt.figure(figsize=(10, 8))
top20 = importance.head(20)
plt.barh(top20['feature'], top20['importance'], color='#3498db')
plt.xlabel('Importance')
plt.title('Top 20 features — Random Forest (52 URL-only)')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.show()"""),

    md("##  Validation croisée (5-fold)"),

    code("""cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=5, scoring='f1')

print(f" Validation croisée (F1) :")
print(f"  - Scores  : {[f'{s:.4f}' for s in cv_scores]}")
print(f"  - Moyenne : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")"""),

    md("""##  Comparaison 87 features vs 52 features

Rappel : le passage de 87 à 52 features **sacrifie un peu d'accuracy**
au profit de la reproductibilité et de l'indépendance au réseau."""),

    code("""comparison = pd.DataFrame({
    'Pipeline'   : ['87 features (initial)', '52 features URL-only (final)'],
    'Features'   : [87, 52],
    'Accuracy'   : [0.9506, accuracy_score(y_test, y_pred)],
    'F1-Score'   : [0.9507, f1_score(y_test, y_pred)],
    'Production' : [' HTML requis', ' URL seule']
})

print(" COMPARAISON DES PIPELINES :")
print(comparison.to_string(index=False))"""),

    md("##  Test de prédiction en direct"),

    code("""def predict_url(url, model=rf, scaler=scaler, encoder=le, features=feature_list):
    feats = extract_features(url, feature_order=features)
    x = np.array([feats])
    x_scaled = scaler.transform(x)
    pred = model.predict(x_scaled)[0]
    proba = model.predict_proba(x_scaled)[0]
    return {
        'url'         : url,
        'prediction'  : encoder.inverse_transform([pred])[0],
        'confidence'  : float(max(proba)),
        'proba_phish' : float(proba[encoder.transform(['phishing'])[0]]),
    }

test_urls = [
    "https://www.google.com",
    "https://github.com/features/copilot",
    "http://paypal-secure-login.xyz/verify?id=12345",
    "http://192.168.1.1/login.php",
    "https://www.wikipedia.org/wiki/Phishing",
]

print(" TESTS DE PRÉDICTION EN DIRECT :\\n")
for url in test_urls:
    try:
        r = predict_url(url)
        icon = "🔴" if r['prediction'] == 'phishing' else "🟢"
        print(f"{icon} {r['prediction'].upper():10s} (confiance {r['confidence']:.1%}) — {url}")
    except Exception as e:
        print(f" ERREUR pour {url} : {e}")"""),

    md("## Sauvegarde du modèle final"),

    code("""os.makedirs('../models', exist_ok=True)

joblib.dump(rf,     '../models/best_model.joblib')
joblib.dump(scaler, '../models/scaler.joblib')
joblib.dump(le,     '../models/label_encoder.joblib')

with open('../models/feature_list.json', 'w') as f:
    json.dump(feature_list, f, indent=2)

print(" Modèle sauvegardé dans models/")
for f in ['best_model.joblib', 'scaler.joblib', 'label_encoder.joblib', 'feature_list.json']:
    size = os.path.getsize(f'../models/{f}') / 1024
    print(f"   - {f} ({size:.1f} KB)")"""),

    md("""## Conclusion

| Étape | Résultat |
|-------|----------|
| Features | 52 URL-only |
| Modèle | Random Forest (200 arbres) |
| Accuracy | ~83% |
| F1-Score | ~83% |
| Inférence | < 1 ms, 100% locale |

### Justification du compromis

- Reproductible : aucune dépendance au site cible
- Robuste : fonctionne même sur URLs mortes
- Cohérent : train et serve utilisent le **même** extracteur
- Compromis : -12% accuracy vs pipeline HTML, mais utilisable en réel
"""),
]

nb = {
    "cells": cells,
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3 (ipykernel)",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.12.14"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 5
}

# Créer le dossier notebooks/ s'il n'existe pas
NOTEBOOKS_DIR.mkdir(parents=True, exist_ok=True)

# Chemin de sortie absolu
out = NOTEBOOKS_DIR / '02_url_only_52_features.ipynb'
with open(out, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f" Notebook créé : {out}")
print(f" Nombre de cellules : {len(cells)}")
