# 🔐 Phishing URL Detector

Détection automatique des URLs de phishing à l'aide du Machine Learning.

> ⛔ In development

---
## ⚙️ Installation / Setup

### Prérequis
- Python 3.12
- Un compte Kaggle (pour télécharger le dataset) des fois démandés mais pas contraignant

### 1. Cloner le repo et installer les dépendances

```bash
git clone https://github.com/REHARINAAngeSteven/phishing-url-detector.git
cd phishing-url-detector
python3 -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate sous Windows
pip install -r requirements.txt
```

### 2. Récupérer le dataset

Télécharger le **Web Page Phishing Detection Dataset** (Hannousse & Yahiouche) depuis Kaggle :

👉 [https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset]

Renommer le fichier CSV téléchargé en `dataset_phishing.csv` et le placer dans :

```text
data/raw/dataset_phishing.csv
```

> Le dossier `data/raw/` n'est pas versionné (voir `.gitignore`) : ce fichier doit être ajouté manuellement par chaque personne qui clone le repo.

### 3. Générer les fichiers modèle

```bash
python tools/retrain_url_only.py
```

Ce script régénère, dans `models/` :
- `best_model.joblib`
- `scaler.joblib`
- `label_encoder.joblib`
- `feature_list.json`

(eux non plus non versionnés — voir `.gitignore` — donc à régénérer localement après chaque clone)

### 4. Vérifier que tout fonctionne

```bash
python tools/stress_test.py
```

Doit afficher un score d'environ 87-88% sur les cas étiquetés.
Les cas en erreur sont des faux positifs sur des URLs légitimes contenant
des identifiants longs (voir section "Limitation connue").

## 🔬 De 87 features à 52 features URL-only

Le dataset utilisé dans ce projet est le **Web Page Phishing Detection Dataset**, disponible sur Kaggle et provenant des travaux de Hannousse & Yahiouche.

Le dataset original contient **11 430 URLs et 87 features**. Ces features sont réparties en trois catégories :

| Catégorie               | Nombre | Description                                                                 |
| ----------------------- | -----: | --------------------------------------------------------------------------- |
| 🌐 Features URL         | **56** | Informations calculables à partir de la structure et de la syntaxe de l'URL |
| 🖥️ Features de contenu | **24** | Informations extraites du contenu HTML de la page                           |
| 🔎 Services externes    |  **7** | Informations obtenues via des services externes                             |
| **Total**               | **87** |                                                                             |

Le dataset est équilibré : **5 715 URLs légitimes et 5 715 URLs de phishing**.

### 📉 Étape 1 — Réduction de 87 à 79 features

Avant de construire notre modèle, nous avons effectué une première analyse des features afin d'identifier celles qui étaient inutilisables, redondantes ou sans intérêt pour notre pipeline.

Cette première sélection a permis de passer de :

```text
87 features originales
        ↓
79 features conservées
```

Ces **79 features** constituaient donc la base du pipeline initial de notre projet.

> ⚠️ Il est important de distinguer les **87 features originales du dataset** des **79 features retenues dans notre premier pipeline**.

---

## 🚧 Pourquoi ne pas conserver les 79 features ?

Le pipeline à 79 features présentait cependant deux problèmes importants.

### 1. 🖥️ Dépendance au contenu HTML

Parmi les 79 features, **21 nécessitaient d'accéder au contenu de la page cible**.

Cela implique, pour une simple prédiction :

```text
URL
 ↓
Requête HTTP
 ↓
Chargement de la page
 ↓
Récupération du HTML
 ↓
Extraction des features
 ↓
Modèle ML
 ↓
Prédiction
```

Cette approche pose problème avec notre dataset.

Le dataset a été construit en **mai 2020**, puis publié dans différentes versions, dont la version 3 en 2021.

Une grande partie des URLs de phishing de cette époque ne sont aujourd'hui plus accessibles.

Lorsqu'une URL morte est testée aujourd'hui, il devient impossible de récupérer son contenu HTML :

```text
URL de phishing historique
          ↓
   Site inaccessible
          ↓
     Pas de HTML
          ↓
Features HTML = valeurs neutres / 0
          ↓
   Signal de phishing perdu
```

Le problème n'est donc pas simplement technique : les informations utilisées pendant l'entraînement ne peuvent plus nécessairement être reproduites au moment de la prédiction.

---

### 2. ⚠️ Incohérence entre l'entraînement et la prédiction

Certaines features lexicales du pipeline initial, notamment :

```text
char_repeat
avg_words_raw
shortest_words_raw
length_words_raw
longest_words_raw
```

n'ont pas pu être reproduites avec une correspondance exacte avec le pipeline d'origine.

Les tests réalisés avec :

```text
tools/calibrate_features.py
```

ont montré une correspondance d'environ **47 à 53 %** pour certaines de ces features.

La définition exacte de certaines caractéristiques n'étant pas suffisamment documentée pour notre reproduction, le modèle pouvait recevoir des valeurs différentes entre :

```text
ENTRAÎNEMENT
URL
 ↓
Ancienne extraction
 ↓
Modèle
```

et :

```text
PRODUCTION
URL
 ↓
Notre extraction
 ↓
Modèle
```

Cela crée un **train/serve skew** : le modèle n'interprète plus nécessairement les valeurs reçues en production de la même manière que celles vues pendant son entraînement.

---

# ✅ Étape 2 — Passage à 52 features URL-only

Pour résoudre ces problèmes, nous avons décidé de reconstruire le pipeline autour d'un principe simple :

> **Une URL doit pouvoir être analysée uniquement à partir de sa chaîne de caractères, sans visiter le site.**

Nous avons donc :

1. repris les features du pipeline à 79 features ;
2. réimplémenté leur extraction dans :

   ```text
   src/feature_extractor.py
   ```
3. supprimé les **21 features nécessitant le HTML** ;
4. supprimé également **6 features constantes**, qui étaient toujours à `0` dans notre dataset et n'apportaient donc aucune information prédictive.

On obtient finalement :

```text
87 features originales
        ↓
79 features après première sélection
        ↓
- 21 features HTML
        ↓
- 6 features constantes
        ↓
52 features URL-only
```

### 🎯 Résultat final

Le modèle est donc entraîné avec **52 features**, toutes calculables directement à partir de l'URL.

| Métrique | Valeur |
|----------|--------|
| **Accuracy** | **90.2%** |
| **F1-Score** | **90.2%** |
| **Validation croisée (F1)** | 89.3% ± 0.9% |
| **Stress test** | 87.5% sur cas étiquetés |
| **Features** | 52 (URL-only) |
| **Temps d'inférence** | < 1 ms / URL |
| **Dépendance réseau** | ❌ Aucune |
| **Taille du modèle** | 20 MB |

```text
                     URL
                      │
                      ▼
          ┌─────────────────────┐
          │ feature_extractor   │
          └──────────┬──────────┘
                     │
                     ▼
              52 features
                     │
                     ▼
          ┌─────────────────────┐
          │    Modèle ML        │
          └──────────┬──────────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
         LEGITIMATE       PHISHING
```

Aucune requête réseau n'est nécessaire pour effectuer une prédiction.

---

## 📊 Comparaison des différentes étapes

| Étape              | Nombre de features | Particularité                                            |
| ------------------ | -----------------: | -------------------------------------------------------- |
| Dataset original   |             **87** | Dataset Kaggle complet                                   |
| Première sélection |             **79** | Features conservées pour le pipeline initial             |
| Pipeline URL-only  |             **52** | Suppression des 21 features HTML + 6 features constantes |
| **Modèle final**   |             **52** | Analyse uniquement à partir de l'URL                     |

---

## ⚖️ Pourquoi accepter une accuracy plus faible ?

Le modèle à 79 features pouvait exploiter davantage d'informations, notamment le contenu des pages.

Cependant, cette approche est difficile à reproduire de manière fiable sur des URLs réelles et anciennes.

Le modèle final à 52 features fait un compromis volontaire :

> **Nous préférons un modèle légèrement moins performant sur le dataset de référence, mais dont le comportement est cohérent, reproductible et indépendant du réseau.**

Notre objectif n'est donc pas uniquement d'obtenir la meilleure accuracy possible sur le dataset.

Nous cherchons également à obtenir un système qui puisse réellement fonctionner selon le principe :

```text
URL
 ↓
Extraction locale
 ↓
Prédiction
```

sans :

```text
❌ requête HTTP
❌ téléchargement HTML
❌ dépendance au site distant
❌ dépendance à un service externe
```

---

## ⚠️ Limitation connue

Le modèle présente une **faiblesse** sur les URLs contenant :

- des identifiants longs et alphanumériques dans le chemin
- des tokens de session
- des UUIDs / hashs
- des IDs numériques longs

### 📊 Mesure de la limitation

Le stress test (`tools/stress_test.py`) sur 24 cas étiquetés montre
**3 faux positifs** (~12.5%) :

| URL légitime classée phishing | P(phishing) |
|-------------------------------|-------------|
| `docs.google.com/document/d/1a2b3c4d...` | 78.3% |
| `notion.so/My-Workspace-Page-a1b2c3d4e5f6...` | 86.7% |
| `news.ycombinator.com/item?id=38452901` | 70.6% |

Ces 3 URLs contiennent toutes des identifiants longs qui déclenchent les
features `length_words_raw`, `longest_words_raw`, `char_repeat` ou
`ratio_digits_url`.

### 🔍 Cause

Le dataset historique (Hannousse & Yahiouche, 2020) est antérieur à la
généralisation des UUIDs et tokens modernes (Notion, Google Docs, etc.).
Le modèle a donc appris que "chaîne longue et aléatoire = suspect".

### 🎯 Piste d'amélioration

Entraîner le modèle sur un dataset plus récent, ou ajouter une feature
`has_uuid_pattern` qui distingue les identifiants légitimes des chaînes
aléatoires suspectes.

### Reproduire

```bash
python tools/stress_test.py
```
---

## 🧠 Résumé du choix architectural

```text
                 DATASET ORIGINAL
                 87 FEATURES
                      │
                      ▼
             Première sélection
                      │
                      ▼
                 79 FEATURES
                      │
             ┌────────┴────────┐
             │                 │
        Features HTML     Features utiles
             │                 │
             ▼                 │
          -21                 │
                               │
        Features constantes    │
             │                 │
             ▼                 │
           -6                  │
             └────────┬────────┘
                      ▼
                52 FEATURES
                 URL-ONLY
                      │
                      ▼
                MODÈLE FINAL
                      │
                      ▼
              PRÉDICTION LOCALE
```

### 🎯 Principe retenu

**87 → 79 → 52**

Le passage à 52 features n'est donc pas une simple suppression arbitraire de caractéristiques.

C'est le résultat de plusieurs étapes de sélection visant à obtenir un modèle :

* 🔒 indépendant du contenu des pages ;
* 🌐 indépendant du réseau ;
* ⚡ rapide à l'inférence ;
* 🔄 reproductible ;
* 🧪 cohérent entre entraînement et production ;
* 🛠️ facilement réentraînable à partir du dataset.
