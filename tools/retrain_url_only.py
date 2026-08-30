"""
tools/retrain_url_only.py

Ré-extrait les 52 features calculables uniquement depuis la chaîne d'URL
(aucune requête HTTP nécessaire) avec src/feature_extractor.py, sur
data/raw/dataset_phishing.csv, puis réentraîne un Random Forest avec les
mêmes hyperparamètres que le notebook d'origine.

Pourquoi 52 et pas 79 :
  - 21 features dépendent du contenu HTML de la page (nb_hyperlinks,
    login_form, iframe, etc.). Le dataset date de 2020-2021 : une large
    part des URLs de phishing qu'il contient sont mortes depuis longtemps.
    Les ré-extraire aujourd'hui produirait des valeurs neutres (0) sur la
    quasi-totalité de la classe phishing -> signal détruit, pas réparé.
  - 6 features sont des constantes à 0 dans ce dataset (nb_or,
    ratio_nullHyperlinks, ratio_intRedirection, ratio_intErrors,
    submit_email, sfh) : aucune valeur prédictive, on les exclut.
  - Les 52 restantes (lexicales + parsing de domaine) sont calculables à
    partir de la seule chaîne d'URL, de façon strictement identique à
    l'entraînement et à la prédiction -> plus de skew train/serve, plus
    besoin de requête réseau ni à l'entraînement ni en production.

Usage :
    python tools/retrain_url_only.py
"""

import json
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

import sys
sys.path.insert(0, "src")
import feature_extractor as fe

CSV_PATH = "data/raw/dataset_phishing.csv"
FULL_FEATURE_LIST_PATH = "models/feature_list.json"
CONSTANT_FEATURES = {
    "nb_or", "ratio_nullHyperlinks", "ratio_intRedirection",
    "ratio_intErrors", "submit_email", "sfh",
}


def build_url_only_feature_list():
    with open(FULL_FEATURE_LIST_PATH, encoding="utf-8") as f:
        full = json.load(f)
    return [f for f in full if f not in fe.FEATURES_NEEDING_HTML and f not in CONSTANT_FEATURES]


def reextract(df, feature_order):
    rows, errors = [], 0
    t0 = time.time()
    for i, url in enumerate(df["url"]):
        try:
            rows.append(fe.extract_features(url, feature_order=feature_order))
        except Exception:
            errors += 1
            rows.append([0.0] * len(feature_order))
        if (i + 1) % 2000 == 0:
            print(f"  {i + 1}/{len(df)} ({time.time() - t0:.1f}s)")
    print(f"Extraction terminée en {time.time() - t0:.1f}s, {errors} erreurs")
    return pd.DataFrame(rows, columns=feature_order)


def main():
    print("=" * 70)
    print("RÉ-EXTRACTION + RÉENTRAÎNEMENT — features URL-only (self-extracted)")
    print("=" * 70)

    df = pd.read_csv(CSV_PATH)
    print(f"{len(df)} URLs chargées depuis {CSV_PATH}")

    feature_order = build_url_only_feature_list()
    print(f"{len(feature_order)} features retenues (URL-only, sans HTML, sans constantes)")

    Path("models").mkdir(exist_ok=True)
    Path("data/processed").mkdir(parents=True, exist_ok=True)

    X = reextract(df, feature_order)
    y = df["status"]

    # Sauvegarde du dataset ré-extrait, pour audit / réutilisation future
    out = X.copy()
    out["url"] = df["url"].values
    out["status"] = y.values
    out.to_csv("data/processed/dataset_reextracted_url_only.csv", index=False)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f"Encodage : legitimate -> {le.transform(['legitimate'])[0]}, "
          f"phishing -> {le.transform(['phishing'])[0]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Mêmes hyperparamètres que le Random Forest du notebook original,
    # pour rester comparable.
    rf = RandomForestClassifier(
        n_estimators=100, random_state=42, max_depth=10,
        min_samples_split=5, n_jobs=-1,
    )
    rf.fit(X_train_s, y_train)
    y_pred = rf.predict(X_test_s)

    print("\n" + "=" * 60)
    print("PERFORMANCES — Random Forest, features URL-only")
    print("=" * 60)
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"AUC-ROC:   {roc_auc_score(y_test, y_pred):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    fi = pd.DataFrame({
        "feature": X.columns, "importance": rf.feature_importances_,
    }).sort_values("importance", ascending=False)
    print("TOP 15 FEATURES :")
    print(fi.head(15).to_string(index=False))

    joblib.dump(rf, "models/best_model.joblib")
    joblib.dump(scaler, "models/scaler.joblib")
    joblib.dump(le, "models/label_encoder.joblib")
    with open("models/feature_list.json", "w", encoding="utf-8") as f:
        json.dump(feature_order, f, indent=2)

    print(f"\n✅ Modèle, scaler, label encoder et feature_list.json ({len(feature_order)} "
          f"features) sauvegardés dans models/")
    print("⚠️  ATTENTION : ceci écrase l'ancien models/best_model.joblib (79 features). "
          "Fais une copie avant si tu veux garder l'ancien pour comparaison.")


if __name__ == "__main__":
    main()