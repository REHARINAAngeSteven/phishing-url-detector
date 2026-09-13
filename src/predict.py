"""
predict.py — Phishing URL Detector

Pipeline complet : URL -> features (selon feature_list.json) -> scaler -> Random Forest -> prédiction.

Usage en CLI :
    python src/predict.py "http://example.com/login"

Usage en import :
    from predict import predict_url
    result = predict_url("http://example.com/login")
    # {'url': ..., 'prediction': 'phishing'|'legitimate', 'probability_phishing': 0.87, ...}
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import extract_features, load_feature_order  # noqa: E402

MODELS_DIR = Path(__file__).parent.parent / "models"


class PhishingPredictor:
    """Charge le modèle une seule fois (utile pour une API : éviter de recharger
    à chaque requête) et expose predict(url)."""

    def __init__(self, models_dir: Path = MODELS_DIR):
        self.model = joblib.load(models_dir / "best_model.joblib")
        self.scaler = joblib.load(models_dir / "scaler.joblib")
        self.label_encoder = joblib.load(models_dir / "label_encoder.joblib")
        self.feature_order = load_feature_order(str(models_dir / "feature_list.json"))

        # Garde-fou : le contrat modèle/scaler/feature_list doit être cohérent
        # (cf. l'audit qu'on a fait avant de commencer l'extraction).
        if self.model.n_features_in_ != len(self.feature_order):
            raise ValueError(
                f"Incohérence : le modèle attend {self.model.n_features_in_} features, "
                f"mais feature_list.json en contient {len(self.feature_order)}."
            )
        if self.scaler.n_features_in_ != len(self.feature_order):
            raise ValueError(
                f"Incohérence : le scaler attend {self.scaler.n_features_in_} features, "
                f"mais feature_list.json en contient {len(self.feature_order)}."
            )

    def predict(self, url: str) -> dict:
        raw_features = extract_features(url, feature_order=self.feature_order)
        # DataFrame nommé (pas un simple array) : élimine le warning sklearn ET
        # garantit que l'alignement se fait par nom de colonne, pas seulement
        # par position — une sécurité de plus dans la même logique que l'audit.
        X = pd.DataFrame([raw_features], columns=self.feature_order)
        X_scaled = self.scaler.transform(X)

        pred_encoded = self.model.predict(X_scaled)[0]
        pred_label = self.label_encoder.inverse_transform([pred_encoded])[0]

        proba = None
        proba_phishing = None
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X_scaled)[0]
            # Retrouver quel index de classe correspond à "phishing"
            phishing_idx = list(self.label_encoder.classes_).index("phishing")
            proba_phishing = float(proba[phishing_idx])

        return {
            "url": url,
            "prediction": str(pred_label),
            "probability_phishing": proba_phishing,
            "features": dict(zip(self.feature_order, raw_features)),
        }


_predictor_singleton = None


def predict_url(url: str) -> dict:
    """Point d'entrée simple pour un usage ponctuel (recharge le modèle si besoin)."""
    global _predictor_singleton
    if _predictor_singleton is None:
        _predictor_singleton = PhishingPredictor()
    return _predictor_singleton.predict(url)


def main():
    parser = argparse.ArgumentParser(description="Prédire si une URL est du phishing.")
    parser.add_argument("url", help="URL à analyser")
    parser.add_argument("--show-features", action="store_true", help="Afficher les valeurs de features extraites")
    args = parser.parse_args()

    result = predict_url(args.url)

    print(f"\nURL : {result['url']}")
    print(f"Prédiction : {result['prediction'].upper()}")
    if result["probability_phishing"] is not None:
        print(f"Probabilité de phishing : {result['probability_phishing']:.1%}")

    if args.show_features:
        print("\nFeatures extraites :")
        for name, value in result["features"].items():
            print(f"  {name:30s} = {value}")


if __name__ == "__main__":
    main()