"""
tools/stress_test.py

Fait passer une batterie d'URLs variées (légitimes "difficiles", phishing
typiques, cas limites) dans le modèle courant, pour voir où il tient et où
il casse. Ce n'est PAS une mesure d'accuracy rigoureuse (échantillon non
représentatif, choisi à la main) — c'est un test de robustesse qualitatif,
utile pour repérer des angles morts avant la soutenance.

Usage :
    python tools/stress_test.py
"""

import sys
sys.path.insert(0, "src")
import warnings
warnings.filterwarnings("ignore")

import joblib
import numpy as np

import feature_extractor as fe

MODEL_PATH = "models/best_model.joblib"
SCALER_PATH = "models/scaler.joblib"
LABEL_ENCODER_PATH = "models/label_encoder.joblib"
FEATURE_LIST_PATH = "models/feature_list.json"

# Chaque entrée : (url, label_attendu ou None si incertain/piège)
TEST_CASES = [
    # --- Grandes marques légitimes, cas simples ---
    ("https://www.google.com", "legitimate"),
    ("https://www.wikipedia.org", "legitimate"),
    ("https://github.com", "legitimate"),
    ("https://www.amazon.com", "legitimate"),

    # --- Légitimes mais "difficiles" structurellement ---
    ("https://docs.google.com/document/d/1a2b3c4d5e6f7g8h9i0j/edit", "legitimate"),  # sous-domaine + ID long
    ("https://mail.google.com/mail/u/0/#inbox", "legitimate"),  # plusieurs sous-niveaux
    ("https://en.wikipedia.org/wiki/Machine_learning", "legitimate"),  # underscore
    ("https://chatgpt.com/c/6a92d7ed-9f68-83ea-9b3b-65263681c3df", "legitimate"),  # UUID moderne
    ("https://claude.ai/chat/6a92d7ed-9f68-83ea-9b3b-65263681c3df", "legitimate"),  # UUID moderne
    ("https://www.notion.so/My-Workspace-Page-a1b2c3d4e5f64a7b8c9d0e1f2a3b4c5d", "legitimate"),  # ID hex long
    ("https://news.ycombinator.com/item?id=38452901", "legitimate"),
    ("https://www.nytimes.com/2026/08/29/technology/some-long-article-slug-with-many-hyphens.html", "legitimate"),  # tirets multiples
    ("https://stackoverflow.com/questions/12345678/how-to-do-x-in-y-with-z", "legitimate"),  # tirets multiples

    # --- Gouvernement / institutionnel (TLD rares, souvent mal vus) ---
    ("https://www.impots.gouv.fr", "legitimate"),
    ("https://www.usa.gov", "legitimate"),

    # --- Phishing typiques (imitation de marque) ---
    ("http://paypal.com.secure-login.xyz", "phishing"),
    ("http://www.paypal-account-verify.tk", "phishing"),
    ("http://secure-appleid-support.com-verify.info", "phishing"),
    ("http://banking.secure-update.xyz", "phishing"),
    ("http://amaz0n-account-suspended.com", "phishing"),  # typosquat chiffre/lettre

    # --- Phishing via IP / obfuscation ---
    ("http://192.168.1.100/login/verify-account.php", "phishing"),
    ("http://45.33.32.156/paypal/signin", "phishing"),

    # --- Phishing structurel (beaucoup de sous-domaines / tirets) ---
    ("http://login-secure-paypal-account-update.verify-user.tk", "phishing"),
    ("http://www.paypal.com.login.verify.account.update.suspicious-domain.ru", "phishing"),

    # --- Raccourcisseurs d'URL (ambigu par nature) ---
    ("https://bit.ly/3xK9pQr", None),
    ("https://tinyurl.com/2p8x7k3m", None),

    # --- Cas limites structurels ---
    ("https://example.com:8080/admin/login.php", None),  # port non standard
    ("http://xn--pypal-4ve.com/login", None),  # punycode homographe (paypal avec caractère spécial)
    ("https://a.b.c.d.e.f.example.com/path", None),  # empilement de sous-domaines
    ("https://example.com/" + "a" * 200, None),  # URL très longue
]


def main():
    feature_order = fe.load_feature_order(FEATURE_LIST_PATH)
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER_PATH)
    phishing_idx = list(le.classes_).index("phishing")

    print(f"{'URL':70s} {'Attendu':12s} {'Prédit':12s} {'P(phishing)':>12s}  Résultat")
    print("-" * 125)

    correct, total_with_label = 0, 0
    for url, expected in TEST_CASES:
        vals = fe.extract_features(url, feature_order=feature_order)
        X = np.array(vals).reshape(1, -1)
        X_s = scaler.transform(X)
        proba = model.predict_proba(X_s)[0]
        pred = le.inverse_transform([np.argmax(proba)])[0]
        p_phishing = proba[phishing_idx] * 100

        if expected is None:
            flag = "?"
        elif pred == expected:
            flag = "OK"
            correct += 1
            total_with_label += 1
        else:
            flag = "*** ERREUR ***"
            total_with_label += 1

        display_url = url if len(url) <= 68 else url[:65] + "..."
        print(f"{display_url:70s} {str(expected):12s} {pred:12s} {p_phishing:11.1f}%  {flag}")

    if total_with_label:
        print("-" * 125)
        print(f"Score sur cas étiquetés : {correct}/{total_with_label} "
              f"({correct / total_with_label * 100:.1f}%)")
    print("\n'?' = cas ambigu/piège volontaire, pas de bonne réponse évidente — "
          "à examiner à l'œil plutôt qu'à noter.")


if __name__ == "__main__":
    main()
