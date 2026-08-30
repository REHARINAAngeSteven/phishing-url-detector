"""
tools/validate_against_dataset.py

Compare les valeurs produites par feature_extractor.py aux valeurs réelles
du dataset, pour les features 🟢 (URL seule) et 🟡 (parsing domaine) —
PAS pour les 🟠 (HTML), puisque le contenu des pages a pu changer depuis
la création du dataset (comparaison non pertinente pour ces 21 features).

Usage :
    cd phishing-url-detector
    python tools/validate_against_dataset.py --n 200

Pour chaque feature, affiche le taux de correspondance exacte (ou proche,
pour les floats). Toute feature sous ~95% de correspondance doit être
revue en priorité — c'est probablement une des features marquées AMBIGU
dans feature_extractor.py dont la définition doit être ajustée.
"""

import argparse
import math
import sys

import pandas as pd

sys.path.insert(0, "src")
from feature_extractor import FEATURE_FUNCTIONS, URLContext  # noqa: E402

# Features 🟠 (HTML) exclues : non comparables à un dataset figé dans le temps
FEATURES_TO_SKIP = {
    "nb_redirection", "nb_external_redirection", "nb_hyperlinks", "ratio_intHyperlinks",
    "ratio_extHyperlinks", "nb_extCSS", "ratio_extRedirection", "ratio_extErrors", "login_form",
    "external_favicon", "links_in_tags", "ratio_intMedia", "ratio_extMedia", "iframe",
    "popup_window", "safe_anchor", "onmouseover", "right_clic", "empty_title",
    "domain_in_title", "domain_with_copyright",
}


def values_match(computed, expected, tol=1e-6) -> bool:
    try:
        return math.isclose(float(computed), float(expected), abs_tol=tol, rel_tol=1e-4)
    except (TypeError, ValueError):
        return computed == expected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="data/raw/dataset_phishing.csv")
    parser.add_argument("--n", type=int, default=200, help="Nombre de lignes à échantillonner")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    sample = df.sample(n=min(args.n, len(df)), random_state=args.seed)

    features_to_check = [f for f in FEATURE_FUNCTIONS if f not in FEATURES_TO_SKIP and f in df.columns]

    match_counts = {f: 0 for f in features_to_check}
    mismatch_examples = {f: [] for f in features_to_check}
    total = 0

    for _, row in sample.iterrows():
        url = row["url"]
        ctx = URLContext(url, fetch_html=False)
        total += 1
        for f in features_to_check:
            computed = FEATURE_FUNCTIONS[f](ctx)
            expected = row[f]
            if values_match(computed, expected):
                match_counts[f] += 1
            elif len(mismatch_examples[f]) < 3:
                mismatch_examples[f].append((url, computed, expected))

    print(f"\nValidation sur {total} URLs échantillonnées depuis {args.csv}\n")
    print(f"{'Feature':25s} {'Correspondance':>15s}   Statut")
    print("-" * 70)

    results = sorted(features_to_check, key=lambda f: match_counts[f] / total)
    for f in results:
        rate = match_counts[f] / total * 100
        if rate >= 99:
            status = "✅"
        elif rate >= 90:
            status = "⚠️  à surveiller"
        else:
            status = "❌ À CORRIGER"
        print(f"{f:25s} {rate:14.1f}%   {status}")

    print("\n--- Détail des features à corriger en priorité (< 90%) ---")
    for f in results:
        rate = match_counts[f] / total * 100
        if rate < 90:
            print(f"\n{f} ({rate:.1f}% de correspondance) — exemples de divergence :")
            for url, computed, expected in mismatch_examples[f]:
                print(f"   URL: {url}")
                print(f"     calculé={computed}  vs  attendu={expected}")


if __name__ == "__main__":
    main()
