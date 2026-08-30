"""
tools/calibrate_features.py

Pour les features où la définition exacte reste incertaine après inspection
manuelle (tokenisation des mots, notamment), ce script teste PLUSIEURS
hypothèses candidates contre le dataset réel et affiche laquelle correspond
le mieux — plutôt que de deviner une seule formule à l'aveugle.

Usage :
    python tools/calibrate_features.py --n 500

Pour chaque famille de features (mots bruts, mots du hostname), affiche le
taux de correspondance de chaque variante candidate, triées de la meilleure
à la pire. Une fois la meilleure variante identifiée, reporter la formule
gagnante dans src/feature_extractor.py.
"""

import argparse
import itertools
import re
import sys

import pandas as pd

sys.path.insert(0, "src")
from feature_extractor import _TLD_EXTRACTOR  # noqa: E402


def _tokenize(s, delimiters=r"[^a-zA-Z0-9]"):
    return [w for w in re.split(delimiters, s) if w]


def _stats(words):
    if not words:
        return 0, 0, 0, 0.0
    lengths = [len(w) for w in words]
    return len(words), min(lengths), max(lengths), sum(lengths) / len(lengths)


# ---------------------------------------------------------------------------
# Candidats pour la famille "words_raw" (length_words_raw, avg_words_raw,
# shortest_words_raw, longest_words_raw dérivent tous de la même liste de mots)
# ---------------------------------------------------------------------------

def _split_letter_digit(s):
    """Découpe aussi aux transitions lettre<->chiffre (ex: 'index2' -> 'index','2')."""
    parts = _tokenize(s)
    out = []
    for p in parts:
        out.extend(re.findall(r"[a-zA-Z]+|[0-9]+", p))
    return out


def words_raw_candidates(url):
    ext = _TLD_EXTRACTOR(url)
    no_scheme = re.sub(r"^[a-zA-Z]+://", "", url, count=1)
    no_scheme_no_www = re.sub(r"^www\.", "", no_scheme)

    candidates = {
        "V1_full_url_as_is": _tokenize(url),
        "V2_sans_schema": _tokenize(no_scheme),
        "V3_sans_schema_sans_www": _tokenize(no_scheme_no_www),
        "V4_sans_schema_sans_www_delims_reduits": _tokenize(
            no_scheme_no_www, delimiters=r"[\-\./\?=&%:_]"
        ),
        "V6_sans_schema_sans_www_split_lettre_chiffre": _split_letter_digit(no_scheme_no_www),
        "V7_full_url_split_lettre_chiffre": _split_letter_digit(url),
    }
    suffix_labels = set(ext.suffix.split(".")) if ext.suffix else set()
    v5 = [w for w in _tokenize(no_scheme_no_www) if w.lower() not in suffix_labels]
    candidates["V5_sans_schema_sans_www_sans_suffixe"] = v5
    return candidates


# ---------------------------------------------------------------------------
# Candidats pour nb_subdomains et char_repeat (valeurs simples, pas des listes)
# ---------------------------------------------------------------------------

def nb_subdomains_candidates(url):
    ext = _TLD_EXTRACTOR(url)
    hostname = re.sub(r"^[a-zA-Z]+://", "", url, count=1).split("/")[0]
    no_scheme = re.sub(r"^[a-zA-Z]+://", "", url, count=1)

    return {
        "dots_hostname": hostname.count("."),
        "dots_hostname_plus_1": hostname.count(".") + 1,
        "dots_url_entiere_sans_schema": no_scheme.count("."),
        "labels_hostname_moins_2": max(0, len(hostname.split(".")) - 2),
        "labels_subdomain_tldextract": len([p for p in ext.subdomain.split(".") if p]),
        "labels_subdomain_tldextract_plus_1": len([p for p in ext.subdomain.split(".") if p]) + 1,
    }


def char_repeat_candidates(url):
    no_scheme = re.sub(r"^[a-zA-Z]+://", "", url, count=1)

    def longest_run(s, min_run=1):
        longest = 0
        for _, group in itertools.groupby(s):
            run_len = len(list(group))
            if run_len >= min_run:
                longest = max(longest, run_len)
        return longest

    def count_double_occurrences(s):
        return sum(1 for i in range(len(s) - 1) if s[i] == s[i + 1])

    def most_frequent_char_count(s):
        s = s.lower()
        if not s:
            return 0
        from collections import Counter
        return Counter(c for c in s if c.isalnum()).most_common(1)[0][1]

    return {
        "run_max_sans_schema_seuil2": longest_run(no_scheme, min_run=2),
        "run_max_url_complete_seuil2": longest_run(url, min_run=2),
        "run_max_sans_schema_seuil1": longest_run(no_scheme, min_run=1),
        "nb_doublons_consecutifs_sans_schema": count_double_occurrences(no_scheme),
        "char_le_plus_frequent_sans_schema": most_frequent_char_count(no_scheme),
    }


def evaluate_single_value(df, candidates_fn, feature_name):
    candidate_names = None
    scores = {}
    total = 0

    for _, row in df.iterrows():
        url = row["url"]
        candidates = candidates_fn(url)
        if candidate_names is None:
            candidate_names = list(candidates.keys())
            scores = {name: 0 for name in candidate_names}
        expected = row[feature_name]
        total += 1
        for name, value in candidates.items():
            try:
                match = abs(float(value) - float(expected)) < 1e-6
            except (TypeError, ValueError):
                match = value == expected
            if match:
                scores[name] += 1

    print(f"\n{'Candidat':45s}{'Correspondance':>15s}")
    for name in sorted(candidate_names, key=lambda n: -scores[n]):
        print(f"{name:45s}{scores[name] / total * 100:14.1f}%")


# ---------------------------------------------------------------------------
# Candidats pour la famille "words_host" (avg_word_host, shortest_word_host,
# longest_word_host)
# ---------------------------------------------------------------------------

def words_host_candidates(url):
    ext = _TLD_EXTRACTOR(url)
    hostname = re.sub(r"^[a-zA-Z]+://", "", url, count=1).split("/")[0]
    hostname_no_www = re.sub(r"^www\.", "", hostname)

    candidates = {
        "H1_hostname_complet_split_non_alnum": _tokenize(hostname),
        "H2_hostname_sans_www_split_non_alnum": _tokenize(hostname_no_www),
        "H3_hostname_complet_split_point_seul": [p for p in hostname.split(".") if p],
        "H4_hostname_sans_www_split_point_seul": [p for p in hostname_no_www.split(".") if p],
        "H5_domaine_seul_tldextract": [ext.domain] if ext.domain else [],
    }
    # H6 : labels du sous-domaine + domaine (registrable), en excluant le suffixe, split par '.'
    registrable_no_suffix = ".".join(p for p in [ext.subdomain, ext.domain] if p)
    candidates["H6_subdomain_plus_domaine_sans_suffixe_split_point"] = [
        p for p in registrable_no_suffix.split(".") if p
    ]
    return candidates


def evaluate_family(df, candidates_fn, target_features, n_report=3):
    """
    target_features: dict {feature_name: index dans le tuple _stats -> (nb, min, max, avg)}
      0 = length, 1 = shortest, 2 = longest, 3 = avg
    """
    candidate_names = None
    scores = {}

    for _, row in df.iterrows():
        url = row["url"]
        candidates = candidates_fn(url)
        if candidate_names is None:
            candidate_names = list(candidates.keys())
            scores = {name: {f: 0 for f in target_features} for name in candidate_names}

        for name, words in candidates.items():
            nb, mn, mx, avg = _stats(words)
            computed = {0: nb, 1: mn, 2: mx, 3: avg}
            for feature, idx in target_features.items():
                expected = row[feature]
                comp = computed[idx]
                try:
                    match = abs(float(comp) - float(expected)) < 1e-4
                except (TypeError, ValueError):
                    match = comp == expected
                if match:
                    scores[name][feature] += 1

    total = len(df)
    print(f"\n{'Candidat':45s}" + "".join(f"{f:>22s}" for f in target_features))
    ranked = sorted(
        candidate_names,
        key=lambda n: -sum(scores[n][f] for f in target_features),
    )
    for name in ranked:
        row_str = f"{name:45s}"
        for f in target_features:
            pct = scores[name][f] / total * 100
            row_str += f"{pct:21.1f}%"
        print(row_str)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="data/raw/dataset_phishing.csv")
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    sample = df.sample(n=min(args.n, len(df)), random_state=args.seed)

    print("=" * 100)
    print(f"CALIBRATION — famille 'words_raw' (sur {len(sample)} URLs)")
    print("=" * 100)
    evaluate_family(
        sample,
        words_raw_candidates,
        target_features={
            "length_words_raw": 0,
            "shortest_words_raw": 1,
            "longest_words_raw": 2,
            "avg_words_raw": 3,
        },
    )

    print("\n" + "=" * 100)
    print(f"CALIBRATION — famille 'words_host' (sur {len(sample)} URLs)")
    print("=" * 100)
    evaluate_family(
        sample,
        words_host_candidates,
        target_features={
            "shortest_word_host": 1,
            "longest_word_host": 2,
            "avg_word_host": 3,
        },
    )

    print("\n" + "=" * 100)
    print(f"CALIBRATION — 'nb_subdomains' (sur {len(sample)} URLs)")
    print("=" * 100)
    evaluate_single_value(sample, nb_subdomains_candidates, "nb_subdomains")

    print("\n" + "=" * 100)
    print(f"CALIBRATION — 'char_repeat' (sur {len(sample)} URLs)")
    print("=" * 100)
    evaluate_single_value(sample, char_repeat_candidates, "char_repeat")

    print(
        "\nInterprétation : pour chaque famille, retenir le candidat qui maximise "
        "l'ensemble des colonnes simultanément (pas une seule) — sinon on optimise "
        "une feature au détriment des autres qui partagent la même liste de mots."
    )


if __name__ == "__main__":
    main()