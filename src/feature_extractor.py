"""
feature_extractor.py — Phishing URL Detector

Extrait les features attendues par le modèle (models/feature_list.json)
à partir d'une URL brute. Le nombre de features est dynamique
(52 en mode URL-only, 79 en mode complet).

Les features sont marquées par niveau de confiance :
  - trivial  : définition sans ambiguïté
  - ambigu   : heuristique reconstituée, à valider via tools/validate_against_dataset.py
  - conflit  : contredit le contrat "1 requête HTTP max" ; fallback dégradé

Usage:
    from feature_extractor import extract_features
    features = extract_features("http://example.com/login")  # -> list[float] ordonnée
"""

import re
import json
import itertools
from urllib.parse import urlparse
from pathlib import Path

import requests
import tldextract
from bs4 import BeautifulSoup

TIMEOUT_SECONDS = 5
USER_AGENT = "Mozilla/5.0 (compatible; PhishingURLDetector/1.0)"

# suffix_list_urls=() force tldextract à utiliser uniquement son snapshot local
# embarqué (mis à jour à l'installation du package) : aucune requête réseau
# cachée, donc le contrat "1 requête HTTP max par URL" reste garanti tel quel.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# ---------------------------------------------------------------------------
# Lexiques (importés depuis src/lexicons.py — maintenus par l'équipe Cyber)
# ---------------------------------------------------------------------------

from lexicons import (
    SUSPICIOUS_TLDS,
    SHORTENING_SERVICES,
    KNOWN_BRANDS,
    PHISH_HINT_WORDS,
)

# ---------------------------------------------------------------------------
# Contexte : tout ce qui est calculé une seule fois par URL
# ---------------------------------------------------------------------------


def _split_words(s: str):
    return [w for w in re.split(r"[^a-zA-Z0-9]", s) if w]


def _min_len(words):
    return min((len(w) for w in words), default=0)


def _max_len(words):
    return max((len(w) for w in words), default=0)


def _avg_len(words):
    return (sum(len(w) for w in words) / len(words)) if words else 0.0


def _domain_of(url: str) -> str:
    """Domaine 'racine' (sans sous-domaine ni TLD), pour comparer interne/externe."""
    ext = _TLD_EXTRACTOR(url)
    return ext.domain


class URLContext:
    """Parsing one-shot de l'URL + (optionnel) résultat de la requête HTTP unique."""

    def __init__(self, url: str, fetch_html: bool = True):
        self.url = url
        self.parsed = urlparse(url)
        self.hostname = self.parsed.hostname or ""
        self.path = self.parsed.path or ""

        ext = _TLD_EXTRACTOR(url)
        self.domain = ext.domain
        self.suffix = ext.suffix
        self.subdomain = ext.subdomain

        # CALIBRÉ le 29/08 sur 500 URLs réelles (voir tools/calibrate_features.py,
        # candidat "V5") : meilleur compromis pour length/avg/shortest/longest_words_raw
        # ensemble — schéma et 'www.' retirés, labels du suffixe public exclus.
        # Imparfait (46-98% selon la stat) mais nettement le meilleur candidat testé.
        no_scheme = re.sub(r'^[a-zA-Z]+://', '', url, count=1)
        no_scheme_no_www = re.sub(r'^www\.', '', no_scheme)
        suffix_labels = set(ext.suffix.split(".")) if ext.suffix else set()
        self.words_raw = [w for w in _split_words(no_scheme_no_www) if w.lower() not in suffix_labels]
        self.words_host = _split_words(self.hostname)
        # CORRIGÉ le 29/08 : words_path doit inclure la query string et le fragment,
        # pas seulement le path — validé exactement sur 2 exemples (avg_word_path=
        # 4.714285714 et 7.375 reproduits au chiffre près une fois la query incluse).
        path_and_query = self.path
        if self.parsed.query:
            path_and_query += "?" + self.parsed.query
        if self.parsed.fragment:
            path_and_query += "#" + self.parsed.fragment
        self.words_path = _split_words(path_and_query)
        # CALIBRÉ le 29/08 sur 500 URLs réelles (voir tools/calibrate_features.py,
        # candidat "H6") : les stats de mots du hostname matchent nettement mieux
        # (93.6%/88.8%/87.4%) en ne prenant que sous-domaine + domaine, SANS le
        # suffixe public, découpés uniquement par point (pas par tiret/underscore).
        registrable_no_suffix = ".".join(p for p in [self.subdomain, self.domain] if p)
        self.words_host_registrable = [p for p in registrable_no_suffix.split(".") if p]

        # --- La requête HTTP unique du contrat ---
        self.response = None
        self.soup = None
        self.fetch_error = None

        if fetch_html:
            try:
                self.response = requests.get(
                    url, timeout=TIMEOUT_SECONDS,
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=True,
                )
                self.soup = BeautifulSoup(self.response.text, "html.parser")
            except requests.RequestException as e:
                self.fetch_error = str(e)

    @property
    def html_available(self) -> bool:
        return self.soup is not None


# ---------------------------------------------------------------------------
# 🟢 Groupe A — URL seule (36 features)
# ---------------------------------------------------------------------------

def f_length_url(ctx): return len(ctx.url)                                    # trivial
def f_length_hostname(ctx): return len(ctx.hostname)                          # trivial
def f_nb_dots(ctx): return ctx.url.count(".")                                 # trivial
def f_nb_hyphens(ctx): return ctx.url.count("-")                              # trivial
def f_nb_at(ctx): return ctx.url.count("@")                                   # trivial
def f_nb_qm(ctx): return ctx.url.count("?")                                   # trivial
def f_nb_and(ctx): return ctx.url.count("&")                                  # trivial
def f_nb_eq(ctx): return ctx.url.count("=")                                   # trivial
def f_nb_underscore(ctx): return ctx.url.count("_")                           # trivial
def f_nb_tilde(ctx): return ctx.url.count("~")                                # trivial
def f_nb_percent(ctx): return ctx.url.count("%")                              # trivial
def f_nb_slash(ctx): return ctx.url.count("/")                                # trivial
def f_nb_star(ctx): return ctx.url.count("*")                                 # trivial
def f_nb_colon(ctx): return ctx.url.count(":")                                # trivial
def f_nb_comma(ctx): return ctx.url.count(",")                                # trivial
def f_nb_semicolumn(ctx): return ctx.url.count(";")                           # trivial
def f_nb_dollar(ctx): return ctx.url.count("$")                               # trivial
def f_nb_space(ctx): return ctx.url.count(" ") + ctx.url.count("%20")         # trivial

def f_nb_www(ctx): return ctx.url.lower().count("www")                        # trivial
def f_nb_com(ctx):
    # CONFIRMÉ par validation empirique : l'occurrence légitime du TLD réel
    # (quand le suffixe de l'URL est exactement "com") ne compte pas.
    count = ctx.url.lower().count("com")
    if ctx.suffix.lower() == "com":
        count = max(0, count - 1)
    return count

def f_nb_dslash(ctx):                                                          # AMBIGU
    # Compte les '//' hors du '//' qui suit le schéma (http:// ou https://)
    without_scheme = re.sub(r'^[a-zA-Z]+://', '', ctx.url, count=1)
    return without_scheme.count("//")

def f_http_in_path(ctx): return 1 if "http" in ctx.path.lower() else 0        # trivial

def f_https_token(ctx):
    # CONFIRMÉ par validation empirique (29/08) : ne détecte PAS un leurre "https"
    # dans le domaine, mais simplement l'ABSENCE de HTTPS (1 = pas de HTTPS = signal négatif)
    return 0 if ctx.url.lower().startswith("https://") else 1

def f_ratio_digits_url(ctx):
    return sum(c.isdigit() for c in ctx.url) / len(ctx.url) if ctx.url else 0.0  # trivial

def f_prefix_suffix(ctx):
    # RÉVERSÉ le 29/08 : mon inversion précédente (basée sur seulement 3 exemples)
    # a fait chuter la correspondance de 86.3% à 13.7% sur 300 lignes réelles —
    # la règle originale, simple, était en fait correcte dans l'immense majorité
    # des cas. Leçon : 3 exemples ne suffisent jamais à généraliser une règle.
    return 1 if "-" in ctx.hostname else 0

def f_path_extension(ctx):
    # AJUSTÉ par validation empirique : les extensions web courantes (.php, .htm, .html...)
    # ne déclenchent PAS le flag (elles sont légitimes et omniprésentes). Seules les
    # extensions hors de cette liste courante sont considérées comme signal.
    # ⚠️ Liste "COMMON_WEB_EXTENSIONS" à affiner : on n'a pas encore d'exemple positif
    # (attendu=1) pour confirmer précisément quelles extensions déclenchent le flag.
    m = re.search(r"\.([a-zA-Z0-9]{1,5})$", ctx.path)
    if not m:
        return 0
    ext = m.group(1).lower()
    COMMON_WEB_EXTENSIONS = {"php", "htm", "html", "asp", "aspx", "jsp", "js", "css", "cfm"}
    return 0 if ext in COMMON_WEB_EXTENSIONS else 1

def f_length_words_raw(ctx): return len(ctx.words_raw)                        # trivial

def f_char_repeat(ctx):
    # AMBIGU — RÉVISÉ le 29/08 : l'hypothèse "run consécutif, schéma retiré" ne tenait
    # que sur 3 exemples (52.7% de correspondance sur 300 lignes réelles, insuffisant).
    # Conservé tel quel en best-effort ; à recalibrer via tools/calibrate_features.py
    # avant de considérer cette feature comme fiable.
    body = re.sub(r'^[a-zA-Z]+://', '', ctx.url, count=1)
    longest = 0
    for _, group in itertools.groupby(body):
        run_len = len(list(group))
        if run_len >= 2:
            longest = max(longest, run_len)
    return longest

def f_shortest_words_raw(ctx): return _min_len(ctx.words_raw)                 # trivial
def f_shortest_word_path(ctx): return _min_len(ctx.words_path)                # trivial
def f_longest_words_raw(ctx): return _max_len(ctx.words_raw)                  # trivial
def f_longest_word_path(ctx): return _max_len(ctx.words_path)                 # trivial
def f_avg_words_raw(ctx): return _avg_len(ctx.words_raw)                      # trivial
def f_avg_word_path(ctx): return _avg_len(ctx.words_path)                     # trivial

def f_phish_hints(ctx):                                                        # AMBIGU (dépend du lexique)
    low = ctx.url.lower()
    return sum(low.count(w) for w in PHISH_HINT_WORDS)

def f_brand_in_path(ctx):                                                      # AMBIGU (dépend du lexique)
    low_words = [w.lower() for w in ctx.words_path]
    return 1 if any(b in low_words for b in KNOWN_BRANDS) else 0


# ---------------------------------------------------------------------------
# 🟡 Groupe B — Parsing domaine (16 features)
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

def f_ip(ctx): return 1 if _IPV4_RE.match(ctx.hostname) else 0                # trivial

def f_ratio_digits_host(ctx):
    return sum(c.isdigit() for c in ctx.hostname) / len(ctx.hostname) if ctx.hostname else 0.0  # trivial

def f_punycode(ctx): return 1 if "xn--" in ctx.hostname else 0                # trivial

def f_port(ctx):                                                               # trivial
    port = ctx.parsed.port
    return 1 if port and port not in (80, 443) else 0

def f_tld_in_path(ctx):                                                        # AMBIGU
    return 1 if ctx.suffix and ctx.suffix in ctx.path.lower() else 0

def f_tld_in_subdomain(ctx):                                                   # AMBIGU
    return 1 if ctx.suffix and ctx.suffix in ctx.subdomain.lower() else 0

def f_abnormal_subdomain(ctx):                                                 # AMBIGU
    return 1 if re.search(r"^w+[-]?w*[-]?w*\.", ctx.subdomain + ".") and ctx.subdomain != "www" else 0

def f_nb_subdomains(ctx):
    # CALIBRÉ le 29/08 sur 500 URLs réelles (voir tools/calibrate_features.py) :
    # meilleur candidat = 88.2% (comptage de points sur l'URL entière, schéma
    # retiré, PAS seulement le hostname). Pas parfait (bug probable dans le
    # dataset d'origine) mais nettement le meilleur candidat testé — adopté.
    no_scheme = re.sub(r'^[a-zA-Z]+://', '', ctx.url, count=1)
    return no_scheme.count(".")

def f_random_domain(ctx):                                                      # AMBIGU (heuristique à calibrer)
    d = ctx.domain.lower()
    if not d:
        return 0
    vowels = sum(1 for c in d if c in "aeiou")
    ratio_consonnes = 1 - (vowels / len(d))
    return 1 if ratio_consonnes > 0.85 else 0

def f_shortening_service(ctx):                                                 # trivial (dépend juste de la liste)
    full_domain = f"{ctx.domain}.{ctx.suffix}".lower()
    return 1 if full_domain in SHORTENING_SERVICES else 0

def f_shortest_word_host(ctx): return _min_len(ctx.words_host_registrable)    # calibré (H6, 93.6%)
def f_longest_word_host(ctx): return _max_len(ctx.words_host_registrable)     # calibré (H6, 88.8%)
def f_avg_word_host(ctx): return _avg_len(ctx.words_host_registrable)         # calibré (H6, 87.4%)

def f_domain_in_brand(ctx):                                                    # AMBIGU (dépend du lexique)
    d = ctx.domain.lower()
    return 1 if d in KNOWN_BRANDS else 0

def f_brand_in_subdomain(ctx):                                                 # AMBIGU (dépend du lexique)
    sub = ctx.subdomain.lower()
    return 1 if any(b in sub for b in KNOWN_BRANDS) and ctx.domain.lower() not in KNOWN_BRANDS else 0

def f_suspecious_tld(ctx): return 1 if ctx.suffix.lower() in SUSPICIOUS_TLDS else 0  # trivial (dépend de la liste)


# ---------------------------------------------------------------------------
# 🟠 Groupe C — Contenu HTML (21 features, 1 seule requête déjà faite dans ctx)
# ---------------------------------------------------------------------------

def _link_domain(href, base_domain):
    if not href or href.startswith("#") or href.startswith("javascript:"):
        return None
    if href.startswith("http://") or href.startswith("https://") or href.startswith("//"):
        return _domain_of(href)
    return base_domain  # lien relatif -> considéré interne


def f_nb_redirection(ctx):
    if not ctx.response:
        return 0
    return len(ctx.response.history)

def f_nb_external_redirection(ctx):                                            # AMBIGU
    if not ctx.response:
        return 0
    base = ctx.domain
    return sum(1 for r in ctx.response.history if _domain_of(r.url) != base)

def f_nb_hyperlinks(ctx):
    if not ctx.html_available:
        return 0
    return len(ctx.soup.find_all("a", href=True))

def _hyperlink_ratio(ctx, internal: bool):
    if not ctx.html_available:
        return 0.0
    links = ctx.soup.find_all("a", href=True)
    if not links:
        return 0.0
    base = ctx.domain
    count = 0
    for a in links:
        d = _link_domain(a["href"], base)
        if d is None:
            continue
        if (d == base) == internal:
            count += 1
    return count / len(links)

def f_ratio_intHyperlinks(ctx): return _hyperlink_ratio(ctx, internal=True)
def f_ratio_extHyperlinks(ctx): return _hyperlink_ratio(ctx, internal=False)

def f_nb_extCSS(ctx):
    if not ctx.html_available:
        return 0
    base = ctx.domain
    count = 0
    for link in ctx.soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
        href = link.get("href", "")
        d = _link_domain(href, base)
        if d and d != base:
            count += 1
    return count

def f_ratio_extRedirection(ctx):
    # CONFLIT AVEC LE CONTRAT "1 REQUÊTE HTTP MAX" :
    # la définition originale nécessite de suivre chaque lien externe pour
    # savoir s'il redirige. Fallback documenté à 0 en attendant décision d'équipe.
    return 0.0

def f_ratio_extErrors(ctx):
    # CONFLIT AVEC LE CONTRAT "1 REQUÊTE HTTP MAX" (idem : nécessite de requêter
    # chaque lien externe pour vérifier s'il répond en erreur). Fallback à 0.
    return 0.0

def f_login_form(ctx):
    if not ctx.html_available:
        return 0
    return 1 if ctx.soup.find("input", {"type": "password"}) else 0

def f_external_favicon(ctx):
    if not ctx.html_available:
        return 0
    icon = ctx.soup.find("link", rel=lambda v: v and "icon" in v)
    if not icon or not icon.get("href"):
        return 0
    d = _link_domain(icon["href"], ctx.domain)
    return 1 if d and d != ctx.domain else 0

def f_links_in_tags(ctx):                                                      # AMBIGU
    if not ctx.html_available:
        return 0
    count = 0
    for tag in ctx.soup.find_all(["meta", "script", "link"]):
        if tag.get("href") or tag.get("src"):
            count += 1
    return count

def _media_ratio(ctx, internal: bool):
    if not ctx.html_available:
        return 0.0
    media = []
    for tag_name, attr in (("img", "src"), ("video", "src"), ("audio", "src"), ("source", "src")):
        media.extend(ctx.soup.find_all(tag_name))
    if not media:
        return 0.0
    base = ctx.domain
    count = 0
    for m in media:
        src = m.get("src", "")
        d = _link_domain(src, base)
        if d is None:
            continue
        if (d == base) == internal:
            count += 1
    return count / len(media)

def f_ratio_intMedia(ctx): return _media_ratio(ctx, internal=True)
def f_ratio_extMedia(ctx): return _media_ratio(ctx, internal=False)

def f_iframe(ctx):
    if not ctx.html_available:
        return 0
    return 1 if ctx.soup.find("iframe") else 0

def f_popup_window(ctx):                                                       # AMBIGU
    if not ctx.response:
        return 0
    return 1 if "window.open(" in ctx.response.text else 0

def f_safe_anchor(ctx):
    if not ctx.html_available:
        return 0.0
    links = ctx.soup.find_all("a", href=True)
    if not links:
        return 0.0
    suspicious = sum(
        1 for a in links
        if a["href"].strip() in ("#", "", "javascript:void(0)") or a["href"].strip().startswith("javascript:")
    )
    return suspicious / len(links)

def f_onmouseover(ctx):                                                        # AMBIGU
    if not ctx.response:
        return 0
    return 1 if ("onmouseover" in ctx.response.text.lower() and "status" in ctx.response.text.lower()) else 0

def f_right_clic(ctx):                                                         # AMBIGU
    if not ctx.response:
        return 0
    text = ctx.response.text.lower()
    return 1 if ("event.button==2" in text or "contextmenu" in text) else 0

def f_empty_title(ctx):
    # CORRIGÉ le 29/08 : en cas d'échec de la requête HTTP, retombait à 1
    # (suspect) alors que les 20 autres features 🟠 retombent à 0 (neutre) —
    # incohérence qui biaisait artificiellement les URLs injoignables vers
    # "phishing". Uniformisé : échec réseau = neutre partout.
    if not ctx.html_available:
        return 0
    if not ctx.soup.title:
        return 1
    return 1 if not ctx.soup.title.text.strip() else 0

def f_domain_in_title(ctx):
    if not ctx.html_available or not ctx.soup.title:
        return 0
    return 1 if ctx.domain.lower() in ctx.soup.title.text.lower() else 0

def f_domain_with_copyright(ctx):                                              # AMBIGU
    if not ctx.response:
        return 0
    text = ctx.response.text.lower()
    idx = text.find("©")
    if idx == -1:
        return 0
    window = text[max(0, idx - 50): idx + 50]
    return 1 if ctx.domain.lower() in window else 0


# ---------------------------------------------------------------------------
# ⚫ Constantes (6 features) — toujours 0 sur ce dataset
# ---------------------------------------------------------------------------

def f_nb_or(ctx): return 0
def f_ratio_nullHyperlinks(ctx): return 0
def f_ratio_intRedirection(ctx): return 0
def f_ratio_intErrors(ctx): return 0
def f_submit_email(ctx): return 0
def f_sfh(ctx): return 0


# ---------------------------------------------------------------------------
# Registre : nom de feature -> fonction
# ---------------------------------------------------------------------------

FEATURE_FUNCTIONS = {
    "length_url": f_length_url, "length_hostname": f_length_hostname, "nb_dots": f_nb_dots,
    "nb_hyphens": f_nb_hyphens, "nb_at": f_nb_at, "nb_qm": f_nb_qm, "nb_and": f_nb_and,
    "nb_or": f_nb_or, "nb_eq": f_nb_eq, "nb_underscore": f_nb_underscore, "nb_tilde": f_nb_tilde,
    "nb_percent": f_nb_percent, "nb_slash": f_nb_slash, "nb_star": f_nb_star, "nb_colon": f_nb_colon,
    "nb_comma": f_nb_comma, "nb_semicolumn": f_nb_semicolumn, "nb_dollar": f_nb_dollar,
    "nb_space": f_nb_space, "nb_www": f_nb_www, "nb_com": f_nb_com, "nb_dslash": f_nb_dslash,
    "http_in_path": f_http_in_path, "https_token": f_https_token, "ratio_digits_url": f_ratio_digits_url,
    "ip": f_ip, "ratio_digits_host": f_ratio_digits_host, "punycode": f_punycode, "port": f_port,
    "tld_in_path": f_tld_in_path, "tld_in_subdomain": f_tld_in_subdomain,
    "abnormal_subdomain": f_abnormal_subdomain, "nb_subdomains": f_nb_subdomains,
    "prefix_suffix": f_prefix_suffix, "random_domain": f_random_domain,
    "shortening_service": f_shortening_service, "path_extension": f_path_extension,
    "nb_redirection": f_nb_redirection, "nb_external_redirection": f_nb_external_redirection,
    "length_words_raw": f_length_words_raw, "char_repeat": f_char_repeat,
    "shortest_words_raw": f_shortest_words_raw, "shortest_word_host": f_shortest_word_host,
    "shortest_word_path": f_shortest_word_path, "longest_words_raw": f_longest_words_raw,
    "longest_word_host": f_longest_word_host, "longest_word_path": f_longest_word_path,
    "avg_words_raw": f_avg_words_raw, "avg_word_host": f_avg_word_host, "avg_word_path": f_avg_word_path,
    "phish_hints": f_phish_hints, "domain_in_brand": f_domain_in_brand,
    "brand_in_subdomain": f_brand_in_subdomain, "brand_in_path": f_brand_in_path,
    "suspecious_tld": f_suspecious_tld, "nb_hyperlinks": f_nb_hyperlinks,
    "ratio_intHyperlinks": f_ratio_intHyperlinks, "ratio_extHyperlinks": f_ratio_extHyperlinks,
    "ratio_nullHyperlinks": f_ratio_nullHyperlinks, "nb_extCSS": f_nb_extCSS,
    "ratio_intRedirection": f_ratio_intRedirection, "ratio_extRedirection": f_ratio_extRedirection,
    "ratio_intErrors": f_ratio_intErrors, "ratio_extErrors": f_ratio_extErrors,
    "login_form": f_login_form, "external_favicon": f_external_favicon,
    "links_in_tags": f_links_in_tags, "submit_email": f_submit_email,
    "ratio_intMedia": f_ratio_intMedia, "ratio_extMedia": f_ratio_extMedia, "sfh": f_sfh,
    "iframe": f_iframe, "popup_window": f_popup_window, "safe_anchor": f_safe_anchor,
    "onmouseover": f_onmouseover, "right_clic": f_right_clic, "empty_title": f_empty_title,
    "domain_in_title": f_domain_in_title, "domain_with_copyright": f_domain_with_copyright,
}

FEATURES_NEEDING_HTML = {
    "nb_redirection", "nb_external_redirection", "nb_hyperlinks", "ratio_intHyperlinks",
    "ratio_extHyperlinks", "nb_extCSS", "ratio_extRedirection", "ratio_extErrors", "login_form",
    "external_favicon", "links_in_tags", "ratio_intMedia", "ratio_extMedia", "iframe",
    "popup_window", "safe_anchor", "onmouseover", "right_clic", "empty_title",
    "domain_in_title", "domain_with_copyright",
}


def load_feature_order(feature_list_path: str = "models/feature_list.json"):
    with open(feature_list_path, encoding="utf-8") as f:
        return json.load(f)


def extract_features(url: str, feature_order=None) -> list:
    """
    Point d'entrée principal : URL -> liste de 79 valeurs, dans l'ordre
    de models/feature_list.json (source de vérité pour l'ordre exact).
    """
    if feature_order is None:
        feature_order = load_feature_order()

    needs_html = any(name in FEATURES_NEEDING_HTML for name in feature_order)
    ctx = URLContext(url, fetch_html=needs_html)

    values = []
    for name in feature_order:
        func = FEATURE_FUNCTIONS.get(name)
        if func is None:
            raise KeyError(f"Aucune fonction d'extraction enregistrée pour la feature '{name}'")
        try:
            values.append(float(func(ctx)))
        except Exception as e:
            # Ne jamais planter tout le vecteur pour une seule feature en échec :
            # valeur de repli 0.0 + trace pour investigation.
            print(f"[WARN] Échec extraction '{name}' pour {url} : {e}")
            values.append(0.0)

    return values
