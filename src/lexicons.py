"""
lexicons.py — Lexiques partagés pour l'extraction de features.

Maintenus de préférence par l'équipe Cybersécurité / Threat Analysis.
Modifier ces listes n'exige aucun changement dans feature_extractor.py.
"""

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "support", "click", "loan", "review",
}

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
}

KNOWN_BRANDS = {
    "paypal", "google", "facebook", "apple", "amazon", "microsoft",
    "netflix", "instagram", "whatsapp", "bankofamerica", "wellsfargo",
    "chase", "twitter", "linkedin", "ebay", "dropbox",
}

PHISH_HINT_WORDS = [
    "login", "secure", "account", "update", "verify", "banking",
    "confirm", "signin", "password", "webscr", "ebayisapi", "suspend",
]
