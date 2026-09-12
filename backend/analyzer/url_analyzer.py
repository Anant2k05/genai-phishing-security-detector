"""
Rule-based analysis of a single URL.

We never fetch or visit the URL -- everything here is done by parsing the
URL string itself (scheme, host, path). This keeps the tool safe to run
against genuinely malicious links.
"""

import re
from urllib.parse import urlparse, unquote

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "webscr", "billing", "password", "banking",
]

SUSPICIOUS_TLDS = [
    ".zip", ".top", ".xyz", ".club", ".work", ".click", ".loan",
    ".men", ".gq", ".tk", ".ml", ".cf",
]

IMPERSONATED_BRANDS = [
    "paypal", "microsoft", "apple", "amazon", "google", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica",
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _brand_lookalike(host: str):
    """
    Flags hosts that contain a brand name but aren't that brand's real
    domain -- e.g. "paypal-secure-login.com" or "paypa1.com".
    """
    host_clean = host.lower().replace("-", "")
    matches = []
    for brand in IMPERSONATED_BRANDS:
        if brand in host_clean and not host_clean.startswith(brand + "."):
            matches.append(brand)
    return matches


def analyze_url(raw_url: str) -> dict:
    """
    Returns { "parsed": {...technical details...}, "indicators": [...] }
    """
    raw_url = (raw_url or "").strip()
    indicators = []

    def add(id_, label, evidence, weight):
        if evidence:
            indicators.append({
                "id": id_,
                "label": label,
                "category": "Malicious Link",
                "evidence": evidence,
                "weight": weight,
            })

    # Normalize: add a scheme if missing so urlparse can split host/path.
    url_for_parsing = raw_url
    if url_for_parsing and not re.match(r"^[a-zA-Z]+://", url_for_parsing):
        url_for_parsing = "http://" + url_for_parsing

    parsed = urlparse(url_for_parsing)
    host = parsed.hostname or ""
    path_and_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    if not host:
        return {
            "parsed": {"valid": False},
            "indicators": [{
                "id": "malformed",
                "label": "URL could not be parsed",
                "category": "Malicious Link",
                "evidence": [raw_url],
                "weight": 10,
            }],
        }

    add("http_scheme", "Uses HTTP instead of HTTPS",
        ["http"] if parsed.scheme == "http" else [], 8)

    add("ip_host", "Uses a raw IP address instead of a domain name",
        [host] if IP_PATTERN.match(host) else [], 15)

    subdomain_count = max(0, host.count(".") - 1)
    add("excessive_subdomains", "Unusually many subdomains",
        [host] if subdomain_count >= 3 else [], 8)

    add("long_url", "Unusually long URL",
        [f"{len(raw_url)} characters"] if len(raw_url) > 100 else [], 5)

    add("url_encoding", "Contains encoded characters that hide the real destination",
        [raw_url] if "%" in raw_url and unquote(raw_url) != raw_url else [], 8)

    add("at_symbol", "Contains '@', which browsers ignore everything before",
        [raw_url] if "@" in parsed.netloc else [], 12)

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_and_query.lower()]
    add("suspicious_keywords", "Suspicious keywords in the URL path",
        keyword_hits, 6)

    tld_hits = [tld for tld in SUSPICIOUS_TLDS if host.lower().endswith(tld)]
    add("suspicious_tld", "Uses a TLD commonly abused for scams",
        tld_hits, 8)

    brand_hits = _brand_lookalike(host)
    add("brand_lookalike", "Domain resembles a known brand but isn't the real domain",
        brand_hits, 15)

    is_shortener = any(host.lower() == d or host.lower().endswith("." + d) for d in SHORTENER_DOMAINS)
    add("shortener", "Shortened URL hides the real destination",
        [host] if is_shortener else [], 6)

    return {
        "parsed": {
            "valid": True,
            "scheme": parsed.scheme,
            "host": host,
            "path": parsed.path,
        },
        "indicators": indicators,
    }
