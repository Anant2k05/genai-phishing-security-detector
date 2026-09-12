"""
Combines message + URL indicators into a single heuristic risk score.

This is deliberately simple: each indicator has a fixed weight, multiple
pieces of evidence for the same indicator give diminishing returns (so one
indicator with 5 keyword hits doesn't dominate the score), and the total is
clamped to 0-100. This is NOT a statistically validated probability -- it's
a heuristic score meant to explain *why* something looks suspicious.
"""

# Configurable thresholds -- see README for reasoning.
RISK_THRESHOLDS = {
    "SAFE": (0, 24),
    "SUSPICIOUS": (25, 49),
    "HIGH RISK": (50, 74),
    "CRITICAL": (75, 100),
}

RECOMMENDATIONS = {
    "CRITICAL": (
        "Do not click the link or provide information. Verify the request "
        "through the organization's official website or another trusted channel."
    ),
    "HIGH RISK": (
        "Treat this message as potentially malicious. Do not provide "
        "credentials, OTPs, or payment information."
    ),
    "SUSPICIOUS": (
        "Verify the sender and destination URL before taking action."
    ),
    "SAFE": (
        "No strong phishing indicators were detected, but automated analysis "
        "cannot guarantee that content is safe."
    ),
}

DISCLAIMER = (
    "Automated analysis can make mistakes. Never use this tool as the sole "
    "basis for trusting a message or URL."
)


def _indicator_contribution(indicator: dict) -> float:
    """First piece of evidence counts full weight; extra evidence for the
    same indicator adds a diminishing 30% per additional hit, up to 3 hits."""
    hits = min(len(indicator["evidence"]), 3)
    weight = indicator["weight"]
    return weight * (1 + 0.3 * (hits - 1))


def compute_score(indicators: list) -> int:
    total = sum(_indicator_contribution(i) for i in indicators)
    return int(max(0, min(100, round(total))))


def get_risk_level(score: int) -> str:
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return "CRITICAL"


def get_recommendation(level: str) -> str:
    return RECOMMENDATIONS.get(level, RECOMMENDATIONS["SUSPICIOUS"])


def collect_categories(indicators: list) -> list:
    """Unique social-engineering categories, in order of first appearance."""
    seen = []
    for indicator in indicators:
        category = indicator.get("category")
        if category and category not in seen:
            seen.append(category)
    return seen


def build_result(message_indicators: list, url_indicators: list) -> dict:
    all_indicators = message_indicators + url_indicators
    score = compute_score(all_indicators)
    level = get_risk_level(score)

    return {
        "score": score,
        "risk_level": level,
        "indicators": all_indicators,
        "social_engineering_categories": collect_categories(all_indicators),
        "recommendation": get_recommendation(level),
        "disclaimer": DISCLAIMER,
    }
