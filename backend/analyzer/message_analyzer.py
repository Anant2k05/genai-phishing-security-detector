"""
Rule-based analysis of message/email text.

Looks for phishing-style language patterns (urgency, credential requests,
impersonation, etc.) using keyword/phrase matching. Each match is returned
as an "indicator" with the matched evidence text so the frontend can show
exactly what triggered it, instead of just a black-box score.
"""

import re

# ---------------------------------------------------------------------------
# Phrase banks. Plain keyword lists kept simple on purpose -- this is a
# heuristic detector, not an NLP model.
# ---------------------------------------------------------------------------

URGENCY_PHRASES = [
    "urgent", "urgently", "immediately", "act now", "act fast",
    "as soon as possible", "asap", "right away", "without delay",
    "expires today", "expiring soon", "final notice", "last chance",
    "within 24 hours", "within 12 hours", "within 1 hour", "limited time",
    "action required", "respond immediately", "time sensitive", "do not delay",
    "before it's too late",
]

THREAT_PHRASES = [
    "account will be suspended", "account has been suspended",
    "account suspended", "account will be terminated", "account terminated",
    "legal action", "account will be closed", "account has been locked",
    "account locked", "unauthorized access detected", "permanently disabled",
    "will be deleted", "account has been compromised", "face penalties",
    "face legal consequences", "suspend your account", "restricted access",
    "your account is at risk", "suspicious activity detected",
]

PASSWORD_PHRASES = [
    "enter your password", "confirm your password", "provide your password",
    "reset your password", "your password has expired", "verify your password",
    "send us your password", "reply with your password", "current password",
]

OTP_PHRASES = [
    "otp", "one time password", "one-time password", "verification code",
    "share the code", "share this code", "6-digit code", "security code",
    "pin number", "share your pin",
]

BANKING_PHRASES = [
    "account number", "card number", "cvv", "expiry date", "ifsc code",
    "bank details", "upi pin", "net banking", "debit card", "credit card details",
    "swift code", "routing number", "atm pin",
]

PAYMENT_PHRASES = [
    "wire transfer", "processing fee", "pay a small fee", "gift card",
    "send money", "western union", "pay now to release", "clearance fee",
    "customs fee", "shipping fee to release", "pay via", "transfer the amount",
    "refundable deposit",
]

ATTACHMENT_PHRASES = [
    "see attached", "open the attachment", "download the attached",
    "invoice attached", "attached document", "review the attached file",
    "open attachment to view", "attached invoice",
]

VERIFICATION_PHRASES = [
    "verify your account", "confirm your identity", "account verification required",
    "verify your identity", "confirm your details", "re-verify your account",
    "validate your account", "update your account information",
]

CTA_PHRASES = [
    "click here", "click below", "click the link", "click this link",
    "tap here", "login here", "log in here", "follow this link",
    "download now", "open this link",
]

BYPASS_PHRASES = [
    "disable your antivirus", "turn off two-factor", "turn off 2fa",
    "share your screen", "install remote access", "teamviewer", "anydesk",
    "give us remote access", "disable your firewall", "bypass verification",
]

TECH_SUPPORT_PHRASES = [
    "your computer has a virus", "call this number immediately",
    "microsoft support team", "windows security alert", "your device is infected",
    "tech support team", "call microsoft support", "security alert from windows",
    "your computer has been infected",
]

REWARD_PHRASES = [
    "you have won", "you've won", "you have been selected", "you are a winner",
    "congratulations", "claim your prize", "free gift", "lottery",
    "cash prize", "reward points", "gift card for you", "selected to receive",
    "claim now", "eligible for a refund",
]

EMOTIONAL_PHRASES = [
    "please help me", "i'm stranded", "don't tell anyone", "keep this confidential",
    "i need your help urgently", "i'm in the hospital", "this is an emergency",
    "trust me", "please don't ignore this",
]

GREETING_PHRASES = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear sir/madam", "dear sir or madam",
    "dear member", "valued customer", "dear beneficiary",
]

IMPERSONATED_BRANDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "bank of america", "wells fargo", "chase", "hdfc", "icici", "sbi",
    "irs", "income tax department", "fedex", "ups", "dhl", "facebook",
    "instagram", "whatsapp",
]

INFORMAL_MARKERS = [
    "u", "ur", "plz", "pls", "thx", "gr8", "b4", "kindly revert",
    "do the needful", "revert back",
]


def _find_matches(text_lower, phrases):
    return [p for p in phrases if p in text_lower]


def _find_word_matches(text_lower, tokens):
    found = []
    for token in tokens:
        if " " in token:
            if token in text_lower:
                found.append(token)
        elif re.search(r"\b" + re.escape(token) + r"\b", text_lower):
            found.append(token)
    return found


def _find_impersonated_brand(text_lower):
    return [b for b in IMPERSONATED_BRANDS if b in text_lower]


def _find_domain_mismatch(text, brands_mentioned):
    """
    If the message mentions a well-known brand but also contains an email
    domain or URL host that doesn't include that brand name, that's a classic
    lookalike-domain trick (e.g. "PayPal" message sent from paypa1-secure.com).
    """
    if not brands_mentioned:
        return []

    hosts = re.findall(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
    hosts += re.findall(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)

    mismatches = []
    for host in hosts:
        host_lower = host.lower()
        if not any(brand.replace(" ", "") in host_lower.replace("-", "").replace(".", "")
                   for brand in brands_mentioned):
            mismatches.append(host)
    return mismatches


def _grammar_anomalies(text):
    """Basic formatting red flags: excessive caps, exclamation marks, texting slang."""
    text_lower = text.lower()
    letters = [c for c in text if c.isalpha()]
    cap_ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0
    exclamations = text.count("!")
    informal = _find_word_matches(text_lower, INFORMAL_MARKERS)

    evidence = []
    if cap_ratio > 0.3:
        evidence.append(f"{round(cap_ratio * 100)}% of letters are uppercase")
    if exclamations >= 3:
        evidence.append(f"{exclamations} exclamation marks")
    if informal:
        evidence.append("informal/texting phrasing: " + ", ".join(informal[:5]))

    return evidence


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_message(text: str) -> list:
    """
    Returns a list of indicator dicts:
    { id, label, category, evidence, weight }
    """
    text = text or ""
    text_lower = text.lower()
    brands = _find_impersonated_brand(text_lower)

    indicators = []

    def add(id_, label, category, evidence, weight):
        if evidence:
            indicators.append({
                "id": id_,
                "label": label,
                "category": category,
                "evidence": evidence,
                "weight": weight,
            })

    add("urgency", "Urgency language", "Urgency",
        _find_matches(text_lower, URGENCY_PHRASES), 8)

    add("threat", "Threat / account suspension language", "Fear / Threat",
        _find_matches(text_lower, THREAT_PHRASES), 12)

    add("password_request", "Requests password", "Credential Harvesting",
        _find_matches(text_lower, PASSWORD_PHRASES), 15)

    add("otp_request", "Requests OTP / verification code", "Credential Harvesting",
        _find_matches(text_lower, OTP_PHRASES), 15)

    add("banking_request", "Requests banking/card details", "Financial Fraud",
        _find_matches(text_lower, BANKING_PHRASES), 15)

    add("payment_request", "Requests payment or money transfer", "Financial Fraud",
        _find_matches(text_lower, PAYMENT_PHRASES), 12)

    add("attachment", "Mentions a suspicious attachment", None,
        _find_matches(text_lower, ATTACHMENT_PHRASES), 6)

    add("verification", "Fake account verification request", "Account Verification",
        _find_matches(text_lower, VERIFICATION_PHRASES), 9)

    add("cta", "Suspicious call-to-action link phrasing", "Malicious Link",
        _find_matches(text_lower, CTA_PHRASES), 8)

    add("bypass_security", "Asks to bypass normal security procedures", "Credential Harvesting",
        _find_matches(text_lower, BYPASS_PHRASES), 14)

    add("tech_support", "Technical support scam language", "Technical Support Scam",
        _find_matches(text_lower, TECH_SUPPORT_PHRASES), 10)

    add("reward", "Reward / prize / lottery language", "Reward / Prize",
        _find_matches(text_lower, REWARD_PHRASES), 9)

    add("emotional", "Emotional manipulation / urgency to trust", "Emotional Manipulation",
        _find_matches(text_lower, EMOTIONAL_PHRASES), 8)

    add("impersonation", "Impersonates a known organization", "Authority Impersonation",
        brands, 10)

    add("generic_greeting", "Generic greeting (not addressed by name)", "Authority Impersonation",
        _find_matches(text_lower, GREETING_PHRASES), 4)

    add("domain_mismatch", "Sender/link domain doesn't match the brand mentioned", "Authority Impersonation",
        _find_domain_mismatch(text, brands), 12)

    add("grammar_anomaly", "Unusual formatting or grammar", None,
        _grammar_anomalies(text), 5)

    return indicators
