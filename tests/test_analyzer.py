"""
Basic tests for the rule-based analysis pipeline. Run with `pytest` from the
project root (backend/ is added to sys.path below so imports work either way).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from analyzer.risk_engine import build_result, compute_score, get_risk_level


def _indicator_ids(indicators):
    return {i["id"] for i in indicators}


def test_urgency_detected():
    indicators = analyze_message("Act now, your account will be suspended immediately.")
    assert "urgency" in _indicator_ids(indicators)


def test_threat_language_detected():
    indicators = analyze_message("Your account has been suspended due to unauthorized access detected.")
    assert "threat" in _indicator_ids(indicators)


def test_password_request_detected():
    indicators = analyze_message("Please confirm your password to continue.")
    assert "password_request" in _indicator_ids(indicators)


def test_otp_request_detected():
    indicators = analyze_message("Please share the code we just sent to your phone.")
    assert "otp_request" in _indicator_ids(indicators)


def test_banking_request_detected():
    indicators = analyze_message("Send us your card number and CVV to verify.")
    assert "banking_request" in _indicator_ids(indicators)


def test_payment_request_detected():
    indicators = analyze_message("Please pay a small processing fee via gift card.")
    assert "payment_request" in _indicator_ids(indicators)


def test_reward_scam_detected():
    indicators = analyze_message("Congratulations, you have won a cash prize! Claim now.")
    assert "reward" in _indicator_ids(indicators)


def test_benign_message_has_low_score():
    indicators = analyze_message(
        "Hi, your monthly statement is ready to view in your account dashboard. "
        "No action is required."
    )
    score = compute_score(indicators)
    assert score < 25
    assert get_risk_level(score) == "SAFE"


def test_high_risk_message_scores_high():
    text = (
        "URGENT: your account will be suspended within 24 hours. Verify your "
        "account now and confirm your password and card number immediately: "
        "http://paypal-secure-login.top/verify"
    )
    indicators = analyze_message(text)
    urls = analyze_url("http://paypal-secure-login.top/verify")
    result = build_result(indicators, urls["indicators"])
    assert result["score"] >= 50
    assert result["risk_level"] in ("HIGH RISK", "CRITICAL")


def test_url_ip_address_detected():
    result = analyze_url("http://192.168.1.50/login")
    ids = {i["id"] for i in result["indicators"]}
    assert "ip_host" in ids


def test_url_http_flagged():
    result = analyze_url("http://example.com/login")
    ids = {i["id"] for i in result["indicators"]}
    assert "http_scheme" in ids


def test_url_https_not_flagged_for_scheme():
    result = analyze_url("https://example.com/")
    ids = {i["id"] for i in result["indicators"]}
    assert "http_scheme" not in ids


def test_url_at_symbol_detected():
    result = analyze_url("http://user@evil.com/login")
    ids = {i["id"] for i in result["indicators"]}
    assert "at_symbol" in ids


def test_url_brand_lookalike_detected():
    result = analyze_url("http://paypal-secure-verify.com/login")
    ids = {i["id"] for i in result["indicators"]}
    assert "brand_lookalike" in ids


def test_malformed_url_handled():
    result = analyze_url("not a url at all")
    assert result["parsed"]["valid"] is True or "malformed" in {i["id"] for i in result["indicators"]}


def test_empty_url_handled():
    result = analyze_url("")
    assert result["parsed"].get("valid") is False


def test_risk_level_thresholds():
    assert get_risk_level(0) == "SAFE"
    assert get_risk_level(24) == "SAFE"
    assert get_risk_level(25) == "SUSPICIOUS"
    assert get_risk_level(50) == "HIGH RISK"
    assert get_risk_level(75) == "CRITICAL"
    assert get_risk_level(100) == "CRITICAL"
