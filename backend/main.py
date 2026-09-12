"""
FastAPI backend for the GenAI Phishing & Usable Security Detector.

Pipeline: input validation -> rule-based analysis (message and/or URL) ->
risk scoring -> optional GenAI explanation -> combined JSON response.

Submitted content is never stored, logged, or used to fetch/visit anything.
"""

import re
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from analyzer.risk_engine import build_result
from analyzer.genai_analyzer import get_genai_analysis, is_available
from examples import DEMO_EXAMPLES

MAX_INPUT_LENGTH = 8000
URL_PATTERN = re.compile(r"https?://\S+")

app = FastAPI(title="GenAI Phishing & Usable Security Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    input_type: Literal["message", "url"]
    content: str = Field(..., min_length=1, max_length=MAX_INPUT_LENGTH)


@app.get("/api/health")
def health():
    return {"status": "ok", "genai_enabled": is_available()}


@app.get("/api/examples")
def examples():
    return DEMO_EXAMPLES


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Content cannot be empty.")

    url_findings: Optional[dict] = None

    if payload.input_type == "url":
        message_indicators = []
        url_result = analyze_url(content)
        url_indicators = url_result["indicators"]
        url_findings = url_result["parsed"]
    else:
        message_indicators = analyze_message(content)
        url_indicators = []
        found_urls = URL_PATTERN.findall(content)
        if found_urls:
            url_result = analyze_url(found_urls[0])
            url_indicators = url_result["indicators"]
            url_findings = url_result["parsed"]

    result = build_result(message_indicators, url_indicators)

    genai_analysis = get_genai_analysis(
        input_text=content,
        indicators=result["indicators"],
        score=result["score"],
        url_findings=url_findings,
    )

    result["genai_analysis"] = genai_analysis
    result["genai_available"] = is_available()
    result["input_type"] = payload.input_type
    result["url_findings"] = url_findings

    return result
