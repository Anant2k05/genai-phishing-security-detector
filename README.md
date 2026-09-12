# GenAI Phishing & Usable Security Detector

A web app that analyzes a suspicious email/message or URL and produces an
explainable, heuristic phishing-risk assessment. It combines deterministic
rule-based detection with an optional GenAI explanation layer.

## Problem Statement

Phishing and social-engineering messages rely on recognizable patterns —
manufactured urgency, threats of account loss, requests for credentials or
OTPs, lookalike domains — but most users don't consistently check for them,
and a plain "this looks like phishing" verdict doesn't teach anyone what to
look for next time. Security-awareness tools that only output a label
without evidence don't build the judgment needed to catch the next attempt.

## Solution

The detector runs submitted content through a conventional analysis pipeline
before any AI is involved:

**Input -> Rule-based indicators -> URL analysis -> Risk score -> GenAI explanation**

Every flagged indicator is shown with the exact matched text and a plain
explanation of why it matters. The heuristic score and risk level are
computed entirely by the rule-based engine; an LLM is used afterward, only to
interpret and summarize those findings in plain language — it never decides
the score itself.

## Key Features

- Paste a message/email or a URL and get a risk assessment
- Risk level (SAFE / SUSPICIOUS / HIGH RISK / CRITICAL) with a 0-100 heuristic score
- Explainable findings: each indicator shows its matched evidence and impact
- URL structural analysis (IP hosts, `@` tricks, lookalike domains, suspicious TLDs, etc.)
- Social-engineering technique badges (Urgency, Credential Harvesting, Authority Impersonation, ...)
- Optional GenAI explanation, clearly labeled and separate from the rule-based score
- Built-in example messages for a one-click demo
- No submitted content is stored or logged; URLs are never fetched or visited

## Architecture

```text
User Input (message or URL)
   |
Input Validation (FastAPI / Pydantic)
   |
Rule-Based Message Analysis  --\
                                 >  Risk Engine (scoring + thresholds)
URL Analysis                 --/
   |
GenAI Analysis (optional, explains the findings above)
   |
Combined JSON Result
   |
React Frontend (indicators, score, recommendation, GenAI panel)
```

## Tech Stack

- **Backend:** Python, FastAPI
- **Frontend:** React, Vite, Tailwind CSS
- **Analysis:** Standard-library regex/`urllib.parse` for rule-based and URL checks
- **GenAI:** OpenAI API (`gpt-4o-mini` by default), used only for the explanation layer
- **Testing:** pytest

## Risk Scoring Methodology

This is a **heuristic phishing risk score**, not a statistically validated
probability. Each indicator (urgency language, credential requests, lookalike
domains, etc.) has a fixed weight. If an indicator matches multiple times in
the same message, additional matches add diminishing returns (30% of the base
weight per extra match, capped at 3) rather than being summed linearly, so
one repeated keyword can't dominate the score on its own. The total is
clamped to 0-100 and mapped to a risk level:

| Score  | Risk Level  |
|--------|-------------|
| 0-24   | SAFE        |
| 25-49  | SUSPICIOUS  |
| 50-74  | HIGH RISK   |
| 75-100 | CRITICAL    |

These thresholds and weights live in `backend/analyzer/risk_engine.py` and
the individual analyzer modules, and are straightforward to retune.

## Security Considerations

- URLs are only parsed as strings (`urllib.parse`) — the app never fetches,
  visits, or downloads anything submitted to it.
- Submitted content is not stored, persisted, or logged.
- API keys are read from environment variables server-side and are never
  exposed to the frontend.
- Input length is capped (8000 characters) and validated with Pydantic.
- All user-submitted text is rendered by React, which escapes it by default —
  no `dangerouslySetInnerHTML` is used anywhere in the frontend.

## Screenshots

_Add screenshots of the message analysis view, URL analysis view, and the
GenAI explanation panel here before publishing._

## Installation

Requires Python 3.10+ and Node.js 18+.

```bash
git clone <repo-url>
cd genai-phishing-detector

# Backend
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt

# Frontend
cd frontend
npm install
cd ..
```

## Environment Variables

Copy `.env.example` to `.env` and fill in as needed:

```env
OPENAI_API_KEY=       # optional -- GenAI section is skipped if unset
GENAI_MODEL=gpt-4o-mini
```

Load them into your shell before starting the backend, e.g. on Windows
PowerShell: `Get-Content .env | ForEach-Object { if ($_ -match '^(\w+)=(.*)$') { Set-Item "Env:$($matches[1])" $matches[2] } }`.

## Running the Application

In one terminal:

```bash
cd backend
uvicorn main:app --reload --port 8000
```

In another terminal:

```bash
cd frontend
npm run dev
```

Open **http://localhost:5173**. The frontend talks to the API at
`http://localhost:8000/api`.

## Testing

```bash
pip install -r requirements.txt
pytest tests/ -v
```

Covers indicator detection (urgency, credential/OTP/banking/payment requests,
reward scams), URL structural checks (IP hosts, HTTP, `@` tricks, lookalike
domains, malformed input), risk scoring thresholds, and benign-message
classification.

## Limitations

This is an educational/portfolio security analysis tool, not a replacement
for enterprise phishing detection systems. Specifically:

- Detection is keyword/pattern-based, not a trained classifier — it can miss
  phishing that avoids common phrasing and can false-positive on legitimate
  urgent messages.
- URL analysis is purely structural; it does not check domain age, hosting
  reputation, certificate data, or live threat-intelligence feeds.
- The GenAI layer explains the rule-based findings; it does not independently
  verify anything and can be wrong.
- Should never be used as the sole basis for deciding whether a message or
  link is safe.

## Future Improvements

- Browser extension for inline analysis
- Email-client integration
- Threat-intelligence feed lookups for URLs
- Multilingual phishing pattern detection
- Domain reputation / age checks
