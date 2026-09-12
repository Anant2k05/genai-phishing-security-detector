import { useEffect, useState } from "react";
import RiskBadge from "./components/RiskBadge";
import ScoreBar from "./components/ScoreBar";
import FindingsList from "./components/FindingsList";
import GenAIPanel from "./components/GenAIPanel";

const API_BASE = "http://localhost:8000/api";
const MAX_LENGTH = 8000;

export default function App() {
  const [inputType, setInputType] = useState("message");
  const [content, setContent] = useState("");
  const [examples, setExamples] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/examples`)
      .then((res) => res.json())
      .then(setExamples)
      .catch(() => setExamples([]));
  }, []);

  async function handleAnalyze() {
    const trimmed = content.trim();
    if (!trimmed) {
      setError("Paste a message or URL first.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input_type: inputType, content: trimmed }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Analysis failed.");
      }

      setResult(await res.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function loadExample(id) {
    const example = examples.find((e) => e.id === id);
    if (!example) return;
    setInputType(example.input_type);
    setContent(example.content);
    setResult(null);
    setError(null);
  }

  return (
    <div className="min-h-screen bg-bg text-slate-200">
      <div className="max-w-4xl mx-auto px-4 py-10">
        <header className="mb-8">
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
            Phishing &amp; Usable Security Detector
          </h1>
          <p className="text-slate-400 mt-1 text-sm">
            Heuristic phishing-risk analysis for suspicious messages and URLs.
          </p>
        </header>

        <div className="rounded-xl border border-border bg-panel p-5">
          <div className="flex gap-2 mb-4">
            {["message", "url"].map((type) => (
              <button
                key={type}
                onClick={() => {
                  setInputType(type);
                  setContent("");
                  setResult(null);
                  setError(null);
                }}
                className={`px-4 py-1.5 rounded-md text-sm font-medium border transition-colors ${
                  inputType === type
                    ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/40"
                    : "border-border text-slate-400 hover:text-slate-200"
                }`}
              >
                {type === "message" ? "Message" : "URL"}
              </button>
            ))}

            {examples.length > 0 && inputType === "message" && (
              <select
                onChange={(e) => e.target.value && loadExample(e.target.value)}
                defaultValue=""
                className="ml-auto rounded-md border border-border bg-bg text-sm text-slate-400 px-2 py-1.5"
              >
                <option value="">Load example...</option>
                {examples.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.title}
                  </option>
                ))}
              </select>
            )}
          </div>

          {inputType === "message" ? (
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value.slice(0, MAX_LENGTH))}
              placeholder="Paste a suspicious email, SMS, or chat message here..."
              rows={8}
              className="w-full rounded-md border border-border bg-bg p-3 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 resize-y"
            />
          ) : (
            <input
              type="text"
              value={content}
              onChange={(e) => setContent(e.target.value.slice(0, MAX_LENGTH))}
              placeholder="Paste a suspicious URL here..."
              className="w-full rounded-md border border-border bg-bg p-3 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          )}

          <div className="flex items-center justify-between mt-3">
            <span className="text-xs text-slate-500">
              {content.length}/{MAX_LENGTH}
            </span>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="rounded-md bg-cyan-500 text-slate-900 font-semibold px-5 py-2 text-sm hover:bg-cyan-400 disabled:opacity-50 transition-colors"
            >
              {loading ? "Analyzing..." : "Analyze for Phishing"}
            </button>
          </div>

          {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
        </div>

        {result && (
          <div className="mt-6 space-y-6">
            <div className="rounded-xl border border-border bg-panel p-5">
              <div className="flex items-center justify-between mb-4">
                <RiskBadge level={result.risk_level} size="lg" />
              </div>
              <ScoreBar score={result.score} level={result.risk_level} />
            </div>

            {result.social_engineering_categories.length > 0 && (
              <Section title="Social Engineering Techniques">
                <div className="flex flex-wrap gap-2">
                  {result.social_engineering_categories.map((cat) => (
                    <span
                      key={cat}
                      className="rounded-md border border-purple-500/30 bg-purple-500/10 px-2.5 py-1 text-xs font-medium text-purple-300"
                    >
                      {cat}
                    </span>
                  ))}
                </div>
              </Section>
            )}

            <Section title="Why was this flagged?">
              <FindingsList indicators={result.indicators} />
            </Section>

            <Section title="Recommended Action">
              <p className="text-sm text-slate-200">{result.recommendation}</p>
              <p className="text-xs text-slate-500 mt-2 italic">{result.disclaimer}</p>
            </Section>

            {result.url_findings?.valid && (
              <Section title="Technical Findings">
                <dl className="grid grid-cols-2 gap-2 text-sm">
                  <dt className="text-slate-500">Scheme</dt>
                  <dd className="font-mono text-slate-300">{result.url_findings.scheme}</dd>
                  <dt className="text-slate-500">Host</dt>
                  <dd className="font-mono text-slate-300">{result.url_findings.host}</dd>
                  <dt className="text-slate-500">Path</dt>
                  <dd className="font-mono text-slate-300">{result.url_findings.path || "/"}</dd>
                </dl>
              </Section>
            )}

            <Section title="GenAI Security Analysis">
              <GenAIPanel
                genaiAnalysis={result.genai_analysis}
                genaiAvailable={result.genai_available}
              />
            </Section>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="rounded-xl border border-border bg-panel p-5">
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-3">
        {title}
      </h2>
      {children}
    </div>
  );
}
