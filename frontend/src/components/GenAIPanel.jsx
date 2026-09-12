export default function GenAIPanel({ genaiAnalysis, genaiAvailable }) {
  return (
    <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.03] p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="rounded bg-cyan-500/15 px-2 py-0.5 text-xs font-semibold text-cyan-300 border border-cyan-500/30">
          GenAI-generated
        </span>
        <p className="text-sm text-slate-400">
          Interpretation of the rule-based findings above -- not the source of the score.
        </p>
      </div>

      {!genaiAvailable && (
        <p className="text-sm text-slate-500">
          No API key configured on the backend. Set OPENAI_API_KEY to enable this section.
        </p>
      )}

      {genaiAvailable && !genaiAnalysis && (
        <p className="text-sm text-slate-500">
          GenAI explanation is unavailable right now (request failed or quota exceeded). The
          rule-based result above is unaffected.
        </p>
      )}

      {genaiAnalysis && (
        <div className="space-y-3 text-sm">
          <p className="text-slate-200">{genaiAnalysis.explanation}</p>

          {genaiAnalysis.techniques?.length > 0 && (
            <div>
              <span className="text-slate-500">Techniques identified: </span>
              {genaiAnalysis.techniques.join(", ")}
            </div>
          )}

          {genaiAnalysis.impersonated_entity && (
            <div>
              <span className="text-slate-500">Possible impersonation: </span>
              {genaiAnalysis.impersonated_entity}
            </div>
          )}

          {genaiAnalysis.recommended_action && (
            <div>
              <span className="text-slate-500">Recommended action: </span>
              {genaiAnalysis.recommended_action}
            </div>
          )}

          <div className="flex items-center gap-2">
            <span className="text-slate-500">Confidence:</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs uppercase tracking-wide text-slate-300">
              {genaiAnalysis.confidence}
            </span>
          </div>

          {genaiAnalysis.caveats && (
            <p className="text-slate-500 italic">{genaiAnalysis.caveats}</p>
          )}
        </div>
      )}
    </div>
  );
}
