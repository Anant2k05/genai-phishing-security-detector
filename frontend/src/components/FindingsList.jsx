import { getImpactText } from "../indicatorInfo";

export default function FindingsList({ indicators }) {
  if (!indicators || indicators.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        No rule-based indicators were matched in this content.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {indicators.map((indicator) => (
        <div
          key={indicator.id}
          className="rounded-lg border border-border bg-panel/60 p-4"
        >
          <p className="font-medium text-slate-100">{indicator.label}</p>
          <p className="mt-1 text-sm text-slate-400">
            <span className="text-slate-500">Evidence: </span>
            {indicator.evidence.slice(0, 4).map((e, idx) => (
              <span
                key={idx}
                className="mr-1.5 mb-1 inline-block rounded bg-cyan-500/10 px-1.5 py-0.5 font-mono text-xs text-cyan-300 border border-cyan-500/20"
              >
                {e}
              </span>
            ))}
          </p>
          <p className="mt-1 text-sm text-slate-400">
            <span className="text-slate-500">Why it matters: </span>
            {getImpactText(indicator.id)}
          </p>
        </div>
      ))}
    </div>
  );
}
