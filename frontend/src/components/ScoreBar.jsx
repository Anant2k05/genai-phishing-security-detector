const BAR_COLOR = {
  SAFE: "bg-emerald-500",
  SUSPICIOUS: "bg-amber-500",
  "HIGH RISK": "bg-orange-500",
  CRITICAL: "bg-red-500",
};

export default function ScoreBar({ score, level }) {
  const color = BAR_COLOR[level] || "bg-amber-500";
  return (
    <div className="w-full">
      <div className="flex justify-between text-sm text-slate-400 mb-1">
        <span>Phishing Risk Score</span>
        <span className="font-mono text-slate-200">{score}/100</span>
      </div>
      <div className="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden">
        <div
          className={`h-full ${color} transition-all duration-500`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}
