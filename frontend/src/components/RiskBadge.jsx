const LEVEL_STYLES = {
  SAFE: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  SUSPICIOUS: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  "HIGH RISK": "bg-orange-500/15 text-orange-400 border-orange-500/40",
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/40",
};

export default function RiskBadge({ level, size = "md" }) {
  const style = LEVEL_STYLES[level] || LEVEL_STYLES.SUSPICIOUS;
  const sizeClass = size === "lg" ? "text-lg px-4 py-1.5" : "text-xs px-2.5 py-1";
  return (
    <span
      className={`inline-flex items-center rounded-md border font-semibold tracking-wide ${sizeClass} ${style}`}
    >
      {level}
    </span>
  );
}
