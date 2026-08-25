"use client";

export default function SecurityScore({ score }: { score: number }) {
  const v = Math.max(0, Math.min(100, Math.round(score)));
  const color = v >= 70 ? "#39d98a" : v >= 40 ? "#ffd166" : "#ff3b30";
  const r = 33, c = 2 * Math.PI * r, off = c * (1 - v / 100);
  return (
    <div className="relative h-[92px] w-[92px] shrink-0">
      <svg viewBox="0 0 92 92" className="h-full w-full -rotate-90">
        <circle cx="46" cy="46" r={r} fill="none" stroke="#212636" strokeWidth="7" />
        <circle
          cx="46" cy="46" r={r} fill="none" stroke={color} strokeWidth="7"
          strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset .6s ease, stroke .6s ease", filter: `drop-shadow(0 0 6px ${color}66)` }}
        />
      </svg>
      {/* absolutely-centered label — always aligned regardless of digits */}
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-[26px] font-bold leading-none tabular-nums" style={{ color }}>{v}</span>
        <span className="mt-1 text-[8px] font-mono uppercase tracking-[0.25em] text-slate-500">score</span>
      </div>
    </div>
  );
}
