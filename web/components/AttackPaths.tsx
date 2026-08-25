"use client";
import { AttackPath } from "@/lib/api";

export default function AttackPaths({ paths }: { paths: AttackPath[] }) {
  if (paths.length === 0) {
    return <div className="p-4 text-center text-sm text-slate-500">No attack chains discovered yet.</div>;
  }
  return (
    <div className="space-y-3">
      {paths.map((p) => (
        <div key={p.id} className={`rounded-lg border p-3 ${p.reaches_canary ? "border-flame/40 bg-flame/5" : "border-ink-600 bg-ink-700/30"}`}>
          <div className="mb-2 flex items-center gap-2">
            <span className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase sev-${p.severity}`}>{p.severity}</span>
            {p.reaches_canary && <span className="rounded bg-flame/20 px-2 py-0.5 text-[10px] font-bold uppercase text-flame">reaches canary</span>}
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {p.nodes.map((n, i) => (
              <span key={n.ref} className="flex items-center gap-1.5">
                <span className={`rounded px-2 py-1 font-mono ${nodeTone(n.type)}`}>{n.label}</span>
                {i < p.nodes.length - 1 && <span className="text-ember">→</span>}
              </span>
            ))}
          </div>
          <div className="mt-2 text-[11px] text-slate-400">{p.impact}</div>
        </div>
      ))}
    </div>
  );
}

function nodeTone(type: string) {
  switch (type) {
    case "resource": return "bg-gold/15 text-gold border border-gold/30";
    case "vulnerability": return "bg-flame/10 text-flame border border-flame/30";
    case "identity": return "bg-sky/10 text-sky border border-sky/30";
    default: return "bg-ink-600 text-slate-300 border border-ink-600";
  }
}
