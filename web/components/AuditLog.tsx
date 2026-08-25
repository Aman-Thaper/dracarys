"use client";
import { AuditEvent } from "@/lib/api";

export default function AuditLog({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) return <div className="p-3 text-sm text-slate-500">No audit events yet.</div>;
  return (
    <div className="max-h-72 space-y-1 overflow-y-auto font-mono text-[11px]">
      {events.map((e) => (
        <div key={e.id} className="flex items-center gap-2 border-b border-ink-700/60 py-1">
          <span className="text-slate-600">{new Date(e.created_at).toLocaleTimeString()}</span>
          <span className={result(e.result)}>{e.action}</span>
          <span className="flex-1 truncate text-slate-500">{e.target}</span>
          <span className={result(e.result)}>{e.result}</span>
        </div>
      ))}
    </div>
  );
}
function result(r: string) {
  if (r === "denied" || r.includes("fail")) return "text-flame";
  if (r === "confirmed" || r === "fix_verified") return "text-acid";
  return "text-slate-300";
}
