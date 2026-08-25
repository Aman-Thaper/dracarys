"use client";
import { Campaign, Target } from "@/lib/api";

const ACTIVE = ["SCOPING","RECON","ATTACK_PLANNING","TESTING","VALIDATION","ATTACK_CHAIN_ANALYSIS","REPORTING","REMEDIATION","RETEST"];
const TERMINAL = ["COMPLETE","FAILED","CANCELLED"];

export default function ControlPanel({ target, campaign, busy, onUnleash, onPause, onResume, onStop, onReset }:
  { target: Target | null; campaign: Campaign | null; busy: boolean;
    onUnleash: () => void; onPause: () => void; onResume: () => void; onStop: () => void; onReset: () => void; }) {
  const state = campaign?.state;
  const running = state && ACTIVE.includes(state);
  const paused = state === "PAUSED";
  const terminal = state && TERMINAL.includes(state);

  return (
    <div className="space-y-4">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Authorized target</div>
        <div className="mt-1 text-sm font-semibold text-slate-100">{target?.name ?? "—"}</div>
        <div className="font-mono text-xs text-ember">{target?.base_url}</div>
      </div>
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500">Scope (enforced)</div>
        <div className="mt-1 flex flex-wrap gap-1">
          {(target?.allowed_hosts ?? []).map((h) => (
            <span key={h} className="rounded bg-ink-700 px-2 py-0.5 font-mono text-[11px] text-acid">{h}</span>
          ))}
          {(target?.allowed_ports ?? []).map((p) => (
            <span key={p} className="rounded bg-ink-700 px-2 py-0.5 font-mono text-[11px] text-sky">:{p}</span>
          ))}
        </div>
      </div>

      {(!campaign || terminal) && (
        <button className="btn btn-primary w-full py-3 text-base tracking-wide" disabled={busy || !target}
          onClick={campaign && terminal ? onReset : onUnleash}>
          {campaign && terminal ? "◆ NEW CAMPAIGN" : "🔥 UNLEASH DRACARYS"}
        </button>
      )}

      {running && (
        <div className="grid grid-cols-2 gap-2">
          <button className="btn btn-ghost" disabled={busy} onClick={onPause}>❚❚ Pause</button>
          <button className="btn btn-ghost !border-flame/50 !text-flame" disabled={busy} onClick={onStop}>■ Stop</button>
        </div>
      )}
      {paused && (
        <div className="grid grid-cols-2 gap-2">
          <button className="btn btn-primary" disabled={busy} onClick={onResume}>▶ Resume</button>
          <button className="btn btn-ghost !border-flame/50 !text-flame" disabled={busy} onClick={onStop}>■ Stop</button>
        </div>
      )}

      {campaign && (
        <div className="grid grid-cols-2 gap-2 border-t border-ink-600 pt-3 text-center">
          <Stat label="State" value={campaign.state.replace(/_/g, " ")} />
          <Stat label="Requests" value={String(campaign.requests_made)} />
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded bg-ink-700/50 py-2">
      <div className="text-[9px] font-mono uppercase tracking-widest text-slate-500">{label}</div>
      <div className="text-xs font-semibold text-slate-100">{value}</div>
    </div>
  );
}
