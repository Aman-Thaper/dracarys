"use client";
import { Evidence, Finding, Remediation, Retest, Severity } from "@/lib/api";
import { useState } from "react";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function FindingsPanel({ findings, evidence, remediations, retests }:
  { findings: Finding[]; evidence: Evidence[]; remediations: Remediation[]; retests: Retest[] }) {
  const sorted = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  if (findings.length === 0) {
    return <div className="p-6 text-center text-sm text-slate-500">No confirmed findings yet.</div>;
  }
  return (
    <div className="divide-y divide-ink-600">
      {sorted.map((f) => (
        <FindingRow key={f.id} f={f}
          evidence={evidence.filter((e) => e.finding_id === f.id)}
          remediation={remediations.find((r) => r.finding_id === f.id)}
          retest={retests.find((r) => r.finding_id === f.id)} />
      ))}
    </div>
  );
}

function FindingRow({ f, evidence, remediation, retest }:
  { f: Finding; evidence: Evidence[]; remediation?: Remediation; retest?: Retest }) {
  const [open, setOpen] = useState(false);
  const verified = retest?.result === "fix_verified";
  return (
    <div className="px-4 py-3">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 text-left">
        <span className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase sev-${f.severity}`}>{f.severity}</span>
        <span className="font-mono text-xs text-slate-400">{f.ground_truth_id}</span>
        <span className="flex-1 text-sm font-medium text-slate-100">{f.title}</span>
        {retest && (
          <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${verified ? "bg-acid/15 text-acid" : "bg-flame/15 text-flame"}`}>
            {verified ? "✓ fix verified" : "✗ fix failed"}
          </span>
        )}
        <span className="text-slate-500">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="mt-3 space-y-3 pl-1 text-sm">
          <Field label="Affected asset" mono>{f.affected_asset}</Field>
          <Field label="Root cause">{f.root_cause}</Field>
          <Field label="Impact">{f.impact}</Field>
          {remediation && (
            <div className="rounded border border-ink-600 bg-ink-700/40 p-3">
              <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-ember">Remediation</div>
              <div className="text-slate-200">{remediation.recommendation}</div>
              <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-[11px] leading-relaxed text-acid">{remediation.patch_diff}</pre>
              <div className="mt-2 text-[11px] text-slate-400"><span className="text-slate-500">Verify:</span> {remediation.verification_test}</div>
            </div>
          )}
          <div>
            <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-slate-500">Evidence ({evidence.length})</div>
            <div className="space-y-2">
              {evidence.map((e) => (
                <div key={e.id} className="rounded border border-ink-600 bg-black/30 p-2 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>{e.summary}</span>
                    <span className="text-slate-600">sha256:{e.sha256.slice(0, 12)}</span>
                  </div>
                  <div className="mt-1 text-sky">
                    {e.request_meta?.method} {e.request_meta?.url}
                    {e.response_meta?.status_code != null && <span className="text-slate-500"> → {e.response_meta.status_code}</span>}
                  </div>
                  {e.content?.body_preview && (
                    <pre className="mt-1 max-h-28 overflow-auto whitespace-pre-wrap text-slate-400">{e.content.body_preview}</pre>
                  )}
                </div>
              ))}
            </div>
          </div>
          {retest && (
            <div className="text-[11px] text-slate-400">
              <span className="text-slate-500">Retest against</span> <span className="font-mono">{retest.patched_base_url}</span>:
              {" "}before <span className="text-flame">{retest.before_outcome}</span> → after <span className="text-acid">{retest.after_outcome}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Field({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500">{label}: </span>
      <span className={mono ? "font-mono text-slate-300" : "text-slate-300"}>{children}</span>
    </div>
  );
}
