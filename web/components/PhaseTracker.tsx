"use client";
import { Campaign, CampaignState, PHASES } from "@/lib/api";

const ORDER: CampaignState[] = [
  "CREATED", "SCOPING", "RECON", "ATTACK_PLANNING", "TESTING", "VALIDATION",
  "ATTACK_CHAIN_ANALYSIS", "REPORTING", "REMEDIATION", "RETEST", "COMPLETE",
];

export default function PhaseTracker({ campaign }: { campaign: Campaign | null }) {
  const state = campaign?.state ?? "CREATED";
  const idx = ORDER.indexOf(state as CampaignState);
  const progress = campaign?.progress ?? {};
  return (
    <div className="flex flex-wrap gap-1.5">
      {PHASES.map((p) => {
        const phaseIdx = ORDER.indexOf(p.states[0]);
        const done = progress[p.key] === "done" || progress[p.key] === true || phaseIdx < idx;
        const active = p.states.includes(state as CampaignState);
        return (
          <div
            key={p.key}
            className={[
              "flex-1 min-w-[64px] rounded border px-2 py-1.5 text-center text-[11px] font-mono uppercase tracking-wide",
              active ? "border-ember bg-ember/15 text-ember animate-pulseline"
                : done ? "border-acid/40 bg-acid/10 text-acid"
                : "border-ink-600 bg-ink-700/40 text-slate-500",
            ].join(" ")}
          >
            <div className="text-[9px] opacity-70">{done ? "✓" : active ? "▶" : "·"}</div>
            {p.label}
          </div>
        );
      })}
    </div>
  );
}
