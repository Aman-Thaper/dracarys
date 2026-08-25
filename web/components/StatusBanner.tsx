"use client";
import { Campaign, Summary } from "@/lib/api";

export default function StatusBanner({ campaign, summary }: { campaign: Campaign | null; summary: Summary | null }) {
  if (!campaign) return null;
  const compromised = summary?.target_compromised;
  const verified = (summary?.fixes_verified ?? 0);
  const attempted = (summary?.fixes_attempted ?? 0);
  const complete = campaign.state === "COMPLETE";
  const allFixed = complete && attempted > 0 && verified === attempted;

  if (allFixed) {
    return (
      <Banner tone="acid" kicker="RETEST COMPLETE" title="FIX VERIFIED"
        sub={`${verified}/${attempted} attack paths broken — the original exploit no longer works.`} />
    );
  }
  if (compromised) {
    return (
      <Banner tone="flame" kicker="CRITICAL ATTACK PATH DISCOVERED" title="TARGET COMPROMISED"
        sub="A chained attack reached the protected treasury canary. Remediation in progress." />
    );
  }
  if (campaign.state === "FAILED") {
    return <Banner tone="flame" kicker="CAMPAIGN HALTED" title="FAILED" sub={campaign.error || "See audit log."} />;
  }
  if (campaign.state === "CANCELLED") {
    return <Banner tone="gold" kicker="OPERATOR" title="CAMPAIGN STOPPED" sub="Kill switch engaged." />;
  }
  if (["SCOPING","RECON","ATTACK_PLANNING","TESTING","VALIDATION","ATTACK_CHAIN_ANALYSIS","REPORTING","REMEDIATION","RETEST"].includes(campaign.state)) {
    return <Banner tone="ember" kicker="DRACARYS IS HUNTING" title={campaign.state.replace(/_/g, " ")}
      sub="Autonomous reconnaissance, exploitation and validation underway." pulse />;
  }
  return <Banner tone="ember" kicker="READY" title="AWAITING ORDERS" sub="Unleash DRACARYS against the authorized lab target." />;
}

function Banner({ tone, kicker, title, sub, pulse }:
  { tone: "flame" | "ember" | "acid" | "gold"; kicker: string; title: string; sub: string; pulse?: boolean }) {
  const map: Record<string, string> = {
    flame: "border-flame/50 bg-flame/10 text-flame",
    ember: "border-ember/50 bg-ember/10 text-ember",
    acid: "border-acid/50 bg-acid/10 text-acid",
    gold: "border-gold/50 bg-gold/10 text-gold",
  };
  return (
    <div className={`card relative overflow-hidden border ${map[tone]} px-5 py-4`}>
      {pulse && <div className="absolute inset-x-0 top-0 h-16 animate-scan bg-gradient-to-b from-white/5 to-transparent" />}
      <div className="text-[10px] font-mono uppercase tracking-[0.25em] opacity-80">{kicker}</div>
      <div className="text-2xl font-black tracking-tight">{title}</div>
      <div className="mt-0.5 text-sm text-slate-300">{sub}</div>
    </div>
  );
}
