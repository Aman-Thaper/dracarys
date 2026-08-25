"use client";
import {
  api, AttackPath, AuditEvent, Campaign, Evidence, Finding, Graph, Remediation,
  Retest, Summary, Target,
} from "@/lib/api";
import AttackGraph from "@/components/AttackGraph";
import AttackPaths from "@/components/AttackPaths";
import AuditLog from "@/components/AuditLog";
import ControlPanel from "@/components/ControlPanel";
import FindingsPanel from "@/components/FindingsPanel";
import PhaseTracker from "@/components/PhaseTracker";
import SecurityScore from "@/components/SecurityScore";
import StatusBanner from "@/components/StatusBanner";
import { useCallback, useEffect, useRef, useState } from "react";

const TERMINAL = ["COMPLETE", "FAILED", "CANCELLED"];

export default function Page() {
  const [health, setHealth] = useState<any>(null);
  const [target, setTarget] = useState<Target | null>(null);
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [retests, setRetests] = useState<Retest[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [clock, setClock] = useState("");
  const timer = useRef<any>(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setErr("Backend unreachable — start the API (make api)."));
    api.targets().then((ts) => setTarget(ts.find((t) => t.is_lab) ?? ts[0] ?? null)).catch(() => {});
    const c = setInterval(() => setClock(new Date().toLocaleTimeString("en-GB")), 1000);
    return () => { clearInterval(timer.current); clearInterval(c); };
  }, []);

  const refresh = useCallback(async (id: string) => {
    const [c, s, f, e, p, g, r, rt, a] = await Promise.all([
      api.campaign(id), api.summary(id).catch(() => null), api.findings(id),
      api.evidence(id), api.attackPaths(id), api.graph(id),
      api.remediations(id), api.retests(id), api.audit(id),
    ]);
    setCampaign(c); setSummary(s); setFindings(f); setEvidence(e); setPaths(p);
    setGraph(g); setRemediations(r); setRetests(rt); setAudit(a);
    if (TERMINAL.includes(c.state)) { clearInterval(timer.current); timer.current = null; }
    return c;
  }, []);

  const startPolling = useCallback((id: string) => {
    clearInterval(timer.current);
    timer.current = setInterval(() => refresh(id).catch(() => {}), 700);
  }, [refresh]);

  const unleash = useCallback(async () => {
    if (!target) return;
    setBusy(true); setErr(null);
    try {
      const c = await api.createCampaign(target.id, "Operation Dragonfire",
        "Discover and prove an attack chain to the treasury canary, then verify fixes.");
      await api.start(c.id);
      setCampaign(c); startPolling(c.id);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }, [target, startPolling]);

  const control = useCallback(async (fn: (id: string) => Promise<any>) => {
    if (!campaign) return;
    setBusy(true);
    try { await fn(campaign.id); await refresh(campaign.id); if (!timer.current) startPolling(campaign.id); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }, [campaign, refresh, startPolling]);

  const reset = () => {
    clearInterval(timer.current); timer.current = null;
    setCampaign(null); setSummary(null); setFindings([]); setEvidence([]);
    setPaths([]); setGraph(null); setRemediations([]); setRetests([]); setAudit([]);
  };

  const compromised = summary?.target_compromised;
  const stat = (label: string, value: any, tone = "text-slate-200") => (
    <span className="flex items-baseline gap-1.5">
      <span className="hud">{label}</span><span className={`font-mono text-xs font-bold ${tone}`}>{value}</span>
    </span>
  );

  return (
    <div className="grid-bg min-h-screen animate-flicker">
      {/* ── Header ─────────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 border-b border-ink-600/70 bg-ink-900/85 backdrop-blur">
        <div className="flex w-full items-center justify-between gap-4 px-5 py-2.5">
          <div className="flex items-baseline gap-3">
            <span className="text-2xl font-black tracking-tight text-ember" style={{ textShadow: "0 0 22px rgba(255,107,43,.55)" }}>
              🐉 DRACARYS
            </span>
            <span className="hidden font-mono text-[11px] text-slate-500 sm:inline">
              <span className="text-acid">root@dracarys</span>:<span className="text-sky">~</span>$ ./dracarys --unleash <span className="cursor" />
            </span>
          </div>
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <span className="hidden text-slate-500 md:inline">{clock}</span>
            <span className={`rounded px-2 py-1 ${health ? "bg-acid/10 text-acid" : "bg-flame/10 text-flame"}`}>
              {health ? `◉ API ${health.version}` : "◎ API offline"}
            </span>
            {health && <span className="hidden rounded bg-ink-700 px-2 py-1 text-slate-400 lg:inline">planner:{health.llm_provider}</span>}
          </div>
        </div>
        {/* HUD ticker */}
        <div className="flex w-full flex-wrap items-center gap-x-5 gap-y-1 border-t border-ink-700/70 bg-black/30 px-5 py-1.5">
          {stat("state", (campaign?.state ?? "IDLE").replace(/_/g, " "), compromised ? "text-flame" : "text-acid")}
          {stat("requests", campaign?.requests_made ?? 0)}
          {stat("findings", summary?.counts.findings ?? 0)}
          {stat("paths→canary", paths.filter((p) => p.reaches_canary).length, "text-gold")}
          {stat("evidence", evidence.length)}
          {stat("fixes", `${summary?.fixes_verified ?? 0}/${summary?.fixes_attempted ?? 0}`, "text-acid")}
          {stat("target", compromised ? "COMPROMISED" : "intact", compromised ? "text-flame" : "text-slate-400")}
        </div>
      </header>

      {err && <div className="w-full px-5 pt-3"><div className="rounded border border-flame/40 bg-flame/10 px-4 py-2 font-mono text-sm text-flame">! {err}</div></div>}

      <main className="w-full space-y-5 px-4 py-5 md:px-5">
        {/* Row: controls + banner */}
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[350px_minmax(0,1fr)]">
          <aside className="space-y-5">
            <section className="card p-4">
              <ControlPanel target={target} campaign={campaign} busy={busy}
                onUnleash={unleash} onPause={() => control(api.pause)} onResume={() => control(api.resume)}
                onStop={() => control(api.stop)} onReset={reset} />
            </section>
            <section className="card p-4">
              <div className="term-h mb-2">campaign_progress</div>
              <PhaseTracker campaign={campaign} />
            </section>
            <section className="card flex items-center justify-between gap-3 p-4">
              <div>
                <div className="term-h mb-2">posture</div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs text-slate-300">
                  <span>find <b className="text-slate-100">{summary?.counts.findings ?? 0}</b></span>
                  <span>path <b className="text-slate-100">{summary?.counts.attack_paths ?? 0}</b></span>
                  <span>evd <b className="text-slate-100">{evidence.length}</b></span>
                  <span>fix <b className="text-acid">{summary?.fixes_verified ?? 0}</b>/<b>{summary?.fixes_attempted ?? 0}</b></span>
                </div>
              </div>
              <SecurityScore score={campaign?.security_score ?? 100} />
            </section>
          </aside>

          <div className="min-w-0 space-y-5">
            <StatusBanner campaign={campaign} summary={summary} />
            <section className="card p-4">
              <div className="term-h mb-3">attack_chains</div>
              <AttackPaths paths={paths} />
            </section>
          </div>
        </div>

        {/* Full-width hero: attack graph */}
        <section className="card p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="term-h">attack_graph</div>
            <span className="hud">{graph?.nodes.length ?? 0} nodes · {graph?.edges.length ?? 0} edges</span>
          </div>
          <AttackGraph graph={graph} />
        </section>

        {/* Bottom: findings + audit */}
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <section className="card">
            <div className="term-h border-b border-ink-600 p-4">
              findings{findings.length > 0 && <span className="text-slate-500"> [{findings.length}]</span>}
            </div>
            <FindingsPanel findings={findings} evidence={evidence} remediations={remediations} retests={retests} />
          </section>
          <section className="card p-4">
            <div className="term-h mb-2">audit_trail</div>
            <AuditLog events={audit} />
          </section>
        </div>
      </main>

      <footer className="w-full px-5 pb-8 pt-2 text-center font-mono text-[11px] text-slate-600">
        [ DRACARYS ] autonomous red-team · synthetic lab · scope=loopback:8888,8889 · attack.prove.fix.retest
      </footer>
    </div>
  );
}
