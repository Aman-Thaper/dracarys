// Typed client for the DRACARYS control-plane API. All calls go same-origin via
// the Next.js rewrite proxy to the FastAPI backend.

export type CampaignState =
  | "CREATED" | "SCOPING" | "RECON" | "ATTACK_PLANNING" | "TESTING" | "VALIDATION"
  | "ATTACK_CHAIN_ANALYSIS" | "REPORTING" | "REMEDIATION" | "RETEST" | "COMPLETE"
  | "FAILED" | "CANCELLED" | "PAUSED";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Target {
  id: string; name: string; base_url: string; description: string;
  allowed_hosts: string[]; allowed_ports: number[]; is_lab: boolean; validated: boolean;
}

export interface Campaign {
  id: string; target_id: string; name: string; objective: string;
  state: CampaignState; scope: any; policy: any; progress: Record<string, any>;
  requests_made: number; security_score: number; error: string | null; control: string;
  created_at: string; started_at: string | null; completed_at: string | null;
}

export interface Finding {
  id: string; ground_truth_id: string | null; category: string; title: string;
  severity: Severity; confidence: string; affected_asset: string; root_cause: string;
  impact: string; description: string; evidence_refs: string[]; status: string;
}

export interface Hypothesis {
  id: string; category: string; module_id: string; title: string; rationale: string;
  target_asset: string; expected_outcome: string; priority: number; status: string; planner: string;
}

export interface Evidence {
  id: string; kind: string; tool: string; summary: string; request_meta: any;
  response_meta: any; content: any; sha256: string; finding_id: string | null; created_at: string;
}

export interface AttackPath {
  id: string; title: string; nodes: GraphNode[]; edges: GraphEdge[];
  finding_ids: string[]; impact: string; severity: Severity; reaches_canary: boolean;
}

export interface GraphNode { ref: string; type: string; label: string; data: any; }
export interface GraphEdge { source: string; target: string; type: string; data?: any; }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; }

export interface Remediation {
  id: string; finding_id: string; ground_truth_id: string | null; summary: string;
  root_cause: string; recommendation: string; patch_diff: string; patch_ref: string;
  verification_test: string;
}

export interface Retest {
  id: string; finding_id: string; result: string; patched_base_url: string;
  before_outcome: string; after_outcome: string; detail: string;
}

export interface AuditEvent {
  id: string; actor: string; action: string; target: string; result: string;
  detail: any; created_at: string;
}

export interface Summary {
  campaign: Campaign; counts: Record<string, number>;
  severity_breakdown: Record<string, number>; target_compromised: boolean;
  fixes_verified: number; fixes_attempted: number;
}

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

const opts = (method: string, body?: any): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: body ? JSON.stringify(body) : undefined,
  cache: "no-store",
});

export const api = {
  health: () => fetch("/api/health", { cache: "no-store" }).then(j<any>),
  targets: () => fetch("/api/targets", { cache: "no-store" }).then(j<Target[]>),
  validate: (base_url: string) =>
    fetch("/api/targets/validate", opts("POST", { base_url })).then(j<any>),
  createCampaign: (target_id: string, name: string, objective: string) =>
    fetch("/api/campaigns", opts("POST", { target_id, name, objective })).then(j<Campaign>),
  campaigns: () => fetch("/api/campaigns", { cache: "no-store" }).then(j<Campaign[]>),
  campaign: (id: string) => fetch(`/api/campaigns/${id}`, { cache: "no-store" }).then(j<Campaign>),
  summary: (id: string) => fetch(`/api/campaigns/${id}/summary`, { cache: "no-store" }).then(j<Summary>),
  start: (id: string) => fetch(`/api/campaigns/${id}/start`, opts("POST")).then(j<Campaign>),
  pause: (id: string) => fetch(`/api/campaigns/${id}/pause`, opts("POST")).then(j<Campaign>),
  resume: (id: string) => fetch(`/api/campaigns/${id}/resume`, opts("POST")).then(j<Campaign>),
  stop: (id: string) => fetch(`/api/campaigns/${id}/stop`, opts("POST")).then(j<Campaign>),
  findings: (id: string) => fetch(`/api/campaigns/${id}/findings`, { cache: "no-store" }).then(j<Finding[]>),
  hypotheses: (id: string) => fetch(`/api/campaigns/${id}/hypotheses`, { cache: "no-store" }).then(j<Hypothesis[]>),
  evidence: (id: string) => fetch(`/api/campaigns/${id}/evidence`, { cache: "no-store" }).then(j<Evidence[]>),
  attackPaths: (id: string) => fetch(`/api/campaigns/${id}/attack-paths`, { cache: "no-store" }).then(j<AttackPath[]>),
  graph: (id: string) => fetch(`/api/campaigns/${id}/graph`, { cache: "no-store" }).then(j<Graph>),
  remediations: (id: string) => fetch(`/api/campaigns/${id}/remediations`, { cache: "no-store" }).then(j<Remediation[]>),
  retests: (id: string) => fetch(`/api/campaigns/${id}/retests`, { cache: "no-store" }).then(j<Retest[]>),
  audit: (id: string) => fetch(`/api/campaigns/${id}/audit`, { cache: "no-store" }).then(j<AuditEvent[]>),
};

export const PHASES: { key: string; label: string; states: CampaignState[] }[] = [
  { key: "scoping", label: "Scope", states: ["SCOPING"] },
  { key: "recon", label: "Recon", states: ["RECON"] },
  { key: "planning", label: "Plan", states: ["ATTACK_PLANNING"] },
  { key: "testing", label: "Attack", states: ["TESTING"] },
  { key: "validation", label: "Validate", states: ["VALIDATION"] },
  { key: "chain_analysis", label: "Chain", states: ["ATTACK_CHAIN_ANALYSIS"] },
  { key: "reporting", label: "Report", states: ["REPORTING"] },
  { key: "remediation", label: "Remediate", states: ["REMEDIATION"] },
  { key: "retest", label: "Retest", states: ["RETEST"] },
  { key: "complete", label: "Verified", states: ["COMPLETE"] },
];
