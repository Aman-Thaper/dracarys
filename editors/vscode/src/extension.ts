import { execFile } from "child_process";
import * as vscode from "vscode";

/** Shape of the JSON emitted by `dracarys scan --format json`. */
interface Finding {
  title: string;
  severity: string;
  confidence: string;
  category: string;
  cwe: string;
  method: string;
  url: string;
  param: string | null;
  detail: string;
  remediation: string;
}

interface ScanReport {
  target: string;
  stats?: { pages_crawled: number; requests_made: number; duration_ms: number };
  severity_breakdown?: Record<string, number>;
  findings: Finding[];
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "0.0.0.0"]);

function isLoopback(target: string): boolean {
  try {
    return LOOPBACK.has(new URL(target).hostname);
  } catch {
    return false;
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Pull the report object out of stdout. The CLI logs progress lines separately,
 * so anchor on the first `{` rather than assuming stdout is pure JSON.
 */
function parseReport(stdout: string): ScanReport {
  const start = stdout.indexOf("{");
  if (start === -1) {
    throw new Error("no JSON report found in scanner output");
  }
  return JSON.parse(stdout.slice(start)) as ScanReport;
}

function runScanner(args: string[], executable: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      args,
      { maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        // A non-zero exit is expected when --fail-on trips, and the report is
        // still on stdout, so only reject when there is nothing to parse.
        if (stdout.includes("{")) {
          resolve(stdout);
          return;
        }
        if (error) {
          const hint =
            (error as NodeJS.ErrnoException).code === "ENOENT"
              ? `Could not run "${executable}". Install it with: pipx install dracarys-dast`
              : stderr.trim() || error.message;
          reject(new Error(hint));
          return;
        }
        reject(new Error(stderr.trim() || "scanner produced no report"));
      },
    );
  });
}

function renderHtml(report: ScanReport): string {
  const findings = [...report.findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const counts = report.severity_breakdown ?? {};
  const chips = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0)
    .map(
      (s) =>
        `<span class="chip ${s}">${counts[s]} ${escapeHtml(s)}</span>`,
    )
    .join(" ");

  const rows = findings
    .map(
      (f) => `
      <tr>
        <td><span class="chip ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
        <td>
          <div class="title">${escapeHtml(f.title)}</div>
          <div class="detail">${escapeHtml(f.detail)}</div>
          <details><summary>Remediation</summary><p>${escapeHtml(f.remediation)}</p></details>
        </td>
        <td class="mono">${escapeHtml(f.cwe)}</td>
        <td class="mono">${escapeHtml(f.method)} ${escapeHtml(f.url)}${
          f.param ? `<br><span class="detail">param: ${escapeHtml(f.param)}</span>` : ""
        }</td>
      </tr>`,
    )
    .join("");

  const stats = report.stats
    ? `${report.stats.pages_crawled} pages · ${report.stats.requests_made} requests · ${report.stats.duration_ms} ms`
    : "";

  const body = findings.length
    ? `<table>
         <tr><th>Severity</th><th>Finding</th><th>CWE</th><th>Location</th></tr>
         ${rows}
       </table>`
    : `<p class="clean">No findings. Every DRACARYS finding requires a deterministic
       oracle to fire, so an empty result means nothing was confirmed — not that
       nothing was checked.</p>`;

  return `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
  body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:16px 20px;line-height:1.55}
  h1{font-size:17px;margin:0 0 4px}
  .sub{color:var(--vscode-descriptionForeground);font-size:12px;margin-bottom:14px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--vscode-panel-border);vertical-align:top}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--vscode-descriptionForeground)}
  .mono{font-family:var(--vscode-editor-font-family);font-size:12px;word-break:break-all}
  .title{font-weight:600}
  .detail{color:var(--vscode-descriptionForeground);font-size:12px}
  details{margin-top:6px}
  summary{cursor:pointer;font-size:12px;color:var(--vscode-textLink-foreground)}
  details p{margin:6px 0 0;font-size:12px;color:var(--vscode-descriptionForeground)}
  .chip{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase}
  .critical{background:#7f1d1d;color:#fee2e2}
  .high{background:#9a3412;color:#ffedd5}
  .medium{background:#854d0e;color:#fef9c3}
  .low{background:#1e3a8a;color:#dbeafe}
  .info{background:#374151;color:#e5e7eb}
  .clean{color:var(--vscode-descriptionForeground)}
</style></head>
<body>
  <h1>DRACARYS — ${escapeHtml(report.target)}</h1>
  <div class="sub">${chips} ${stats ? `· ${escapeHtml(stats)}` : ""}</div>
  ${body}
</body></html>`;
}

function showReport(report: ScanReport): void {
  const panel = vscode.window.createWebviewPanel(
    "dracarysReport",
    `DRACARYS — ${report.target}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );
  panel.webview.html = renderHtml(report);
}

async function scanCommand(output: vscode.OutputChannel): Promise<void> {
  const config = vscode.workspace.getConfiguration("dracarys");
  const target = await vscode.window.showInputBox({
    prompt: "Target URL to scan",
    value: config.get<string>("target", "http://127.0.0.1:3000"),
    validateInput: (value) => {
      try {
        const parsed = new URL(value);
        return parsed.protocol === "http:" || parsed.protocol === "https:"
          ? undefined
          : "Target must be an http(s) URL";
      } catch {
        return "Target must be a valid URL";
      }
    },
  });
  if (!target) {
    return;
  }

  const args = [
    "scan",
    target,
    "--format",
    "json",
    "--max-pages",
    String(config.get<number>("maxPages", 60)),
  ];
  if (config.get<boolean>("passive", false)) {
    args.push("--passive");
  }

  // Scanning anything other than loopback needs an explicit, deliberate opt-in.
  if (!isLoopback(target)) {
    const choice = await vscode.window.showWarningMessage(
      `${target} is not a loopback address. Only scan systems you are authorized to test.`,
      { modal: true },
      "I am authorized to scan this target",
    );
    if (choice !== "I am authorized to scan this target") {
      return;
    }
    args.push("--yes-i-am-authorized");
  }

  const executable = config.get<string>("executable", "dracarys");
  output.appendLine(`$ ${executable} ${args.join(" ")}`);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `DRACARYS scanning ${target}…` },
    async () => {
      try {
        const report = parseReport(await runScanner(args, executable));
        output.appendLine(
          `${report.findings.length} finding(s) on ${report.target}`,
        );
        showReport(report);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        output.appendLine(`error: ${message}`);
        void vscode.window.showErrorMessage(`DRACARYS: ${message}`);
      }
    },
  );
}

/** Convert a SARIF run into the report shape the webview already renders. */
function reportFromSarif(sarif: any): ScanReport {
  const run = sarif?.runs?.[0];
  const rules = new Map<string, any>();
  for (const rule of run?.tool?.driver?.rules ?? []) {
    rules.set(rule.id, rule);
  }
  const levelToSeverity: Record<string, string> = {
    error: "high",
    warning: "medium",
    note: "low",
    none: "info",
  };
  const findings: Finding[] = (run?.results ?? []).map((result: any) => {
    const rule = rules.get(result.ruleId) ?? {};
    const uri =
      result.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? "";
    return {
      title: result.message?.text ?? result.ruleId ?? "finding",
      severity: levelToSeverity[result.level] ?? "info",
      confidence: "",
      category: result.ruleId ?? "",
      cwe: (rule.properties?.tags ?? []).find((t: string) => t.startsWith("CWE-")) ?? "",
      method: "",
      url: uri,
      param: null,
      detail: rule.fullDescription?.text ?? rule.shortDescription?.text ?? "",
      remediation: rule.help?.text ?? "",
    };
  });
  const breakdown: Record<string, number> = {};
  for (const f of findings) {
    breakdown[f.severity] = (breakdown[f.severity] ?? 0) + 1;
  }
  return {
    target: run?.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? "SARIF report",
    severity_breakdown: breakdown,
    findings,
  };
}

async function openSarifCommand(): Promise<void> {
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: { SARIF: ["sarif", "json"] },
    openLabel: "Open SARIF report",
  });
  if (!picked?.length) {
    return;
  }
  try {
    const bytes = await vscode.workspace.fs.readFile(picked[0]);
    showReport(reportFromSarif(JSON.parse(Buffer.from(bytes).toString("utf8"))));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    void vscode.window.showErrorMessage(`DRACARYS: could not read SARIF — ${message}`);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("DRACARYS");
  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("dracarys.scan", () => scanCommand(output)),
    vscode.commands.registerCommand("dracarys.openSarif", openSarifCommand),
  );
}

export function deactivate(): void {
  /* nothing to tear down */
}
