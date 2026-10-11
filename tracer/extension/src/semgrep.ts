/**
 * 'Codegraph: Scan with Semgrep' - run the scanner, join findings with the trace via
 * `codegraph-trace flag --json`, and turn each report row into a vscode.Diagnostic
 * (squiggles in the editor). Every diagnostic carries a quick action
 * 'Show reasoning and decisions' that opens the visual panel zoomed on that node.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { execFileAsync, runTraceJson } from "./cli";
import { getSettings, output } from "./config";
import { shortSymbolName } from "./names";

/** One row from ``codegraph-trace flag --json`` (finding + joined trace story). */
export interface FlagRow {
  check_id: string;
  severity: string | null;
  message: string | null;
  path: string;
  start_line: number;
  end_line: number;
  location: string;
  symbol: string;
  symbol_kind: string;
  author: string | null;
  locked: boolean;
  touch_count: number;
  steps: { step_id: string; seq: number | null; author: string | null; reasoning: string }[];
  reasoning_snippets: string[];
  branch_summary: {
    attempts: number;
    survived: number;
    abandoned: number;
    revised: number;
    error_retry: number;
  };
  heuristics: {
    sensitive_reasoning: { value: boolean; matched: string[] };
    one_shot_confident: { value: boolean; hedging_matched: string[] };
    review_first: boolean;
    note: string | null;
  };
}

interface FlagReport {
  findings_total: number;
  rows: FlagRow[];
}

function severityOf(row: FlagRow): vscode.DiagnosticSeverity {
  switch ((row.severity || "").toUpperCase()) {
    case "ERROR":
      return vscode.DiagnosticSeverity.Error;
    case "WARNING":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function diagnosticMessage(row: FlagRow): string {
  const h = row.heuristics;
  const parts: string[] = [];
  parts.push(`${row.check_id}: ${row.message ?? ""}`.trim());
  parts.push(
    `symbol: ${shortSymbolName(row.symbol, row.path)} | author: ${row.author ?? "unrecorded"}` +
      `${row.locked ? " (locked)" : ""} | touches: ${row.touch_count} | ` +
      `branches: ${row.branch_summary.attempts} attempt(s), ` +
      `${row.branch_summary.abandoned} abandoned, ` +
      `${row.branch_summary.error_retry} error retr(ies)`
  );
  const sens = h.sensitive_reasoning.value
    ? `yes (${h.sensitive_reasoning.matched.join(", ")})`
    : "no";
  parts.push(
    `heuristics: sensitive_reasoning=${sens}, ` +
      `one_shot_confident=${h.one_shot_confident.value ? "yes" : "no"}`
  );
  if (row.reasoning_snippets.length) {
    const snippet = row.reasoning_snippets[0].replace(/\s+/g, " ").trim();
    parts.push(
      `reasoning: ${snippet.length > 220 ? snippet.slice(0, 220) + "…" : snippet}`
    );
  }
  if (h.review_first && h.note) {
    parts.push(`>>> ${h.note}`);
  }
  return parts.join("\n");
}

/** Runs Semgrep, joins via ``flag``, and publishes diagnostics in the editor. */
export class SemgrepScanner implements vscode.Disposable {
  readonly diagnostics =
    vscode.languages.createDiagnosticCollection("codegraph-semgrep");
  /** Diagnostic -> report row, so the quick action can deep-link to the symbol. */
  private rowsByKey = new Map<string, FlagRow>();

  /** Stable map key for a diagnostic (uri + line + check id). */
  key(uri: vscode.Uri, diag: vscode.Diagnostic): string {
    return `${uri.toString()}:${diag.range.start.line}:${diag.code}`;
  }

  /** Look up the flag row backing a published diagnostic. */
  rowFor(uri: vscode.Uri, diag: vscode.Diagnostic): FlagRow | undefined {
    return this.rowsByKey.get(this.key(uri, diag));
  }

  /** Run Semgrep, join with the trace, and refresh editor diagnostics. */
  async scan(): Promise<void> {
    const s = getSettings();
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Codegraph: Semgrep scan",
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: `semgrep --config ${s.semgrepConfig} ...` });
        const findingsPath = path.join(
          os.tmpdir(),
          `codegraph-findings-${Date.now()}.json`
        );
        try {
          await this.runSemgrep(findingsPath);
          progress.report({ message: "joining findings with the trace..." });
          // --save persists the report to .codegraph-trace/findings-report.json so the
          // visual panel's has-finding filter reflects the latest in-editor scan.
          const report = await runTraceJson<FlagReport>([
            "flag",
            "--findings",
            findingsPath,
            "--json",
            "--save",
          ]);
          this.publish(report);
          const flagged = report.rows.filter(
            (r) => r.heuristics.review_first
          ).length;
          vscode.window.showInformationMessage(
            `Codegraph: ${report.rows.length} finding(s)` +
              (flagged
                ? `, ${flagged} marked review-first (possible hallucinated safety)`
                : "")
          );
        } finally {
          fs.rmSync(findingsPath, { force: true });
        }
      }
    );
  }

  private async runSemgrep(findingsPath: string): Promise<void> {
    const s = getSettings();
    const args = [
      "scan",
      "--config",
      s.semgrepConfig,
      "--json",
      "--output",
      findingsPath,
      s.repoRoot,
    ];
    try {
      const { stderr } = await execFileAsync(s.semgrepPath, args, {
        cwd: s.repoRoot,
      });
      if (stderr.trim()) {
        output.appendLine(stderr.trim());
      }
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code !== "ENOENT") {
        throw err;
      }
      // semgrep binary not on PATH: fall back to the venv's `python -m semgrep`.
      output.appendLine(
        `[semgrep] '${s.semgrepPath}' not found; trying '${s.pythonPath} -m semgrep'`
      );
      await execFileAsync(s.pythonPath, ["-m", "semgrep", ...args], {
        cwd: s.repoRoot,
      });
    }
  }

  private publish(report: FlagReport): void {
    const s = getSettings();
    this.diagnostics.clear();
    this.rowsByKey.clear();

    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const row of report.rows) {
      const abs = path.isAbsolute(row.path)
        ? row.path
        : path.join(s.repoRoot, row.path);
      const uri = vscode.Uri.file(abs);
      const range = new vscode.Range(
        Math.max(0, row.start_line - 1),
        0,
        Math.max(0, row.end_line - 1),
        Number.MAX_SAFE_INTEGER
      );
      const diag = new vscode.Diagnostic(
        range,
        diagnosticMessage(row),
        severityOf(row)
      );
      diag.source = "codegraph-semgrep";
      diag.code = row.check_id;
      const list = byFile.get(uri.toString()) ?? [];
      list.push(diag);
      byFile.set(uri.toString(), list);
      this.rowsByKey.set(this.key(uri, diag), row);
    }
    for (const [uriStr, diags] of byFile) {
      this.diagnostics.set(vscode.Uri.parse(uriStr), diags);
    }
    output.appendLine(
      `[semgrep] published ${report.rows.length} diagnostic(s) across ` +
        `${byFile.size} file(s).`
    );
  }

  /** Clear published Semgrep diagnostics. */
  dispose(): void {
    this.diagnostics.dispose();
  }
}

/** Quick action on codegraph-semgrep diagnostics: open the panel zoomed on the node. */
export class ShowReasoningActionProvider implements vscode.CodeActionProvider {
  static readonly metadata: vscode.CodeActionProviderMetadata = {
    providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
  };

  constructor(private scanner: SemgrepScanner) {}

  /** Offer "Show reasoning and decisions" on each codegraph-semgrep diagnostic. */
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== "codegraph-semgrep") {
        continue;
      }
      const row = this.scanner.rowFor(document.uri, diag);
      if (!row) {
        continue;
      }
      const action = new vscode.CodeAction(
        "Show reasoning and decisions",
        vscode.CodeActionKind.QuickFix
      );
      action.isPreferred = true;
      action.diagnostics = [diag];
      action.command = {
        command: "codegraph.showReasoning",
        title: "Show reasoning and decisions",
        arguments: [{ symbol: row.symbol, file: row.path }],
      };
      actions.push(action);
    }
    return actions;
  }
}
