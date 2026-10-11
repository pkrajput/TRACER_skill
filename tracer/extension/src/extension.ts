/**
 * codegraph-recorder: a thin shell over the codegraph-trace Python CLI.
 *
 * Four jobs: (a) record human commits into the same trace as the agent's, (b) keep the
 * code graph fresh (reindex + reconcile after every human commit), (c) keep the decision
 * ledger up to date (branches derive), and (d) show everything inside the editor
 * (Semgrep-joined diagnostics + the visual panel). If this extension disappeared
 * tomorrow, the CLI would still do everything.
 */
import * as path from "path";
import * as vscode from "vscode";
import { ensureGraphDb, runTrace, runTraceJson } from "./cli";
import { getSettings, output } from "./config";

interface SymbolContent {
  file: string;
  qualified_name: string;
  historical: {
    content: string | null;
    source_seq: number | null;
    source: string;
  } | null;
  current: { exists: boolean; start_line?: number; end_line?: number };
}

interface RestoreArgs {
  file: string;
  qualifiedName: string;
  seq?: number;
  branchId?: number;
}

interface OpenInEditorArgs {
  file: string;
  line?: number;
}
import { PanelServer } from "./panel";
import { ReasoningOverlay } from "./reasoning";
import { CommitRecorder } from "./recorder";
import { SemgrepScanner, ShowReasoningActionProvider } from "./semgrep";

/** VS Code entry point: wire recorder, Semgrep, panel, hover overlay, and commands. */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
  output.appendLine("codegraph-recorder activating");

  const recorder = new CommitRecorder(context);
  const scanner = new SemgrepScanner();
  const panel = new PanelServer();
  const reasoning = new ReasoningOverlay();
  context.subscriptions.push(recorder, scanner, panel, reasoning, output);

  context.subscriptions.push(
    vscode.commands.registerCommand("codegraph.scanWithSemgrep", async () => {
      try {
        await scanner.scan();
      } catch (err) {
        vscode.window.showErrorMessage(
          `Codegraph scan failed: ${(err as Error).message} (see 'Codegraph Recorder' output)`
        );
      }
    }),
    vscode.commands.registerCommand("codegraph.openPanel", () => panel.open()),
    vscode.commands.registerCommand(
      "codegraph.showReasoning",
      (target?: string | { symbol?: string; node?: string; file?: string }) =>
        panel.open(target)
    ),
    vscode.commands.registerCommand("codegraph.rollback", async (seq?: number) => {
      if (typeof seq !== "number") {
        const raw = await vscode.window.showInputBox({
          prompt: "Step number to roll back to (see 'codegraph-trace versions')",
          validateInput: (v) => (/^\d+$/.test(v.trim()) ? undefined : "Enter a step number"),
        });
        if (!raw) {
          return;
        }
        seq = parseInt(raw.trim(), 10);
      }
      const branch = `rollback/step-${seq}`;
      try {
        // Non-destructive: a git checkout onto a new branch at that version's commit;
        // the trace, snapshots, and embeddings are never touched.
        const stdout = await runTrace(["goto", String(seq), "--branch", branch]);
        const text = stdout.trim();
        output.appendLine(text);
        const pick = await vscode.window.showInformationMessage(
          `Codegraph: created branch '${branch}' at step ${seq}. ` +
            `Nothing was lost - the CLI's instructions are in the output channel.`,
          "Show instructions"
        );
        if (pick === "Show instructions") {
          output.show(true);
        }
      } catch (err) {
        const e = err as Error & { stderr?: string };
        const detail = (e.stderr || e.message || "").trim();
        output.appendLine(`[rollback] ${detail}`);
        vscode.window.showErrorMessage(
          `Codegraph rollback failed: ${detail.split("\n")[0]} ` +
            `(commit/stash your changes first, or run 'codegraph-trace goto ${seq} ` +
            `--branch ${branch} --force' from a terminal)`
        );
      }
    }),
    vscode.commands.registerCommand(
      "codegraph.restoreSymbol",
      async (args?: RestoreArgs) => {
        if (!args?.file || !args?.qualifiedName) {
          vscode.window.showErrorMessage(
            "Codegraph: restore needs a file and symbol (use the panel's restore buttons)."
          );
          return;
        }
        const cliArgs = ["symbol-content", args.file, args.qualifiedName, "--json"];
        if (typeof args.branchId === "number") {
          cliArgs.push("--branch-id", String(args.branchId));
        } else if (typeof args.seq === "number") {
          cliArgs.push("--at-seq", String(args.seq));
        } else {
          vscode.window.showErrorMessage(
            "Codegraph: restore needs a step number or a branch id."
          );
          return;
        }
        try {
          const res = await runTraceJson<SymbolContent>(cliArgs);
          const content = res.historical?.content;
          if (!content) {
            vscode.window.showWarningMessage(
              `Codegraph: no recorded content for ${args.qualifiedName} at that point.`
            );
            return;
          }
          const s = getSettings();
          const abs = path.join(s.repoRoot, args.file);
          const doc = await vscode.workspace.openTextDocument(abs);
          const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
          const edit = new vscode.WorkspaceEdit();
          const asOf =
            typeof args.branchId === "number"
              ? `abandoned attempt (step ${res.historical?.source_seq ?? "?"})`
              : `step ${res.historical?.source_seq ?? args.seq}`;
          if (res.current.exists && res.current.start_line && res.current.end_line) {
            const start = new vscode.Position(res.current.start_line - 1, 0);
            const endLine = Math.min(res.current.end_line - 1, doc.lineCount - 1);
            const end = doc.lineAt(endLine).range.end;
            edit.replace(doc.uri, new vscode.Range(start, end), content);
          } else {
            const pick = await vscode.window.showWarningMessage(
              `Codegraph: ${args.qualifiedName} no longer exists in ${args.file}. ` +
                `Insert the ${asOf} version at the end of the file?`,
              "Insert"
            );
            if (pick !== "Insert") {
              return;
            }
            const last = doc.lineAt(Math.max(0, doc.lineCount - 1)).range.end;
            edit.insert(doc.uri, last, `\n\n${content}\n`);
          }
          const applied = await vscode.workspace.applyEdit(edit);
          if (applied) {
            editor.revealRange(
              new vscode.Range(
                Math.max(0, (res.current.start_line ?? doc.lineCount) - 1), 0,
                Math.max(0, (res.current.start_line ?? doc.lineCount) - 1), 0
              ),
              vscode.TextEditorRevealType.InCenter
            );
            vscode.window.showInformationMessage(
              `Codegraph: restored ${args.qualifiedName} to its ${asOf} version - ` +
                `an ordinary editor edit, undo with Ctrl+Z.`
            );
          } else {
            vscode.window.showErrorMessage("Codegraph: the editor rejected the edit.");
          }
        } catch (err) {
          const e = err as Error & { stderr?: string };
          const detail = (e.stderr || e.message || "").trim();
          output.appendLine(`[restore] ${detail}`);
          vscode.window.showErrorMessage(
            `Codegraph restore failed: ${detail.split("\n")[0]}`
          );
        }
      }
    ),
    vscode.commands.registerCommand(
      "codegraph.openInEditor",
      async (args?: OpenInEditorArgs) => {
        if (!args?.file) {
          vscode.window.showErrorMessage(
            "Codegraph: open needs a file (use the panel's Open to view button)."
          );
          return;
        }
        try {
          const s = getSettings();
          const abs = path.join(s.repoRoot, args.file);
          const doc = await vscode.workspace.openTextDocument(abs);
          const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
          const line1 = typeof args.line === "number" && args.line > 0 ? args.line : 1;
          const line0 = Math.min(Math.max(0, line1 - 1), Math.max(0, doc.lineCount - 1));
          const range = new vscode.Range(line0, 0, line0, 0);
          editor.selection = new vscode.Selection(range.start, range.start);
          editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
        } catch (err) {
          const e = err as Error;
          output.appendLine(`[openInEditor] ${e.message}`);
          vscode.window.showErrorMessage(
            `Codegraph open failed: ${e.message.split("\n")[0]}`
          );
        }
      }
    ),
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new ShowReasoningActionProvider(scanner),
      ShowReasoningActionProvider.metadata
    )
  );

  await recorder.activate();
  reasoning.activate();

  // Best-effort: ensure .codegraph-trace/ is gitignored (and untracked) so the recorder
  // never treats its own outputs as application code. Failure is non-fatal.
  runTrace(["ensure-ignore"]).catch((err) => {
    output.appendLine(`[ensure-ignore] ${(err as Error).message}`);
  });

  // Resolve the exact code-map DB for this workspace before any command uses the cache.
  // Never silently fall through to another project's map.
  const graphDb = await ensureGraphDb();
  if (!graphDb) {
    void vscode.window.showWarningMessage(
      "Codegraph: no code-map database matches this repository. " +
        "Index it with codebase-memory-mcp, then set codegraph.graphDbPath " +
        "(or leave it empty for verified auto-discovery). See the Codegraph Recorder output."
    );
  }

  // Start the panel server eagerly so the first quick-action click is instant; a failure
  // here (e.g. Flask missing) is logged and retried lazily on first open.
  panel.start().catch((err) => {
    output.appendLine(`[panel] deferred start failed: ${(err as Error).message}`);
  });
}

/** VS Code teardown hook (disposables are registered on the context). */
export function deactivate(): void {
  // Disposal (child processes included) happens via context.subscriptions.
}
