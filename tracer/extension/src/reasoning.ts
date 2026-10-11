/**
 * Reasoning in the editor: hovering a recorded symbol shows its last reasoning, author
 * (human or agent) and lock state, and a subtle gutter mark flags every recorded symbol.
 *
 * Thin-shell rule: all data comes from the CLI (`codegraph-trace overlay <file> --json`,
 * with `symbol-at` as the per-line fallback); the extension never reads trace.db itself.
 */
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { runTraceJson } from "./cli";
import { getSettings, output } from "./config";
import { shortSymbolName } from "./names";

interface OverlaySymbol {
  qualified_name: string;
  label: string | null;
  start_line: number;
  end_line: number;
  author: string | null;
  locked: boolean;
  last_seq: number | null;
  last_step_id: string | null;
  last_prompt: string;
  last_reasoning: string;
}

interface OverlayReport {
  file: string;
  symbols: OverlaySymbol[];
}

interface SymbolAtResult {
  file: string;
  line: number;
  qualified_name: string | null;
  label?: string;
  start_line?: number;
  end_line?: number;
}

function truncate(text: string, max = 700): string {
  const clean = text.trim();
  return clean.length <= max ? clean : clean.slice(0, max) + " …";
}

/** Repo-relative, forward-slashed path for a document, or undefined if outside the repo. */
function relPath(doc: vscode.TextDocument): string | undefined {
  const s = getSettings();
  if (!s.repoRoot || doc.uri.scheme !== "file") {
    return undefined;
  }
  const rel = path.relative(s.repoRoot, doc.uri.fsPath);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    return undefined;
  }
  return rel.replace(/\\/g, "/");
}

/** Hover provider + gutter marks over recorded symbols (data from the CLI overlay). */
export class ReasoningOverlay implements vscode.Disposable, vscode.HoverProvider {
  /** rel path -> overlay symbols (refreshed on editor switch and save). */
  private cache = new Map<string, OverlaySymbol[]>();
  private timer?: NodeJS.Timeout;
  private disposables: vscode.Disposable[] = [];

  /** The subtle gutter mark: a 3px teal left border on every recorded symbol's span. */
  private readonly decoration = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    borderWidth: "0 0 0 3px",
    borderStyle: "solid",
    borderColor: "rgba(78, 201, 176, 0.6)",
    overviewRulerColor: "rgba(78, 201, 176, 0.4)",
    overviewRulerLane: vscode.OverviewRulerLane.Left,
  });

  /** Register hover/gutter listeners when ``.codegraph-trace`` exists under the repo. */
  activate(): void {
    // Only light up for recorded repos.
    const s = getSettings();
    if (!s.repoRoot || !fs.existsSync(path.join(s.repoRoot, ".codegraph-trace"))) {
      output.appendLine("[reasoning] no .codegraph-trace directory; overlay disabled");
      return;
    }
    this.disposables.push(
      vscode.window.onDidChangeActiveTextEditor(() => this.schedule()),
      vscode.workspace.onDidSaveTextDocument(() => this.schedule(true)),
      vscode.languages.registerHoverProvider({ scheme: "file" }, this)
    );
    this.schedule();
  }

  private schedule(invalidate = false): void {
    if (this.timer) {
      clearTimeout(this.timer);
    }
    this.timer = setTimeout(() => {
      void this.refresh(invalidate);
    }, 300);
  }

  private async refresh(invalidate: boolean): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return;
    }
    const rel = relPath(editor.document);
    if (!rel) {
      return;
    }
    if (invalidate) {
      this.cache.delete(rel);
    }
    try {
      const symbols = await this.symbolsFor(rel);
      this.applyDecorations(editor, symbols);
    } catch (err) {
      output.appendLine(`[reasoning] overlay failed for ${rel}: ${(err as Error).message}`);
    }
  }

  private async symbolsFor(rel: string): Promise<OverlaySymbol[]> {
    const cached = this.cache.get(rel);
    if (cached) {
      return cached;
    }
    const report = await runTraceJson<OverlayReport>(["overlay", rel, "--json"]);
    const symbols = report.symbols ?? [];
    this.cache.set(rel, symbols);
    return symbols;
  }

  private applyDecorations(editor: vscode.TextEditor, symbols: OverlaySymbol[]): void {
    const lineCount = editor.document.lineCount;
    const ranges: vscode.Range[] = [];
    for (const sym of symbols) {
      const start = Math.max(0, Math.min(sym.start_line - 1, lineCount - 1));
      const end = Math.max(start, Math.min(sym.end_line - 1, lineCount - 1));
      ranges.push(new vscode.Range(start, 0, end, 0));
    }
    editor.setDecorations(this.decoration, ranges);
  }

  /** Show last reasoning / author / lock state for the symbol under the cursor. */
  async provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): Promise<vscode.Hover | undefined> {
    const rel = relPath(document);
    if (!rel) {
      return undefined;
    }
    let symbols: OverlaySymbol[];
    try {
      symbols = await this.symbolsFor(rel);
    } catch {
      return undefined;
    }
    if (!symbols.length) {
      return undefined;
    }
    const line = position.line + 1;
    // Innermost recorded symbol whose span contains the hovered line.
    let sym = symbols
      .filter((s) => s.start_line <= line && line <= s.end_line)
      .sort((a, b) => a.end_line - a.start_line - (b.end_line - b.start_line))[0];
    if (!sym) {
      // Spans can go stale after unrecorded edits; ask the CLI to resolve the line.
      try {
        const at = await runTraceJson<SymbolAtResult>([
          "symbol-at",
          rel,
          "--line",
          String(line),
          "--json",
        ]);
        if (at.qualified_name) {
          sym = symbols.find((s) => s.qualified_name === at.qualified_name) as OverlaySymbol;
        }
      } catch {
        return undefined;
      }
    }
    if (!sym) {
      return undefined;
    }

    const md = new vscode.MarkdownString(undefined, true);
    md.isTrusted = true;
    const lock = sym.locked ? "  $(lock) locked" : "";
    const short = shortSymbolName(sym.qualified_name, rel);
    md.appendMarkdown(
      `**${short}**\n\n` +
        `author: \`${sym.author ?? "unrecorded"}\`${lock}` +
        (sym.last_seq != null ? `  ·  last changed at step ${sym.last_seq}` : "") +
        `\n\n`
    );
    if (sym.last_reasoning) {
      md.appendMarkdown(`---\n\n${truncate(sym.last_reasoning)}\n\n`);
    } else if (sym.last_prompt) {
      md.appendMarkdown(`---\n\nprompt: ${truncate(sym.last_prompt)}\n\n`);
    }
    const args = encodeURIComponent(
      JSON.stringify([{ symbol: sym.qualified_name, file: rel }])
    );
    md.appendMarkdown(
      `[Show reasoning and decisions](command:codegraph.showReasoning?${args})`
    );
    return new vscode.Hover(md);
  }

  /** Tear down hover registration, decorations, and timers. */
  dispose(): void {
    if (this.timer) {
      clearTimeout(this.timer);
    }
    this.decoration.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
