/**
 * The visual panel host. On activate we spawn `codegraph-trace panel --port 0` as a child
 * process (the Python side owns all the SQL and prints PANEL_URL=<...> once bound to a
 * free port), then point a Webview iframe at it. `open(target)` deep-links with
 * ?node=<qualified_name>&file=<path> so a diagnostic's quick action lands zoomed on that
 * symbol (with file-history fallback when the exact symbol has no trace rows).
 */
import * as cp from "child_process";
import * as vscode from "vscode";
import { ensureGraphDb } from "./cli";
import { getSettings, output } from "./config";

/** Deep-link target for show-reasoning: symbol QN, optional file for shared fallback. */
export type ReasoningTarget =
  | string
  | { symbol?: string; node?: string; file?: string };

function resolveTarget(target?: ReasoningTarget): { node?: string; file?: string } {
  if (!target) {
    return {};
  }
  if (typeof target === "string") {
    return { node: target };
  }
  return {
    node: target.symbol || target.node,
    file: target.file,
  };
}

/** Hosts ``codegraph-trace panel`` and shows it in a Webview iframe. */
export class PanelServer implements vscode.Disposable {
  private proc?: cp.ChildProcess;
  private url?: string;
  private starting?: Promise<string>;
  private webview?: vscode.WebviewPanel;

  /** Start the Python panel server (idempotent); resolves to its base URL. */
  start(): Promise<string> {
    if (this.url) {
      return Promise.resolve(this.url);
    }
    if (this.starting) {
      return this.starting;
    }
    this.starting = this.spawn();
    return this.starting;
  }

  private async spawn(): Promise<string> {
    const s = getSettings();
    const graphDb = await ensureGraphDb();
    if (!graphDb) {
      const msg =
        "No code-map database for this repository. Index it with codebase-memory-mcp " +
        "and set codegraph.graphDbPath (or leave unset for verified auto-discovery).";
      output.appendLine(`[panel] ${msg}`);
      void vscode.window.showWarningMessage(`Codegraph: ${msg}`);
    }
    const args = [
      "-m",
      "codegraph_trace.cli",
      "panel",
      "--port",
      "0",
      "--repo",
      s.repoRoot,
    ];
    if (graphDb) {
      args.push("--graph-db", graphDb);
    }
    output.appendLine(`$ ${s.pythonPath} ${args.join(" ")}`);
    return new Promise<string>((resolve, reject) => {
      const proc = cp.spawn(s.pythonPath, args, { cwd: s.repoRoot });
      this.proc = proc;
      const timeout = setTimeout(
        () => reject(new Error("panel server did not start within 30s")),
        30000
      );
      let buffer = "";
      proc.stdout.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        const match = buffer.match(/PANEL_URL=(\S+)/);
        if (match && !this.url) {
          clearTimeout(timeout);
          this.url = match[1];
          output.appendLine(`[panel] serving at ${this.url}`);
          resolve(this.url);
        }
      });
      proc.stderr.on("data", (chunk: Buffer) =>
        output.appendLine(`[panel] ${chunk.toString().trim()}`)
      );
      proc.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      proc.on("exit", (code) => {
        output.appendLine(`[panel] server exited (${code})`);
        this.url = undefined;
        this.starting = undefined;
        this.proc = undefined;
      });
    });
  }

  /** Open (or reveal) the Webview, optionally zoomed on a node's qualified name. */
  async open(target?: ReasoningTarget): Promise<void> {
    let base: string;
    try {
      base = await this.start();
    } catch (err) {
      vscode.window.showErrorMessage(
        `Codegraph panel failed to start: ${(err as Error).message}`
      );
      return;
    }
    const { node, file } = resolveTarget(target);
    let url = base;
    if (node) {
      const q = new URLSearchParams();
      q.set("node", node);
      if (file) {
        q.set("file", file);
      }
      url = `${base}?${q.toString()}`;
    }

    if (!this.webview) {
      this.webview = vscode.window.createWebviewPanel(
        "codegraphPanel",
        "Codegraph Trace",
        vscode.ViewColumn.Beside,
        { enableScripts: true, retainContextWhenHidden: true }
      );
      this.webview.onDidDispose(() => (this.webview = undefined));
      // The panel page posts messages to its parent (the wrapper below), which forwards
      // them here; the extension runs the CLI (rollback) or applies the edit (restore).
      this.webview.webview.onDidReceiveMessage(
        (msg: {
          type?: string;
          seq?: number;
          file?: string;
          line?: number;
          qualifiedName?: string;
          branchId?: number;
        }) => {
          if (msg?.type === "rollback" && typeof msg.seq === "number") {
            void vscode.commands.executeCommand("codegraph.rollback", msg.seq);
          } else if (
            msg?.type === "restoreSymbol" &&
            typeof msg.file === "string" &&
            typeof msg.qualifiedName === "string"
          ) {
            void vscode.commands.executeCommand("codegraph.restoreSymbol", msg);
          } else if (msg?.type === "openInEditor" && typeof msg.file === "string") {
            void vscode.commands.executeCommand("codegraph.openInEditor", msg);
          }
        }
      );
    } else {
      this.webview.reveal(vscode.ViewColumn.Beside, true);
    }
    this.webview.webview.html = this.iframeHtml(url);
  }

  private iframeHtml(target: string): string {
    // A full-bleed iframe; VS Code transparently forwards localhost inside webviews. The
    // wrapper script bridges the iframe's postMessage events into the extension.
    return `<!DOCTYPE html>
<html>
<head><style>
  html, body { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; }
  iframe { border: 0; width: 100%; height: 100vh; }
</style></head>
<body><iframe src="${target}"></iframe>
<script>
  const vscode = acquireVsCodeApi();
  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (!msg) { return; }
    if (msg.type === 'rollback' && typeof msg.seq === 'number') {
      vscode.postMessage({ type: 'rollback', seq: msg.seq });
    } else if (msg.type === 'restoreSymbol' && msg.file && msg.qualifiedName) {
      vscode.postMessage(msg);
    } else if (msg.type === 'openInEditor' && msg.file) {
      vscode.postMessage(msg);
    }
  });
</script>
</body>
</html>`;
  }

  /** Stop the panel process and dispose the Webview. */
  dispose(): void {
    this.webview?.dispose();
    if (this.proc && !this.proc.killed) {
      this.proc.kill();
    }
  }
}
