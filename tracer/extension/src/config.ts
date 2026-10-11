/**
 * Extension settings and the shared OutputChannel.
 * Values come from the `codegraph.*` configuration keys (see package.json).
 */
import * as vscode from "vscode";

/** Resolved `codegraph.*` settings used by every CLI/git/semgrep call. */
export interface CodegraphSettings {
  pythonPath: string;
  repoRoot: string;
  graphDbPath: string;
  driverAuthor: string;
  cbmCliPath: string;
  semgrepPath: string;
  semgrepConfig: string;
}

/** Read the extension settings, defaulting repoRoot to the first workspace folder. */
export function getSettings(): CodegraphSettings {
  const cfg = vscode.workspace.getConfiguration("codegraph");
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
  return {
    pythonPath: cfg.get<string>("pythonPath", "python"),
    repoRoot: cfg.get<string>("repoRoot", "") || workspaceRoot,
    graphDbPath: cfg.get<string>("graphDbPath", ""),
    driverAuthor: cfg.get<string>("driverAuthor", "openhands"),
    cbmCliPath: cfg.get<string>("cbmCliPath", "codebase-memory-mcp"),
    semgrepPath: cfg.get<string>("semgrepPath", "semgrep"),
    semgrepConfig: cfg.get<string>("semgrepConfig", "p/security-audit"),
  };
}

/** Shared OutputChannel for CLI stdout/stderr and recorder status lines. */
export const output = vscode.window.createOutputChannel("Codegraph Recorder");
