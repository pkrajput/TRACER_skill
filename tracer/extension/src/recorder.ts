/**
 * The recorder loop for human edits.
 *
 * Watch <repo>/.git/logs/HEAD (git appends a line on every commit), and for each new
 * commit that was not made by the agent driver:
 *   1. ask the human why (InputBox, prefilled with the commit message; Escape = use it),
 *   2. `codegraph-trace record human-<shortsha> --author human ...` (tags + locks),
 *   3. `codebase-memory-mcp cli index_repository {mode: fast}` then `codegraph-trace
 *      reconcile` (keeps the graph fresh, no manual reconcile ever again),
 *   4. `codegraph-trace branches derive` (keeps the decision ledger up to date).
 *
 * Recording is post-hoc: the commit itself is never blocked.
 */
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { execFileAsync, git, invalidateGraphDbCache, runTrace } from "./cli";
import { getSettings, output } from "./config";

/** Watches HEAD and records non-driver commits as human-written (locked) steps. */
export class CommitRecorder implements vscode.Disposable {
  private watcher?: vscode.FileSystemWatcher;
  private statusBar: vscode.StatusBarItem;
  private processing = false;
  private rerun = false;
  private debounceTimer?: NodeJS.Timeout;

  constructor(private context: vscode.ExtensionContext) {
    this.statusBar = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      50
    );
  }

  private stateKey(): string {
    return `codegraph.lastHead:${getSettings().repoRoot}`;
  }

  /** Start watching ``.git/logs/HEAD`` for new commits in the workspace repo. */
  async activate(): Promise<void> {
    const s = getSettings();
    if (!s.repoRoot || !fs.existsSync(path.join(s.repoRoot, ".git"))) {
      output.appendLine(
        `[recorder] no git repo at '${s.repoRoot}'; commit watcher not started.`
      );
      return;
    }

    // Initialise oldHead so the first watched commit diffs against the right base.
    if (!this.context.globalState.get<string>(this.stateKey())) {
      try {
        const head = await git(["rev-parse", "HEAD"]);
        await this.context.globalState.update(this.stateKey(), head);
      } catch {
        // Repo with no commits yet; leave unset and record from scratch later.
      }
    }

    this.watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(s.repoRoot), ".git/logs/HEAD")
    );
    const onEvent = () => this.scheduleProcess();
    this.watcher.onDidChange(onEvent);
    this.watcher.onDidCreate(onEvent);
    output.appendLine(`[recorder] watching ${s.repoRoot}/.git/logs/HEAD`);
  }

  /** Git can append several lines in quick succession; debounce and serialize. */
  private scheduleProcess(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => void this.process(), 400);
  }

  private async process(): Promise<void> {
    if (this.processing) {
      this.rerun = true;
      return;
    }
    this.processing = true;
    try {
      await this.handleHeadChange();
    } catch (err) {
      output.appendLine(`[recorder] ${(err as Error).message}`);
    } finally {
      this.processing = false;
      if (this.rerun) {
        this.rerun = false;
        this.scheduleProcess();
      }
    }
  }

  private async handleHeadChange(): Promise<void> {
    const newHead = await git(["rev-parse", "HEAD"]);
    const oldHead = this.context.globalState.get<string>(this.stateKey()) ?? "";
    if (!newHead || newHead === oldHead) {
      return;
    }

    const commits = await this.commitsBetween(oldHead, newHead);
    if (commits.length === 0) {
      // Amend / rebase / reset: HEAD moved but not forward. Adopt the new head silently.
      output.appendLine(
        `[recorder] HEAD moved non-linearly (${oldHead.slice(0, 8)} -> ` +
          `${newHead.slice(0, 8)}); adopting without recording.`
      );
      await this.context.globalState.update(this.stateKey(), newHead);
      return;
    }

    const s = getSettings();
    let recordedAny = false;
    let before = oldHead;
    for (const sha of commits) {
      const author = (
        await git(["log", "-1", "--format=%an", sha])
      ).trim();
      if (author === s.driverAuthor) {
        // The agent driver already records its own steps; just advance the base.
        output.appendLine(`[recorder] skipping driver commit ${sha.slice(0, 8)}`);
        before = sha;
        await this.context.globalState.update(this.stateKey(), sha);
        continue;
      }
      await this.recordHumanCommit(before || undefined, sha);
      recordedAny = true;
      before = sha;
      await this.context.globalState.update(this.stateKey(), sha);
    }

    if (recordedAny) {
      await this.refreshGraphAndLedger();
    }
  }

  private async commitsBetween(oldHead: string, newHead: string): Promise<string[]> {
    if (!oldHead) {
      return [newHead];
    }
    try {
      const out = await git(["rev-list", "--reverse", `${oldHead}..${newHead}`]);
      return out ? out.split(/\r?\n/).filter(Boolean) : [];
    } catch {
      return []; // oldHead unknown to this repo (e.g. after a rewrite): non-linear.
    }
  }

  private async recordHumanCommit(
    before: string | undefined,
    after: string
  ): Promise<void> {
    const shortSha = after.slice(0, 8);
    const commitMessage = (
      await git(["log", "-1", "--format=%B", after])
    ).trim();

    // Ask the human why - after the fact, never blocking the commit. Escape silently
    // falls back to the commit message as the reasoning.
    const reasoning =
      (await vscode.window.showInputBox({
        title: `Codegraph: record commit ${shortSha}`,
        prompt: "One line: why this change?",
        value: commitMessage,
        ignoreFocusOut: true,
      })) ?? commitMessage;

    const args = [
      "record",
      `human-${shortSha}`,
      "--author",
      "human",
      "--reasoning",
      reasoning,
      "--after",
      after,
      "--no-embeddings",
    ];
    if (before) {
      args.push("--before", before);
    }
    const out = await runTrace(args);
    output.appendLine(out.trim());
    vscode.window.setStatusBarMessage(
      `$(check) Codegraph: recorded human-${shortSha}`,
      4000
    );
  }

  /** Reindex + reconcile + branches derive, with a status-bar spinner. */
  private async refreshGraphAndLedger(): Promise<void> {
    const s = getSettings();
    this.statusBar.text = "$(sync~spin) Codegraph: reindex + reconcile";
    this.statusBar.show();
    try {
      try {
        const payload = JSON.stringify({ repo_path: s.repoRoot, mode: "fast" });
        const { stdout } = await execFileAsync(
          s.cbmCliPath,
          ["cli", "index_repository", payload],
          { cwd: s.repoRoot }
        );
        output.appendLine(stdout.trim());
        // Reindex may create/replace the cache DB; re-resolve before reconcile.
        invalidateGraphDbCache();
      } catch (err) {
        output.appendLine(
          `[recorder] index_repository failed (${(err as Error).message}); ` +
            "reconcile will run against the existing graph."
        );
      }
      try {
        const out = await runTrace(["reconcile", "--json", "--no-embeddings"]);
        output.appendLine(out.trim());
      } catch {
        // Already logged by runTrace; a stale graph is not fatal for the recording.
      }
      this.statusBar.text = "$(sync~spin) Codegraph: branches derive";
      const derived = await runTrace(["branches", "derive", "--json"]);
      output.appendLine(derived.trim());
    } finally {
      this.statusBar.hide();
    }
  }

  /** Stop the HEAD watcher and status-bar item. */
  dispose(): void {
    this.watcher?.dispose();
    this.statusBar.dispose();
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
  }
}
