/**
 * The one bridge between the extension and the Python CLI. The extension never
 * reimplements recording logic: every action below is a child-process call to
 * `python -m codegraph_trace.cli ...` (or git / semgrep / codebase-memory-mcp),
 * with stdout parsed as JSON where the CLI supports --json.
 */
import * as cp from "child_process";
import { getSettings, output } from "./config";

/** Captured stdout/stderr from a child-process call. */
export interface ExecResult {
  stdout: string;
  stderr: string;
}

interface ResolveGraphDbResult {
  ok: boolean;
  repo: string;
  graph_db: string | null;
  error?: string;
}

/** Cached verified code-map path for the current repo (null = missing / failed). */
let resolvedGraphDb: string | null | undefined;
let resolvedForRepo: string | undefined;

/** Promise wrapper around ``child_process.execFile`` with a large maxBuffer. */
export function execFileAsync(
  file: string,
  args: string[],
  options: cp.ExecFileOptions = {}
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    cp.execFile(
      file,
      args,
      { maxBuffer: 64 * 1024 * 1024, ...options },
      (err, stdout, stderr) => {
        if (err) {
          const e = err as Error & { stdout?: string; stderr?: string };
          e.stdout = stdout?.toString();
          e.stderr = stderr?.toString();
          reject(e);
        } else {
          resolve({ stdout: stdout.toString(), stderr: stderr.toString() });
        }
      }
    );
  });
}

/**
 * Resolve the code-map DB for the open repo and cache it.
 * Always prefers settings.graphDbPath when set; Python verifies ownership.
 * Returns null (and logs a setup message) when no matching map exists.
 */
export async function ensureGraphDb(): Promise<string | null> {
  const s = getSettings();
  if (resolvedGraphDb !== undefined && resolvedForRepo === s.repoRoot) {
    return resolvedGraphDb;
  }
  const args = [
    "-m",
    "codegraph_trace.cli",
    "resolve-graph-db",
    "--json",
    "--repo",
    s.repoRoot,
  ];
  if (s.graphDbPath) {
    args.push("--graph-db", s.graphDbPath);
  }
  output.appendLine(`$ ${s.pythonPath} ${args.join(" ")}`);
  try {
    const { stdout, stderr } = await execFileAsync(s.pythonPath, args, {
      cwd: s.repoRoot,
    });
    if (stderr.trim()) {
      output.appendLine(stderr.trim());
    }
    const data = JSON.parse(stdout) as ResolveGraphDbResult;
    if (!data.ok || !data.graph_db) {
      const msg = data.error || "No matching code-map database for this repository.";
      output.appendLine(`[graph-db] ${msg}`);
      resolvedGraphDb = null;
      resolvedForRepo = s.repoRoot;
      return null;
    }
    resolvedGraphDb = data.graph_db;
    resolvedForRepo = s.repoRoot;
    output.appendLine(`[graph-db] using ${resolvedGraphDb}`);
    return resolvedGraphDb;
  } catch (err) {
    const e = err as Error & { stdout?: string; stderr?: string };
    // resolve-graph-db exits 2 with JSON on stdout when setup is incomplete.
    if (e.stdout) {
      try {
        const data = JSON.parse(e.stdout) as ResolveGraphDbResult;
        if (data.error) {
          output.appendLine(`[graph-db] ${data.error}`);
          resolvedGraphDb = null;
          resolvedForRepo = s.repoRoot;
          return null;
        }
      } catch {
        // fall through
      }
    }
    output.appendLine(`[graph-db] resolve failed: ${e.message}`);
    if (e.stderr) {
      output.appendLine(e.stderr);
    }
    resolvedGraphDb = null;
    resolvedForRepo = s.repoRoot;
    return null;
  }
}

/** Clear the cached path (e.g. after reindex so the next command re-resolves). */
export function invalidateGraphDbCache(): void {
  resolvedGraphDb = undefined;
  resolvedForRepo = undefined;
}

/** Run a codegraph-trace subcommand; --repo/--graph-db are appended from settings + resolve. */
export async function runTrace(args: string[]): Promise<string> {
  const s = getSettings();
  const full = ["-m", "codegraph_trace.cli", ...args, "--repo", s.repoRoot];
  // Only pass a path verified for this repo — never fall back to an unchecked setting.
  const graphDb = await ensureGraphDb();
  if (graphDb) {
    full.push("--graph-db", graphDb);
  }
  output.appendLine(`$ ${s.pythonPath} ${full.join(" ")}`);
  try {
    const { stdout, stderr } = await execFileAsync(s.pythonPath, full, {
      cwd: s.repoRoot,
    });
    if (stderr.trim()) {
      output.appendLine(stderr.trim());
    }
    return stdout;
  } catch (err) {
    const e = err as Error & { stdout?: string; stderr?: string };
    output.appendLine(`[error] ${e.message}`);
    if (e.stderr) {
      output.appendLine(e.stderr);
    }
    throw err;
  }
}

/** Like ``runTrace``, but parse stdout as JSON (subcommand must support ``--json``). */
export async function runTraceJson<T>(args: string[]): Promise<T> {
  const stdout = await runTrace(args);
  return JSON.parse(stdout) as T;
}

/** Run git in the recorded repo. */
export async function git(args: string[]): Promise<string> {
  const s = getSettings();
  const { stdout } = await execFileAsync("git", args, { cwd: s.repoRoot });
  return stdout.trim();
}
