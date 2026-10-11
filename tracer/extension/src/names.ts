/**
 * Short project-relative display names for symbols.
 *
 * Full qualified names embed a machine-path project prefix
 * (e.g. ``Users-...-game.js.connector.startGate``) and are kept only for
 * internal lookups / deep links; everything the user reads uses this helper.
 */
/** Short display name for a qualified name (leaf, or ``file › leaf`` when a path is given). */
export function shortSymbolName(qn: string, filePath?: string | null): string {
  if (!qn) {
    const fp = (filePath || "").replace(/\\/g, "/");
    return fp.split("/").filter(Boolean).slice(-1)[0] || "";
  }
  if (qn.startsWith("file::")) {
    return qn.slice(6).split("/").filter(Boolean).slice(-1)[0] || qn;
  }
  const leaf = qn.split(".").filter(Boolean).slice(-1)[0] || qn;
  if (filePath) {
    const base = filePath.replace(/\\/g, "/").split("/").filter(Boolean).slice(-1)[0];
    if (base) {
      return `${base} › ${leaf}`;
    }
  }
  const parts = qn.split(".").filter(Boolean);
  return parts.slice(-2).join(".") || qn;
}
