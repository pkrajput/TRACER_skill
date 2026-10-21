---
name: tracer-security
description: Investigate and repair Python SAST findings using symbol-linked code evolution, separately recorded developer rationale, static evidence, and bounded runtime checks. Use for Semgrep/CodeQL triage, security review of changed code, or preserving an evidence-backed security edit note; do not use as a generic code review workflow.
---

# TRACER Security

Use the installed `tracer-security` helpers to index Python snapshots and prepare
review evidence. `tracer-security plan --help` describes patch, Semgrep JSON,
and CodeQL SARIF inputs. `prepare-agent --help` describes captured messages.
These commands prepare evidence without executing target code or calling models.
The host agent supplies its ordinary edit/test workflow and authorized model use.

Treat scanner output and historical explanations as evidence to test, not vulnerability labels. Keep these channels distinct:

- current source, Semgrep findings, and CodeQL paths or queries;
- observed symbol evolution from Git commits or recorded edits;
- natural-language rationale that was actually captured at development time.

Begin with the changed production symbols and relevant scanner flows. Include security-sensitive changed functions even when no rule fired. For an ordinary repository, build temporal evidence only from commits available at the requested cutoff. The bundled command can prepare a bounded GumTree history view:

```bash
python3 -m security_ground_truth.temporal_security.cli prepare-history \
  --repo-cache REPOSITORY --cutoff FULL_COMMIT_SHA --targets targets.json \
  --repository-kind ordinary --output history.json
```

For each plausible weakness, state the attacker-controlled input or precondition and the security property. Inspect current AST structure and data flow, then classify the current evidence as `supported`, `refuted`, or `inconclusive`. Bind a conclusive assessment to an exact quotation from the current source and explain its relevance. History may explain how a condition arose, but it does not prove present behavior.

Retrieve captured rationale independently of whether an old AST or complete file state can be reconstructed. Include prose associated with partial views and earlier edits. Prefer relevant symbol mentions, recorded fragment anchors, assumptions and corrections; retain the original event ID, exact excerpt/offset, source hash and action/path association. File association or an exact match in today's symbol does not prove historical symbol identity. The local extractor is `security_ground_truth.temporal_security.rationale`; it omits fenced code and uses bounded original excerpts without an extra summarizer call.

When an excerpt guides a hypothesis, record the quotation, testable assumption and planned current-code check. Record whether current evidence supports, contradicts, leaves unresolved, or makes irrelevant that assumption. An old claim of safety is not a dismissal. Generic or absent prose needs no invented rationale; the current-code investigation can proceed. Include these citations and assumption checks in the edit note.

Use a small harmless proof of concept only when the static/current/history evidence remains inconclusive. First establish that ordinary input reaches the real target, then observe the boundary or adversarial condition. Do not replace the implementation under test or treat setup failure, a rejected payload, or missing coverage as a false positive. Preserve source identity, target reachability, observations, and failure details.

Repair only a supported defect. Make the smallest production-code edit that preserves legitimate behavior. Reassess the edited source, repeat any check used to support the repair, and run the project's public functional tests. Keep unresolved warnings unresolved.

Store a machine-readable edit note beside the work product or in the project's chosen evidence directory. Include the source/cutoff identity, affected symbols, scanner IDs, temporal evidence hashes, captured-rationale provenance, hypotheses and assessments, checks and observations, patch hash, validation command/results, and remaining assumptions. Do not claim that the note prevents future regressions unless that effect has been separately evaluated.

The SusVibes research runner lives in `security_ground_truth.temporal_security`; its hidden security evaluator is post-repair measurement and must never supply repair feedback.

For subsequent feature changes protected by repair memory, read
[references/maintenance.md](references/maintenance.md). It defines check
qualification, immutable boundary checks, one feedback retry, and separate
reporting of accepted features and secure-code fallbacks.
