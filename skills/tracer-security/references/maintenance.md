# Persisting and enforcing a repair contract

After a supported repair passes ordinary functional checks, retain an external
`edit_note.json`. Include the current symbol/path, source hash, patch hash,
security invariant, diagnostic evidence, original rationale citations, exact
validation commands, result identities, and unresolved assumptions. Do not
manufacture missing development rationale or describe it as private reasoning.

For maintenance gating, qualify a separately owned assertion-bearing check.
It must fail on the original component, pass on the repaired component, and
preserve an ordinary-input control. Bind the check hash and repaired-symbol
hash to the note. A passing check covers its tested property, not the repository.

For a subsequent feature change, provide the new task, current source, and note.
Evaluate ordinary behavior, the requested feature, and the saved boundary
separately in the project's established isolated test environment. Keep the
saved boundary check immutable during repair. A changed contract requires an
explicitly recorded requalification rather than silently weakening its check.

If authorized for this workflow, return exact application or check failures for
one correction attempt. If that still fails, retain the qualified starting code
and report a fallback. Track the first proposal, retry, accepted implementation,
and fallback distinctly. Preserving old code does not deliver the new feature.

The five-case study evaluates this combined memory, gate, and retry workflow.
It does not demonstrate the isolated effect of natural-language memory.
