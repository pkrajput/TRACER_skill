"""Audit performed stages separately from security correctness or gold labels."""


def audit_method(seed_ids, hypotheses, transcript, *, history_required):
    checks = []
    for row in transcript:
        call = row.get("tool_call", {})
        if call.get("function", {}).get("name") == "run_python_check":
            checks.append(row.get("result", {}))
    groups = []
    covered_seeds = set()
    for hypothesis in hypotheses:
        covered_seeds.update(hypothesis["alert_ids"])
        attempts = [c for c in checks if c.get("hypothesis_id") == hypothesis["hypothesis_id"]]
        reached = [c for c in attempts if c.get("target_reached") is True
                   and (c.get("probe") or {}).get("source_identity") == "expected_files_match"]
        groups.append({"hypothesis_id": hypothesis["hypothesis_id"],
                       "alert_ids": hypothesis["alert_ids"],
                       "history_evidence_retrieved": bool(hypothesis.get("history_queries")),
                       "dynamic_attempts": len(attempts),
                       "matching_source_probe_executed": any(
                           (c.get('probe') or {}).get('source_identity') == 'expected_files_match'
                           and (c.get('probe') or {}).get('status') in {'completed', 'check_exception'}
                           for c in attempts),
                       "target_reached_on_matching_files": bool(reached),
                       "behavior_observed_at_reached_target": any(c["probe"].get("observations") for c in reached),
                       "independent_security_verification": False})
    complete = bool(groups) and not (set(seed_ids) - covered_seeds) and all(
        g["dynamic_attempts"] and (not history_required or g["history_evidence_retrieved"]) for g in groups)
    return {"contract": "flag-symbol-evolution-probe-v1", "groups": groups,
            "seeds_without_hypothesis": sorted(set(seed_ids) - covered_seeds),
            "required_stage_attempts_recorded": complete,
            "method_execution_complete": complete and all(g['matching_source_probe_executed'] for g in groups),
            "qualified_main_experiment": False,
            "qualification_note": "Stage execution does not certify semantic validity, oracle exclusion, or alert-level ground truth; these require separate qualification.",
            "independent_gold_labels": False}
