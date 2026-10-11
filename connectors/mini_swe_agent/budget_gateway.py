"""Central SQLite budget gateway with pre-dispatch reservations.

Every OpenRouter request dispatched by this study MUST:
  1. call ``reserve()`` with a conservative upper bound on its charge BEFORE dispatch;
  2. dispatch only if a reservation was granted;
  3. call ``settle()`` (charged), ``release()`` (verified-uncharged failure), or
     ``mark_ambiguous()`` afterwards.

Money is stored as integer microdollars (1 USD = 1_000_000). No binary floats
are stored. Admission is atomic (BEGIN IMMEDIATE) and enforces:
  - global cap ($150),
  - per-bucket caps,
  - optional per-cell caps (e.g. $10 per baseline cell, $5 per branch arm),
  - at most nine in-flight reservations, at most three per model.

Ambiguous outcomes (e.g. timeouts after dispatch) keep their full reservation
until reconciled. A cap/accounting violation writes ``STOP_PAID_CALLS`` next to
the database and all further reservations are refused (fail closed).

Prompt-token upper bound used by callers: for BPE tokenizers every token encodes
at least one byte, so ``len(utf8(serialized_request_body))`` is a strict upper
bound on prompt tokens; a framing allowance is added on top by the caller.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

MICRO = 1_000_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS buckets (
  name TEXT PRIMARY KEY,
  cap_microusd INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cells (
  cell_key TEXT PRIMARY KEY,
  bucket TEXT NOT NULL REFERENCES buckets(name),
  cap_microusd INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
  request_id TEXT PRIMARY KEY,
  run_id TEXT,
  bucket TEXT NOT NULL REFERENCES buckets(name),
  cell_key TEXT,
  provider TEXT,
  model TEXT,
  body_hash TEXT,
  reserved_microusd INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN
    ('reserved','charged','failed_uncharged','ambiguous')),
  actual_cost_microusd INTEGER,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  reasoning_tokens INTEGER,
  cache_tokens INTEGER,
  provider_request_id TEXT,
  accounting_status TEXT NOT NULL DEFAULT 'pending',
  attempt_of TEXT,
  attempt_no INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  reconciled_at TEXT,
  meta TEXT
);
"""

# Phase 2 authorization (2026-09-12): fresh $200 cap, new buckets.
DEFAULT_BUCKETS = {
    "smoke": 5 * MICRO,
    "baselines": 140 * MICRO,
    "probes": 40 * MICRO,
    "reserve": 15 * MICRO,
}
GLOBAL_CAP = 200 * MICRO
MAX_PAID_CONCURRENCY = 9  # three task blocks, three requests per model
MAX_PER_MODEL_CONCURRENCY = 3


class BudgetRejection(Exception):
    """Reservation refused. ``hard`` means STOP_PAID_CALLS is in force."""

    def __init__(self, reason: str, hard: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.hard = hard


class AccountingViolation(Exception):
    pass


@dataclass
class Reservation:
    request_id: str
    bucket: str
    cell_key: str | None
    reserved_microusd: int


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class BudgetGateway:
    def __init__(self, db_path: str | Path, buckets: dict[str, int] | None = None,
                 global_cap: int = GLOBAL_CAP):
        self.db_path = Path(db_path)
        self.stop_file = self.db_path.parent / "STOP_PAID_CALLS"
        self.global_cap = int(global_cap)
        self._conn = sqlite3.connect(str(self.db_path), timeout=30,
                                     isolation_level=None, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        for name, cap in (buckets or DEFAULT_BUCKETS).items():
            self._conn.execute(
                "INSERT OR IGNORE INTO buckets(name, cap_microusd) VALUES (?,?)",
                (name, int(cap)))

    # ---------------------------------------------------------------- setup
    def ensure_cell(self, cell_key: str, bucket: str, cap_microusd: int) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO cells(cell_key, bucket, cap_microusd) VALUES (?,?,?)",
            (cell_key, bucket, int(cap_microusd)))

    # ------------------------------------------------------------- queries
    def _usage(self, where: str, args: tuple) -> tuple[int, int, int]:
        """(charged, outstanding, n_outstanding) for a scope.

        charged counts settled actual costs; outstanding counts the FULL
        reservation of every 'reserved' or 'ambiguous' request (an ambiguous
        timeout is never treated as free until reconciled).
        """
        row = self._conn.execute(
            f"""SELECT
                COALESCE(SUM(CASE WHEN status='charged' THEN actual_cost_microusd ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN status IN ('reserved','ambiguous') THEN reserved_microusd ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN status='reserved' THEN 1 ELSE 0 END),0)
                FROM requests WHERE {where}""", args).fetchone()
        return int(row[0]), int(row[1]), int(row[2])

    def totals(self) -> dict:
        g_charged, g_out, g_inflight = self._usage("1=1", ())
        per_bucket = {}
        for (name, cap) in self._conn.execute("SELECT name, cap_microusd FROM buckets"):
            c, o, _ = self._usage("bucket=?", (name,))
            per_bucket[name] = {"cap": cap, "charged": c, "outstanding": o}
        return {"global_cap": self.global_cap, "charged": g_charged,
                "outstanding": g_out, "in_flight": g_inflight,
                "buckets": per_bucket}

    def stopped(self) -> bool:
        return self.stop_file.exists()

    def _write_stop(self, reason: str) -> None:
        with open(self.stop_file, "a") as f:
            f.write(json.dumps({"time": _now(), "reason": reason}) + "\n")

    def sweep_stale_reserved(self, max_age_seconds: int = 900) -> int:
        """Controller-restart hygiene: mark orphaned 'reserved' rows (from a
        crashed process) as 'ambiguous'. They remain fully counted as
        outstanding until reconciled against the provider; this only frees
        the per-model in-flight slot, never budget."""
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                               time.gmtime(time.time() - max_age_seconds))
        cur = self._conn.execute(
            "UPDATE requests SET status='ambiguous', "
            "accounting_status='stale_reserved' "
            "WHERE status='reserved' AND created_at < ?", (cutoff,))
        return cur.rowcount

    # ------------------------------------------------------------- reserve
    def reserve(self, *, bucket: str, bound_microusd: int, run_id: str | None = None,
                cell_key: str | None = None, provider: str | None = None,
                model: str | None = None, body_hash: str | None = None,
                attempt_of: str | None = None, attempt_no: int = 1,
                meta: dict | None = None) -> Reservation:
        """Atomically admit a request. Raises BudgetRejection on refusal.

        A refusal makes zero provider calls by construction (the caller must
        not dispatch without a Reservation).
        """
        bound = int(bound_microusd)
        if bound <= 0:
            raise BudgetRejection("non-positive bound", hard=False)
        if self.stopped():
            raise BudgetRejection("STOP_PAID_CALLS in force", hard=True)
        if attempt_no > 3:  # first try + at most two transport retries
            raise BudgetRejection("retry limit exceeded (max 2 transport retries)")
        request_id = uuid.uuid4().hex
        con = self._conn
        con.execute("BEGIN IMMEDIATE")
        try:
            g_charged, g_out, g_inflight = self._usage("1=1", ())
            # Phase 2 protocol change (preregistered): paid concurrency <= 9,
            # with at most THREE in-flight requests per model family. Admission
            # stays atomic under BEGIN IMMEDIATE.
            if g_inflight >= MAX_PAID_CONCURRENCY:
                raise BudgetRejection(
                    f"max paid concurrency ({MAX_PAID_CONCURRENCY}) reached")
            if model is not None:
                m_inflight = con.execute(
                    "SELECT COUNT(*) FROM requests WHERE status='reserved' "
                    "AND model=?", (model,)).fetchone()[0]
                if m_inflight >= MAX_PER_MODEL_CONCURRENCY:
                    raise BudgetRejection(
                        f"in-flight request exists for model {model}")
            if g_charged + g_out + bound > self.global_cap:
                raise BudgetRejection(
                    f"global cap: charged={g_charged} outstanding={g_out} "
                    f"bound={bound} cap={self.global_cap}")
            row = con.execute("SELECT cap_microusd FROM buckets WHERE name=?",
                              (bucket,)).fetchone()
            if row is None:
                raise BudgetRejection(f"unknown bucket {bucket!r}")
            b_cap = int(row[0])
            b_charged, b_out, _ = self._usage("bucket=?", (bucket,))
            if b_charged + b_out + bound > b_cap:
                raise BudgetRejection(
                    f"bucket {bucket} cap: charged={b_charged} outstanding={b_out} "
                    f"bound={bound} cap={b_cap}")
            if cell_key is not None:
                crow = con.execute("SELECT cap_microusd FROM cells WHERE cell_key=?",
                                   (cell_key,)).fetchone()
                if crow is None:
                    raise BudgetRejection(f"unknown cell {cell_key!r}")
                c_cap = int(crow[0])
                c_charged, c_out, _ = self._usage("cell_key=?", (cell_key,))
                if c_charged + c_out + bound > c_cap:
                    raise BudgetRejection(
                        f"cell {cell_key} cap: charged={c_charged} "
                        f"outstanding={c_out} bound={bound} cap={c_cap}")
            con.execute(
                """INSERT INTO requests(request_id, run_id, bucket, cell_key, provider,
                   model, body_hash, reserved_microusd, status, attempt_of, attempt_no,
                   created_at, meta)
                   VALUES (?,?,?,?,?,?,?,?, 'reserved', ?,?,?,?)""",
                (request_id, run_id, bucket, cell_key, provider, model, body_hash,
                 bound, attempt_of, attempt_no, _now(),
                 json.dumps(meta or {}, sort_keys=True)))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        return Reservation(request_id, bucket, cell_key, bound)

    # -------------------------------------------------------------- settle
    def settle(self, request_id: str, *, actual_cost_microusd: int,
               prompt_tokens: int | None = None, completion_tokens: int | None = None,
               reasoning_tokens: int | None = None, cache_tokens: int | None = None,
               provider_request_id: str | None = None,
               accounting_status: str = "reconciled") -> None:
        actual = int(actual_cost_microusd)
        con = self._conn
        con.execute("BEGIN IMMEDIATE")
        try:
            row = con.execute(
                "SELECT status, reserved_microusd, bucket, cell_key FROM requests "
                "WHERE request_id=?", (request_id,)).fetchone()
            if row is None:
                raise AccountingViolation(f"unknown request {request_id}")
            status, reserved, bucket, cell_key = row
            if status == "charged":
                # duplicate settle: idempotent only if identical cost
                prev = con.execute(
                    "SELECT actual_cost_microusd FROM requests WHERE request_id=?",
                    (request_id,)).fetchone()[0]
                con.execute("COMMIT")
                if int(prev) != actual:
                    self._write_stop(
                        f"duplicate settle with different cost for {request_id}")
                    raise AccountingViolation("conflicting duplicate settlement")
                return
            con.execute(
                """UPDATE requests SET status='charged', actual_cost_microusd=?,
                   prompt_tokens=?, completion_tokens=?, reasoning_tokens=?,
                   cache_tokens=?, provider_request_id=?, accounting_status=?,
                   reconciled_at=? WHERE request_id=?""",
                (actual, prompt_tokens, completion_tokens, reasoning_tokens,
                 cache_tokens, provider_request_id, accounting_status, _now(),
                 request_id))
            con.execute("COMMIT")
        except BaseException:
            try:
                con.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        # post-settle audit (outside txn: stop file is advisory + enforced at reserve)
        if actual > int(reserved):
            self._write_stop(
                f"actual cost {actual} exceeded reservation {reserved} for {request_id}")
        self._audit_caps()

    def release(self, request_id: str, reason: str = "verified_uncharged") -> None:
        """Mark a dispatch failure verified to be free (e.g. connect error before send,
        or provider-confirmed zero-cost error)."""
        self._conn.execute(
            "UPDATE requests SET status='failed_uncharged', actual_cost_microusd=0, "
            "accounting_status=?, reconciled_at=? WHERE request_id=? AND status IN "
            "('reserved','ambiguous')", (reason, _now(), request_id))

    def mark_ambiguous(self, request_id: str, reason: str = "timeout") -> None:
        """Outcome unknown; the reservation stays counted until reconciled."""
        self._conn.execute(
            "UPDATE requests SET status='ambiguous', accounting_status=? "
            "WHERE request_id=? AND status='reserved'", (reason, request_id))

    def _audit_caps(self) -> None:
        g_charged, g_out, _ = self._usage("1=1", ())
        if g_charged + g_out > self.global_cap:
            self._write_stop(f"global cap violated: {g_charged}+{g_out}")
        for (name, cap) in self._conn.execute(
                "SELECT name, cap_microusd FROM buckets").fetchall():
            c, o, _ = self._usage("bucket=?", (name,))
            if c + o > int(cap):
                self._write_stop(f"bucket {name} cap violated: {c}+{o}>{cap}")

    def outstanding_requests(self) -> list[tuple[str, str, int]]:
        return list(self._conn.execute(
            "SELECT request_id, status, reserved_microusd FROM requests "
            "WHERE status IN ('reserved','ambiguous')"))

    def close(self) -> None:
        self._conn.close()
