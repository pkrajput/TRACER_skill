"""Recording adapter around mini-SWE-agent (TRACER-compatible).

Wraps the pinned mini-swe-agent classes without changing model-visible
behavior: the official prompts, tool schema, and observation templates are
untouched. All recording happens controller-side:

  * every model request/response is stored verbatim (requests.jsonl; the
    Authorization header is never serialized - only the JSON body is);
  * every paid request passes through the SQLite budget gateway BEFORE
    dispatch (conservative byte-based prompt-token upper bound + max billable
    output bound at the pinned endpoint's frozen max rates);
  * before/after every tool action (including read-only and failed ones) a
    content-addressed repository snapshot is taken via out-of-band
    ``docker exec`` (events.jsonl -> snapshot ids -> blobs/);
  * an export helper maps events into TRACER's agent-agnostic ``Step`` shape.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
import uuid
from decimal import Decimal
from pathlib import Path

import requests as _requests

from minisweagent.agents.default import DefaultAgent
from minisweagent.exceptions import LimitsExceeded, Submitted
from minisweagent.models import GLOBAL_MODEL_STATS
from minisweagent.models.openrouter_model import (BASH_TOOL, OpenRouterModel,
                                                  OpenRouterAPIError)

from .budget_gateway import BudgetGateway, BudgetRejection
from .snapshots import BlobStore, ContainerSnapshotter
from .bounded_http import bounded_post

FRAMING_ALLOWANCE_TOKENS = 4096  # added on top of the byte-based prompt bound
OUTPUT_BOUND_FACTOR = 2  # reserve 2x max_tokens of output in case reasoning is billed on top


class RunRecorder:
    """Owns runs/<run_id>/{events,requests,snapshots}.jsonl and the blob store."""

    def __init__(self, run_dir: str | Path, blob_store: BlobStore, run_id: str):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.blobs = blob_store
        self.run_id = run_id
        self.seq = 0
        self._lock = threading.Lock()
        # restart support: continue sequence numbers
        ev = self.run_dir / "events.jsonl"
        if ev.exists():
            lines = ev.read_text().strip().splitlines()
            if lines:
                self.seq = json.loads(lines[-1])["sequence"] + 1
        self.last_action_event_ids: list[str] = []

    def _append(self, name: str, obj: dict) -> None:
        with self._lock:
            with open(self.run_dir / name, "a") as f:
                f.write(json.dumps(obj, sort_keys=True) + "\n")

    def blob_ref(self, text: str | bytes) -> str:
        data = text.encode("utf-8", "replace") if isinstance(text, str) else text
        return self.blobs.put(data)

    def record_snapshot(self, manifest) -> str:
        self._append("snapshots.jsonl", manifest.to_json())
        return manifest.snapshot_id

    def next_event_id(self) -> str:
        return f"{self.run_id}-e{self.seq:05d}"

    def record_event(self, *, type_: str, request_id: str | None = None,
                     before_snapshot: str | None = None,
                     after_snapshot: str | None = None, command: str | None = None,
                     exit_code: int | None = None,
                     model_visible_content_ref: str | None = None,
                     raw_content_ref: str | None = None,
                     duration_ms: int | None = None, extra: dict | None = None) -> str:
        with self._lock:
            event_id = f"{self.run_id}-e{self.seq:05d}"
            seq = self.seq
            self.seq += 1
        self._append("events.jsonl", {
            "event_id": event_id, "run_id": self.run_id, "sequence": seq,
            "type": type_, "request_id": request_id,
            "before_snapshot": before_snapshot, "after_snapshot": after_snapshot,
            "command": command, "exit_code": exit_code,
            "model_visible_content_ref": model_visible_content_ref,
            "raw_content_ref": raw_content_ref, "duration_ms": duration_ms,
            "extra": extra or {}, "ts": time.time()})
        return event_id

    def record_request(self, obj: dict) -> None:
        self._append("requests.jsonl", obj)

    def attach_model_visible(self, event_id: str, content_ref: str) -> None:
        self._append("events_model_visible.jsonl",
                     {"event_id": event_id, "model_visible_content_ref": content_ref})


class ContextLimitReached(LimitsExceeded):
    pass


class GatewayStop(LimitsExceeded):
    pass


class RecordingOpenRouterModel(OpenRouterModel):
    """OpenRouter model with pre-dispatch budget reservation + full recording.

    The dispatched JSON body is exactly what is hashed, audited and recorded.
    Provider pinning (order + allow_fallbacks=false + max_price) must already
    be inside ``model_kwargs``; this class verifies the response's provider.
    """

    def __init__(self, *, gateway: BudgetGateway, recorder: RunRecorder,
                 bucket: str, cell_key: str | None, run_id: str,
                 rate_prompt_micro_per_mtok: int, rate_completion_micro_per_mtok: int,
                 expected_provider: str, context_ceiling_tokens: int,
                 request_timeout_read: int = 600, billable_output_ceiling_tokens: int | None = None, **kwargs):
        super().__init__(**kwargs)
        self.gateway = gateway
        self.recorder = recorder
        self.bucket = bucket
        self.cell_key = cell_key
        self.run_id = run_id
        self.rate_in = int(rate_prompt_micro_per_mtok)
        self.rate_out = int(rate_completion_micro_per_mtok)
        self.expected_provider = expected_provider
        self.context_ceiling = int(context_ceiling_tokens)
        self.billable_output_ceiling = billable_output_ceiling_tokens
        self.request_timeout_read = request_timeout_read
        self.last_reported_prompt_tokens = 0
        self.last_reported_total_tokens = 0
        self.absolute_deadline = None

    # ------------------------------------------------------------------ bound
    def _bound_microusd(self, body_bytes: int, max_tokens: int) -> int:
        prompt_bound_tokens = body_bytes + FRAMING_ALLOWANCE_TOKENS
        # Some providers bill reasoning independently of max_tokens. Reserve
        # the endpoint full context as an output envelope for benchmark calls.
        out_bound_tokens = max(max_tokens * OUTPUT_BOUND_FACTOR, self.billable_output_ceiling or 0)
        cost = (math.ceil(prompt_bound_tokens * self.rate_in / 1_000_000)
                + math.ceil(out_bound_tokens * self.rate_out / 1_000_000))
        return int(cost)

    # ------------------------------------------------------------------ query
    def query(self, messages: list[dict], **kwargs) -> dict:
        if self.last_reported_total_tokens >= self.context_ceiling:
            raise ContextLimitReached({
                "role": "exit", "content": "context_limit",
                "extra": {"exit_status": "context_limit", "submission": ""}})
        prepared = self._prepare_messages_for_api(messages)
        payload = {
            "model": self.config.model_name,
            "messages": prepared,
            "tools": [BASH_TOOL],
            "usage": {"include": True},
            **(self.config.model_kwargs | kwargs),
        }
        body = json.dumps(payload)
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        max_tokens = int(payload.get("max_tokens") or 0)
        if max_tokens <= 0:
            raise RuntimeError("max_tokens must be set explicitly for budget bounding")
        bound = self._bound_microusd(len(body.encode()), max_tokens)

        first_request_id = None
        last_err: Exception | None = None
        for attempt in (1, 2, 3):
            remaining=self.absolute_deadline-time.time() if self.absolute_deadline else self.request_timeout_read
            if remaining<=0:
                raise GatewayStop({'role':'exit','content':'branch wall-time limit','extra':{'exit_status':'LimitsExceeded','submission':''}})
            try:
                res = self.gateway.reserve(
                    bucket=self.bucket, bound_microusd=bound, run_id=self.run_id,
                    cell_key=self.cell_key, provider=self.expected_provider,
                    model=self.config.model_name, body_hash=body_hash,
                    attempt_of=first_request_id, attempt_no=attempt,
                    meta={"body_bytes": len(body.encode()), "max_tokens": max_tokens})
            except BudgetRejection as e:
                raise GatewayStop({
                    "role": "exit", "content": f"budget gateway refusal: {e.reason}",
                    "extra": {"exit_status": "cost_limit_gateway", "submission": ""}})
            if first_request_id is None:
                first_request_id = res.request_id
            t0 = time.time()
            self.recorder._append('request_attempts.jsonl',{'request_id':res.request_id,'body_hash':body_hash,
                'request_body_ref':self.recorder.blob_ref(body),'started_at':t0,'attempt':attempt})
            try:
                response = bounded_post(
                    self._api_url,
                    headers={"Authorization": f"Bearer {self._api_key}",
                             "Content-Type": "application/json"},
                    data=body, timeout=min(self.request_timeout_read,remaining),
                    artifact_dir=self.recorder.run_dir,request_id=res.request_id)
            except _requests.exceptions.ConnectTimeout as e:
                self.gateway.release(res.request_id, "connect_timeout")
                last_err = e
                time.sleep(4 * attempt)
                continue
            except _requests.exceptions.ConnectionError as e:
                # connection may have been established; outcome uncertain
                self.gateway.mark_ambiguous(res.request_id, f"connection_error: {e}")
                self._record_transport_failure(res.request_id,e)
                raise GatewayStop({'role':'exit','content':'provider connection failure; full liability retained',
                    'extra':{'exit_status':'ProviderConnectionError','submission':''}}) from e
            except _requests.exceptions.ReadTimeout as e:
                self.gateway.mark_ambiguous(res.request_id, "read_timeout")
                self._record_transport_failure(res.request_id,e)
                raise GatewayStop({'role':'exit','content':'provider deadline exceeded; full liability retained',
                    'extra':{'exit_status':'ProviderTimeout','submission':''}}) from e
            duration_ms = int((time.time() - t0) * 1000)
            if response.status_code != 200:
                # HTTP error responses are not billed by OpenRouter
                self.gateway.release(res.request_id, f"http_{response.status_code}")
                if response.status_code in (429, 500, 502, 503, 504, 408, 524):
                    last_err = OpenRouterAPIError(
                        f"HTTP {response.status_code}: {response.text[:500]}")
                    time.sleep(8 * attempt)
                    continue
                raise OpenRouterAPIError(
                    f"HTTP {response.status_code}: {response.text[:2000]}")
            try:
                data = response.json()
            except Exception as e:
                self.gateway.mark_ambiguous(res.request_id, 'invalid_success_response')
                self.gateway._write_stop('Malformed success response; reservation retained')
                raise RuntimeError('Malformed success response') from e
            if "error" in data and "choices" not in data:
                self.gateway.mark_ambiguous(res.request_id, 'error_in_success_body')
                self.recorder._append('provider_errors.jsonl',{'request_id':res.request_id,
                    'request_body_ref':self.recorder.blob_ref(body),'response_body_ref':self.recorder.blob_ref(response.text),
                    'generation_id':data.get('id'),'error':data['error']})
                generation_id=data.get('id')
                if generation_id:self.gateway._conn.execute('UPDATE requests SET provider_request_id=? WHERE request_id=?',(generation_id,res.request_id))
                code=data['error'].get('code') if isinstance(data['error'],dict) else None
                if code in (429,500,502,503,529) and attempt<3:
                    delay=20*attempt
                    remaining=self.absolute_deadline-time.time() if self.absolute_deadline else self.request_timeout_read
                    if remaining>delay:
                        self.recorder._append('provider_retries.jsonl',{'request_id':res.request_id,
                            'attempt':attempt,'next_attempt':attempt+1,'delay_seconds':delay,
                            'error_code':code,'body_hash':body_hash,'liability_policy':'full ambiguous bound retained'})
                        time.sleep(delay)
                        continue
                if code in (408,429,500,502,503,504,524,529):
                    raise GatewayStop({'role':'exit','content':'provider error; full liability retained',
                        'extra':{'exit_status':'ProviderTimeout' if code in (408,504,524) else 'ProviderUnavailable','submission':''}})
                self.gateway._write_stop('Error in successful HTTP response; reconcile before further calls')
                raise OpenRouterAPIError(json.dumps(data)[:2000])
            usage = data.get("usage", {}) or {}
            if usage.get("cost") is None:
                self.gateway.mark_ambiguous(res.request_id, "missing_provider_cost")
                self.gateway._write_stop("Successful response omitted provider cost; reconcile before further calls")
                self.recorder.record_request({"request_id": res.request_id,
                    "request_body_ref": self.recorder.blob_ref(body),
                    "response_body_ref": self.recorder.blob_ref(response.text),
                    "openrouter_id": data.get("id"), "usage": usage})
                raise RuntimeError("Provider response missing cost; budget reservation retained")
            cost_usd = usage["cost"]
            actual_micro = int((Decimal(str(cost_usd)) * 1_000_000)
                               .to_integral_value(rounding="ROUND_CEILING"))
            ctd = usage.get("completion_tokens_details") or {}
            ptd = usage.get("prompt_tokens_details") or {}
            self.gateway.settle(
                res.request_id, actual_cost_microusd=actual_micro,
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                reasoning_tokens=ctd.get("reasoning_tokens"),
                cache_tokens=ptd.get("cached_tokens"),
                provider_request_id=data.get("id"),
                accounting_status="settled_from_response_usage")
            self.recorder.record_request({
                "request_id": res.request_id, "attempt": attempt,
                "openrouter_id": data.get("id"), "body_hash": body_hash,
                "request_body_ref": self.recorder.blob_ref(body),
                "response_body_ref": self.recorder.blob_ref(response.text),
                "provider": data.get("provider"), "model": data.get("model"),
                "usage": usage, "reserved_microusd": res.reserved_microusd,
                "actual_cost_microusd": actual_micro, "duration_ms": duration_ms,
                "ts": time.time()})
            served_by = data.get("provider")
            if self.expected_provider and (not served_by or \
                    served_by.lower() != self.expected_provider.lower()):
                self.gateway._write_stop('Provider pin not verified in response')
                raise RuntimeError(
                    f"provider pin violated: served by {served_by!r}, "
                    f"pinned {self.expected_provider!r}")
            self.last_reported_prompt_tokens = int(usage.get("prompt_tokens") or 0)
            self.last_reported_total_tokens = int(usage.get("total_tokens") or 0)
            return self._finish(data, actual_micro, res.request_id)
        raise OpenRouterAPIError(f"transport retries exhausted: {last_err}")

    def _record_transport_failure(self,request_id,error):
        generation_id=getattr(error,'generation_id',None)
        if generation_id:
            self.gateway._conn.execute('UPDATE requests SET provider_request_id=? WHERE request_id=?',(generation_id,request_id))
        self.recorder._append('transport_failures.jsonl',{'request_id':request_id,'generation_id':generation_id,
            'exception_type':type(error).__name__,'metadata_path':getattr(error,'transport_metadata_path',None),
            'policy':'end this branch as infrastructure-invalid; retain full reservation in every budget check'})

    def _try_reconcile_ambiguous(self, request_id: str, body_hash: str) -> None:
        """Best effort: without a generation id we cannot verify non-billing,
        so the reservation stays held (fail closed)."""
        return

    def _finish(self, response: dict, actual_micro: int, request_id: str) -> dict:
        cost_output = {"cost": actual_micro / 1_000_000}
        GLOBAL_MODEL_STATS.add(cost_output["cost"])
        snapshot_id = None
        try:
            actions = self._parse_actions(response)
        except Exception as e:
            self.recorder.record_event(
                type_="model_request", request_id=request_id,
                raw_content_ref=self.recorder.blob_ref(json.dumps(response)),
                extra={"format_error": str(e)[:500]})
            if hasattr(e, "messages"):
                e.messages[0].setdefault("extra", {}).update(cost_output)
                e.messages[0]["extra"]["response"] = dict(response)
            raise
        message = dict(response["choices"][0]["message"])
        message["extra"] = {"actions": actions, "response": response,
                            **cost_output, "timestamp": time.time()}
        self.recorder.record_event(
            type_="model_request", request_id=request_id,
            raw_content_ref=self.recorder.blob_ref(json.dumps(response)),
            extra={"n_actions": len(actions)})
        return message


class RecordingDockerEnvironment:
    """Composition wrapper: delegate to DockerEnvironment, snapshot around actions."""

    def __init__(self, inner, recorder: RunRecorder,
                 snapshotter: ContainerSnapshotter):
        self._inner = inner
        self.recorder = recorder
        self.snapshotter = snapshotter
        man = snapshotter.snapshot(label="initial")
        recorder.record_snapshot(man)
        self._last_snapshot_id = man.snapshot_id
        self.initial_snapshot_id = man.snapshot_id

    def __getattr__(self, name):
        return getattr(self._inner, name)

    @property
    def last_snapshot_id(self):
        return self._last_snapshot_id

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None):
        before = self._last_snapshot_id
        t0 = time.time()
        # suppress Submitted so we can snapshot first
        orig_check = self._inner._check_finished
        self._inner._check_finished = lambda output: None
        try:
            output = self._inner.execute(action, cwd, timeout=timeout)
        finally:
            self._inner._check_finished = orig_check
        duration_ms = int((time.time() - t0) * 1000)
        man = self.snapshotter.snapshot(label="post_action")
        after = self.recorder.record_snapshot(man)
        self._last_snapshot_id = after
        event_id = self.recorder.record_event(
            type_="action", before_snapshot=before, after_snapshot=after,
            command=action.get("command", ""), exit_code=output.get("returncode"),
            raw_content_ref=self.recorder.blob_ref(output.get("output", "")),
            duration_ms=duration_ms,
            extra={"exception_info": output.get("exception_info", ""),
                   "tool_call_id": action.get("tool_call_id")})
        self.recorder.last_action_event_ids.append(event_id)
        orig_check(output)  # may raise Submitted
        return output


class RecordingAgent(DefaultAgent):
    """DefaultAgent + exact model-visible observation capture per action event."""

    def execute_actions(self, message: dict) -> list[dict]:
        self.env.recorder.last_action_event_ids = []
        try:
            added = super().execute_actions(message)
        except Submitted as e:
            # record the model-visible exit content for the final action
            ids = self.env.recorder.last_action_event_ids
            if ids:
                ref = self.env.recorder.blob_ref(e.messages[0].get("content", ""))
                self.env.recorder.attach_model_visible(ids[-1], ref)
            raise
        ids = self.env.recorder.last_action_event_ids
        for event_id, msg in zip(ids, added):
            content = msg.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content)
            self.env.recorder.attach_model_visible(
                event_id, self.env.recorder.blob_ref(content))
        return added


# --------------------------------------------------------------- TRACER export
def export_tracer_steps(run_dir: str | Path) -> list[dict]:
    """Map recorded events into TRACER's agent-agnostic Step shape
    (codegraph_trace.models.Step fields), using snapshot ids in place of git
    SHAs (the shadow store is content-addressed, not a git history)."""
    run_dir = Path(run_dir)
    events = [json.loads(l) for l in
              (run_dir / "events.jsonl").read_text().splitlines()]
    steps = []
    for ev in events:
        if ev["type"] != "action":
            continue
        steps.append({
            "step_id": ev["event_id"],
            "prompt": ev.get("command") or "",
            "reasoning_text": "",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(ev.get("ts", 0))),
            "before_sha": ev.get("before_snapshot"),
            "after_sha": ev.get("after_snapshot"),
            "raw_event": ev,
            "author": "agent",
            "lineage_id": "main",
        })
    return steps
