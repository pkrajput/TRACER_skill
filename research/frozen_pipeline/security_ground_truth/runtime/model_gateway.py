"""One fixed OpenRouter investigator, recorded requests and fail-closed budget.

Explicit HTTP 429 rejections get two bounded delayed retries; transient
transport/server failures get one. Every attempt retains its reservation until independently
reconciled, so even unknown billing cannot bypass the gross cap. No key is logged.
"""
from __future__ import annotations

import argparse
import http.client
import json
import math
from pathlib import Path
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
import fcntl
from contextlib import contextmanager

from .common import utcnow, write_json
from .context_budget import fit_messages
from .http_deadline import RequestDeadlineExceeded, request_json


class BudgetExceeded(RuntimeError):
    pass


class BudgetLedger:
    def __init__(self, path: Path, cap_usd: float = 699, *, scope=None):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.cap = math.floor(cap_usd * 1_000_000)
        self.scope = scope
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, micro_usd INTEGER NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('cap_micro_usd', self.cap))
            if db.execute('SELECT value FROM settings WHERE key=?', ('cap_micro_usd',)).fetchone()[0] != self.cap:
                raise ValueError('Existing ledger cap differs; refusing an implicit budget change')
            if scope:
                db.execute('CREATE TABLE IF NOT EXISTS budget_scopes (id TEXT PRIMARY KEY, cap_micro_usd INTEGER NOT NULL, initial_total_micro_usd INTEGER NOT NULL)')
                values=(scope['id'],scope['cap_micro_usd'],scope['initial_total_micro_usd'])
                if any(type(x) is not int or x<0 for x in values[1:]):raise ValueError('Invalid integer scope cap')
                db.execute('INSERT OR IGNORE INTO budget_scopes VALUES (?,?,?)',values)
                if db.execute('SELECT cap_micro_usd,initial_total_micro_usd FROM budget_scopes WHERE id=?',(scope['id'],)).fetchone()!=values[1:]:
                    raise ValueError('Existing pilot budget differs; refusing an implicit budget change')
        path.chmod(0o600)

    @contextmanager
    def connection(self):
        # Serialize short ledger transactions across both threads and processes.
        # sqlite's connection context commits but does NOT close the connection;
        # explicit closure prevents leaked handles in long parallel campaigns.
        with self.path.with_suffix(self.path.suffix + '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            db = sqlite3.connect(self.path, timeout=120)
            try:
                with db:
                    yield db
            finally:
                db.close()
                fcntl.flock(lock, fcntl.LOCK_UN)

    def reserve(self, request_id: str, usd: float, details: dict) -> None:
        amount = math.ceil(usd * 1_000_000)
        details = dict(details)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            total = db.execute('SELECT COALESCE(SUM(micro_usd),0) FROM requests').fetchone()[0]
            if total + amount > self.cap:
                raise BudgetExceeded('Gross study budget reservation would exceed cap')
            if self.scope:
                scoped=db.execute("SELECT COALESCE(SUM(micro_usd),0) FROM requests WHERE json_extract(details,'$.budget_scope')=?",(self.scope['id'],)).fetchone()[0]
                if (scoped+amount>self.scope['cap_micro_usd'] or
                    total+amount>self.scope['initial_total_micro_usd']+self.scope['cap_micro_usd']):
                    raise BudgetExceeded('Pilot incremental reservation would exceed its hard cap')
                details['budget_scope']=self.scope['id']
            # The lab Gemini amendment increases the combined ceiling only.
            # Legacy rows without an explicit Gemini provider are charged to
            # OpenRouter conservatively; no earlier reservations are erased.
            if details.get('provider') != 'gemini-direct':
                openrouter = db.execute("SELECT COALESCE(SUM(micro_usd),0) FROM requests "
                    "WHERE COALESCE(json_extract(details,'$.provider'),'') != 'gemini-direct'").fetchone()[0]
                if openrouter + amount > min(self.cap, 699_000_000):
                    raise BudgetExceeded('OpenRouter service budget reservation would exceed $699 cap')
            db.execute('INSERT INTO requests VALUES (?,?,?,?)', (request_id, amount, 'reserved', json.dumps(details)))

    def settle(self, request_id: str, reported_cost: float | None, details: dict, *, cost_basis='provider_reported') -> None:
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT micro_usd,details FROM requests WHERE id=?', (request_id,)).fetchone()
            if old is None:
                raise ValueError('Missing reservation')
            prior_details=json.loads(old[1]);details=dict(details)
            if prior_details.get('budget_scope'):details['budget_scope']=prior_details['budget_scope']
            amount = old[0] if reported_cost is None else math.ceil(reported_cost * 1.10 * 1_000_000)
            if cost_basis not in {'provider_reported', 'usage_priced'}:
                raise ValueError('Unknown cost basis')
            status = 'unreconciled_reserved' if reported_cost is None else ('reported_cost_plus_10pct' if cost_basis == 'provider_reported' else 'usage_priced_plus_10pct')
            db.execute('UPDATE requests SET micro_usd=?,status=?,details=? WHERE id=?',
                       (amount, status, json.dumps(details), request_id))
            if amount > old[0]:
                raise RuntimeError('Reported cost exceeded conservative reservation; halt dispatch and review pricing')

    def summary(self) -> dict:
        with self.connection() as db:
            rows = db.execute('SELECT status,COUNT(*),SUM(micro_usd) FROM requests GROUP BY status').fetchall()
        return {'gross_cap_usd': self.cap / 1_000_000,
                'accounted_usd_including_unreconciled_reservations': sum(r[2] for r in rows) / 1_000_000,
                'requests': sum(r[1] for r in rows),
                'by_status': {r[0]: {'requests': r[1], 'usd': r[2] / 1_000_000} for r in rows}}

    def scope_summary(self):
        if not self.scope:return None
        with self.connection() as db:
            rows=db.execute("SELECT micro_usd,status,details FROM requests WHERE json_extract(details,'$.budget_scope')=?",(self.scope['id'],)).fetchall()
        reported=[];unknown=0
        for _,status,raw in rows:
            cost=(json.loads(raw).get('usage') or {}).get('cost')
            if isinstance(cost,(int,float)) and math.isfinite(cost) and cost>=0:reported.append(cost)
            else:unknown+=1
        return {**self.scope,'requests':len(rows),'accounted_usd':sum(r[0] for r in rows)/1e6,
                'provider_reported_usd':sum(reported),'requests_without_reported_cost':unknown}


def load_key(path: Path) -> str:
    for line in path.read_text().splitlines():
        line = line.strip().removeprefix('export ')
        if line.startswith('OPENROUTER_API_KEY='):
            value = line.split('=', 1)[1].strip().strip('\"\'')
            if value:
                return value
    raise RuntimeError('OpenRouter key unavailable in configured credential file')


class Investigator:
    def __init__(self, run_root: Path, config: dict):
        self.root, self.config = run_root, config
        self.ledger = BudgetLedger(run_root / 'budget.sqlite', config.get('gross_cap_usd', 699), scope=config.get('budget_scope'))
        self._pace_lock = threading.Lock()
        self._next_request_at = 0.0

    def _pace(self):
        interval = self.config.get('minimum_request_interval_seconds', 0)
        if interval <= 0:
            return
        while True:
            with self._pace_lock:
                delay = self._next_request_at - time.monotonic()
                if delay <= 0:
                    self._next_request_at = time.monotonic() + interval
                    return
            time.sleep(min(delay, 30))

    def complete(self, messages: list[dict], *, tools: list[dict] | None = None,
                 cell_id: str, max_tokens: int = 4096, final_json: bool = False,
                 required_tool: str | None = None) -> dict:
        for attempt in range(3):
            try:
                self._pace()
                return self._complete_once(messages, tools=tools, cell_id=cell_id,
                                           max_tokens=max_tokens, final_json=final_json, required_tool=required_tool)
            except RequestDeadlineExceeded as error:
                # The timed-out attempt keeps its full budget reservation.  v11
                # permits one fresh request only when no response tokens reached
                # the caller; the gross/incremental ledgers still cap both.
                if (not self.config.get('retry_zero_token_timeout',False)
                        or getattr(error,'tokens_returned',None)!=0 or attempt>=1):
                    raise
                time.sleep(15)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                    ConnectionError, http.client.IncompleteRead) as error:
                if (self.config.get('retry_zero_token_timeout', False)
                        and self.config.get('retry_policy') == 'zero_token_deadline_once_only'
                        and isinstance(error, TimeoutError)):
                    if attempt >= 1:
                        raise
                    # A transport inactivity timeout returns no completion body
                    # and therefore no response tokens.  Keep its reservation
                    # and permit the same single retry as a wall-clock deadline.
                    time.sleep(15)
                    continue
                if self.config.get('retry_policy') == 'zero_token_deadline_once_only':
                    raise
                limited = isinstance(error, urllib.error.HTTPError) and error.code == 429
                transient = not isinstance(error, urllib.error.HTTPError) or error.code in {502, 503, 504}
                if not (limited or transient) or attempt >= (2 if limited else 1):
                    raise
                if limited and self.config.get('minimum_request_interval_seconds', 0) > 0:
                    with self._pace_lock:
                        self._next_request_at = max(self._next_request_at, time.monotonic() + 15 * (attempt + 1))
                time.sleep(15 * (attempt + 1))

    def _complete_once(self, messages: list[dict], *, tools: list[dict] | None = None,
                       cell_id: str, max_tokens: int = 4096, final_json: bool = False,
                       required_tool: str | None = None) -> dict:
        request_id = uuid.uuid4().hex
        directory = self.root / 'requests' / request_id
        messages, context_changes = fit_messages(messages, max_bytes=self.config.get('max_context_message_bytes', 90000))
        payload = {'model': self.config['model'], 'messages': messages, 'temperature': 0,
                   'max_tokens': max_tokens, 'stream': False,
                   'provider': {'only': [self.config['provider']], 'allow_fallbacks': False,
                                'require_parameters': True,
                                'max_price': {'prompt': 1, 'completion': 4}},
                   'reasoning': {'enabled': True}}
        if tools:
            payload['tools'] = tools
        if required_tool:
            if final_json or required_tool not in {t['function']['name'] for t in (tools or [])}:
                raise ValueError('Required tool must be available in a non-final request')
            # The endpoint returns {} in forced-function mode and may name
            # unavailable tools in auto mode. Ask for the arguments as JSON,
            # then losslessly adapt that model-written object to a tool call.
            # Raw provider output and the adaptation are both archived.
            payload['tools'] = [t for t in tools if t['function']['name'] == required_tool]
            function = payload['tools'][0]['function']
            payload['tool_choice'] = 'none'
            payload['response_format'] = {'type': 'json_object'}
            payload['reasoning'] = {'enabled': False}
            payload['messages'] = messages + [{'role': 'user', 'content':
                'For this required protocol stage, return ONLY the JSON arguments object for '
                + required_tool + '. Do not return a final alert decision or a function-call wrapper. '
                + 'Fill every required field from the evidence above; do not invent observations. '
                + 'Function description and argument schema: ' + json.dumps(function)}]
        if final_json:
            payload['tool_choice'] = 'none'
            payload['response_format'] = {'type': 'json_object'}
            payload['reasoning'] = {'enabled': False}
        if required_tool or final_json:
            # JSON-only turns must not also declare tools on providers which
            # reject that combination. The required schema is in the message.
            payload.pop('tools', None)
            payload.pop('tool_choice', None)
        encoded = json.dumps(payload).encode()
        if len(encoded) > 120_000:
            raise ValueError('Per-request evidence budget exceeded; summarize tool outputs before dispatch')
        # UTF-8 byte count + protocol allowance bounds input tokens conservatively.
        reservation = ((len(encoded) + 4096) / 1_000_000 + max_tokens * 4 / 1_000_000 + 0.01) * 1.10
        self.ledger.reserve(request_id, reservation, {'cell_id': cell_id, 'created_utc': utcnow()})
        write_json(directory / 'request.json', payload)
        write_json(directory / 'context_budget.json', {'policy': 'preserve-seeds-and-recent-feedback-v1', 'changes': context_changes})
        started = time.monotonic()
        status = {'request_id': request_id, 'cell_id': cell_id, 'started_utc': utcnow(),
                  'model': self.config['model'], 'provider_requested': self.config['provider'],
                  'reservation_usd': reservation}
        write_json(directory / 'status.json', status)
        key = load_key(Path(self.config['credential_file']))
        request = urllib.request.Request('https://openrouter.ai/api/v1/chat/completions', data=encoded,
                                         headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json',
                                                  'X-Title': 'TRACER history-aware SAST study'})
        try:
            result = request_json(request, timeout=self.config.get('request_timeout_seconds',180))
            write_json(directory / 'response.json', result)
            if result.get('error') or not result.get('choices'):
                raise RuntimeError('Provider returned no completion; see recorded response')
            cost = result.get('usage', {}).get('cost')
            if not isinstance(cost, (int, float)) or not math.isfinite(cost) or cost < 0:
                cost = None
            self.ledger.settle(request_id, cost, {'cell_id': cell_id, 'generation_id': result.get('id'),
                                                'provider': result.get('provider'), 'usage': result.get('usage')})
            status.update({'status': 'completed', 'generation_id': result.get('id'),
                           'provider_actual': result.get('provider'), 'usage': result.get('usage')})
            if not isinstance(result['choices'][0].get('message'), dict):
                raise ValueError('Provider returned no message: ' + str(result['choices'][0].get('finish_reason')))
            if required_tool:
                raw_message = result['choices'][0]['message']
                arguments = json.loads(raw_message.get('content') or '')
                if not isinstance(arguments, dict):
                    raise ValueError('Required-stage response must be a JSON arguments object')
                missing = set(function['parameters'].get('required', [])) - arguments.keys()
                if missing:
                    raise ValueError('Required-stage response omitted required arguments: ' + ', '.join(sorted(missing)))
                adapted = {'role': 'assistant', 'content': None, 'tool_calls': [{
                    'id': 'tracer_' + request_id, 'type': 'function', 'function': {
                        'name': required_tool, 'arguments': json.dumps(arguments)}}]}
                write_json(directory / 'tool_protocol_adapter.json', {
                    'policy': 'model-json-arguments-to-required-function-v1',
                    'required_tool': required_tool, 'model_written_arguments': arguments,
                    'adapted_message': adapted, 'raw_response': 'response.json'})
                result = {**result, 'choices': [{**result['choices'][0], 'message': adapted}]}
            return result
        except Exception as error:
            # No raw request headers or key-bearing exception representation.
            status.update({'status': 'failed_or_unreconciled', 'error_type': type(error).__name__,
                           'http_status': getattr(error, 'code', None)})
            if isinstance(error, urllib.error.HTTPError):
                body = error.read(32768).decode('utf-8', errors='replace').replace(key, '[REDACTED]')
                (directory / 'provider_error.txt').write_text(body)
            raise
        finally:
            status.update({'finished_utc': utcnow(), 'elapsed_seconds': time.monotonic() - started})
            write_json(directory / 'status.json', status)
            write_json(self.root / 'budget_summary.json', self.ledger.summary())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--qualify', action='store_true')
    args = parser.parse_args()
    investigator = Investigator(args.run_root, json.loads(args.config.read_text()))
    if args.qualify:
        tool = {'type': 'function', 'function': {'name': 'read_symbol', 'description': 'Read a Python symbol.',
                'parameters': {'type': 'object', 'properties': {'symbol': {'type': 'string'}}, 'required': ['symbol']}}}
        messages = [{'role': 'user', 'content': 'Infrastructure check, no benchmark case: call read_symbol with symbol parse_path. Do not invent a tool result.'}]
        result = investigator.complete(messages, tools=[tool], cell_id='endpoint_qualification', max_tokens=1024)
        message = result['choices'][0]['message']
        calls = message.get('tool_calls', [])
        passed = any(c['function']['name'] == 'read_symbol' and
                     json.loads(c['function']['arguments']).get('symbol') == 'parse_path' for c in calls)
        qualification = {'tool_call_passed': passed, 'provider': result.get('provider'),
                         'model': result.get('model'), 'reasoning_field_present': bool(message.get('reasoning') or message.get('reasoning_details')),
                         'security_benchmark_result': False, 'budget': investigator.ledger.summary()}
        write_json(args.run_root / 'endpoint_qualification.json', qualification)
        print(json.dumps(qualification, indent=2))
    else:
        print(json.dumps(investigator.ledger.summary(), indent=2))


if __name__ == '__main__':
    main()
