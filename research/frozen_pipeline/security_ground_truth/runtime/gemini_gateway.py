"""Direct lab Gemini transport with archived tools and the shared study ledger."""
import json
import math
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid

from .common import utcnow, write_json
from .context_budget import fit_messages
from .model_gateway import Investigator


def load_gemini_key(path):
    for line in Path(path).read_text().splitlines():
        if line.strip().startswith('GEMINI_API_KEY='):
            return line.strip().split('=', 1)[1].strip().strip('\"\'')
    raise ValueError('Gemini credential unavailable')


class GeminiInvestigator(Investigator):
    def _complete_once(self, messages, *, tools=None, cell_id, max_tokens=4096,
                       final_json=False, required_tool=None):
        request_id = uuid.uuid4().hex
        directory = self.root / 'requests' / request_id
        messages, changes = fit_messages(messages)
        payload = {'model': self.config['model'], 'messages': messages, 'temperature': 0,
                   'max_tokens': max_tokens, 'stream': False,
                   'reasoning_effort': self.config.get('reasoning_effort', 'low')}
        if tools:
            payload['tools'] = tools
        if required_tool:
            matches = [t['function'] for t in (tools or []) if t['function']['name'] == required_tool]
            if final_json or len(matches) != 1:
                raise ValueError('Invalid required protocol stage')
            function = matches[0]
            payload['tools'] = [t for t in tools if t['function']['name'] == required_tool]
            payload['tool_choice'] = {'type':'function','function':{'name':required_tool}}
        if final_json:
            payload.pop('tools', None)
            payload['response_format'] = {'type': 'json_object'}
        encoded = json.dumps(payload).encode()
        if len(encoded) > 120000:
            raise ValueError('Per-request evidence budget exceeded')
        prices = self.config['pricing_per_million_tokens']
        reservation = (((len(encoded)+4096)*prices['input'] +
                        (max_tokens+4096)*prices['output'])/1e6 + 0.01)*1.10
        self.ledger.reserve(request_id, reservation, {'cell_id':cell_id, 'provider':'gemini-direct','created_utc':utcnow()})
        write_json(directory/'request.json', payload)
        write_json(directory/'context_budget.json', {'changes':changes})
        status = {'request_id':request_id,'cell_id':cell_id,'model':self.config['model'],
                  'provider_requested':'gemini-direct','started_utc':utcnow(),'reservation_usd':reservation}
        write_json(directory/'status.json',status)
        started=time.monotonic()
        key=load_gemini_key(self.config['credential_file'])
        request=urllib.request.Request('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
             data=encoded,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=180) as response:
                result=json.load(response)
            write_json(directory/'response.json', result)
            if result.get('error') or not result.get('choices'):
                raise ValueError('Gemini returned no completion; inspect archived response')
            usage=result.get('usage',{})
            inp,out,total=(usage.get(k) for k in ['prompt_tokens','completion_tokens','total_tokens'])
            known=all(isinstance(x,int) and x>=0 for x in [inp,out,total])
            # Charge all non-input tokens, including any separately counted
            # thinking tokens; ignore cache discounts conservatively.
            cost=(inp*prices['input']+max(out,total-inp)*prices['output'])/1e6 if known else None
            self.ledger.settle(request_id,cost,{'cell_id':cell_id,'provider':'gemini-direct','usage':usage,
                  'generation_id':result.get('id'),'pricing':prices,'cost_basis':'published_list_price_no_cache_discount'},
                  cost_basis='usage_priced')
            status.update(status='completed',usage=usage,estimated_list_price_usd=cost,
                          cost_basis='published_list_price_no_cache_discount')
            if not isinstance(result['choices'][0].get('message'), dict):
                reason = result['choices'][0].get('finish_reason', 'missing_message')
                raise ValueError('Provider returned no message: ' + str(reason))
            if required_tool:
                calls = result['choices'][0]['message'].get('tool_calls') or []
                if not calls or any(c['function']['name'] != required_tool for c in calls):
                    raise ValueError('Gemini did not execute the required native function')
                for call in calls:
                    args = json.loads(call['function']['arguments'])
                    if not isinstance(args,dict) or set(function['parameters'].get('required',[]))-args.keys():
                        raise ValueError('Required-stage arguments incomplete')
                # Preserve provider thought signatures inside tool_calls exactly;
                # synthetic assistant calls would break signed Gemini history.
                write_json(directory/'required_tool_protocol.json', {
                    'policy':'provider-native-forced-function-v1','required_tool':required_tool,
                    'tool_calls':calls,'raw_response':'response.json'})
            return result
        except Exception as error:
            status.update(status='failed_or_unreconciled',error_type=type(error).__name__,http_status=getattr(error,'code',None))
            if isinstance(error,urllib.error.HTTPError):
                (directory/'provider_error.txt').write_text(error.read(32768).decode(errors='replace').replace(key,'[REDACTED]'))
            raise
        finally:
            status.update(finished_utc=utcnow(),elapsed_seconds=time.monotonic()-started)
            write_json(directory/'status.json',status)
            write_json(self.root/'budget_summary.json',self.ledger.summary())


def make_investigator(root, config):
    return GeminiInvestigator(root, config) if config.get('provider') == 'gemini-direct' else Investigator(root, config)
