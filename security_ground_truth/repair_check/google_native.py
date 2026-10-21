"""Native Gemini JSON transport for defensive repair, with immutable request logs."""
from __future__ import annotations
import json, math, time, uuid, urllib.request, urllib.error
from pathlib import Path
from security_ground_truth.runtime.model_gateway import Investigator
from security_ground_truth.runtime.gemini_gateway import load_gemini_key
from security_ground_truth.runtime.common import write_json, utcnow

CATEGORIES = ['HARASSMENT','HATE_SPEECH','SEXUALLY_EXPLICIT','DANGEROUS_CONTENT']
ACTION_SCHEMA = {'type':'object','required':['actions'],'properties':{
    'actions':{'type':'array','minItems':1,'maxItems':3,'items':{
        'type':'object','required':['action'],'properties':{
            'action':{'type':'string','enum':['read','search','edit','syntax','finish']},
            **{k:{'type':'string','maxLength':24000} for k in ['path','text','old','new','summary']},
            'start':{'type':'integer','minimum':1,'maximum':200000},
            'lines':{'type':'integer','minimum':1,'maximum':160}}}}}}

class GoogleRepair(Investigator):
    def generate(self, system, messages, *, cell_id):
        # Retry only transport failures, never refusals or invalid model actions.
        # Each HTTP attempt gets its own reservation and archived request.
        for attempt in range(3):
            try:
                return self._generate_once(system, messages, cell_id=cell_id)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                retryable = not isinstance(error, urllib.error.HTTPError) or error.code in {429, 502, 503, 504}
                if not retryable or attempt == 2:
                    raise
                time.sleep(10 * (attempt + 1))

    def _generate_once(self, system, messages, *, cell_id):
        self._pace()
        rid=uuid.uuid4().hex;directory=self.root/'requests'/rid
        payload={'systemInstruction':{'parts':[{'text':system}]},
          'contents':[{'role':role,'parts':[{'text':text}]} for role,text in messages],
          'generationConfig':{'temperature':self.config.get('temperature',1),'maxOutputTokens':8192,'responseMimeType':'application/json',
                              'responseJsonSchema':self.config.get('response_schema',ACTION_SCHEMA),
                              'thinkingConfig':{'thinkingLevel':'LOW'}},
          'toolConfig':{'functionCallingConfig':{'mode':'NONE'}},
          'safetySettings':[{'category':'HARM_CATEGORY_'+c,'threshold':'BLOCK_NONE'} for c in CATEGORIES]}
        encoded=json.dumps(payload).encode()
        if len(encoded)>120000:raise ValueError('Repair evidence context limit exceeded')
        prices=self.config['pricing_per_million_tokens']
        reservation=(((len(encoded)+4096)*prices['input']+8192*prices['output'])/1e6+0.01)*1.1
        self.ledger.reserve(rid,reservation,{'cell_id':cell_id,'provider':'gemini-direct','created_utc':utcnow()})
        write_json(directory/'request.json',payload)
        status={'request_id':rid,'cell_id':cell_id,'started_utc':utcnow(),'model':self.config['model'],
                'provider':'gemini-direct','reservation_usd':reservation}
        write_json(directory/'status.json',status)
        key=load_gemini_key(self.config['credential_file'])
        request=urllib.request.Request('https://generativelanguage.googleapis.com/v1beta/models/'+self.config['model']+':generateContent',
              data=encoded,headers={'x-goog-api-key':key,'Content-Type':'application/json'})
        started=time.monotonic()
        try:
            with urllib.request.urlopen(request,timeout=240) as response:result=json.load(response)
            write_json(directory/'response.json',result)
            usage=result.get('usageMetadata',{});prompt=usage.get('promptTokenCount');total=usage.get('totalTokenCount')
            cost=None
            if isinstance(prompt,int) and isinstance(total,int) and total>=prompt>=0:
                output=max(total-prompt,usage.get('candidatesTokenCount',0)+usage.get('thoughtsTokenCount',0))
                cost=(prompt*prices['input']+output*prices['output'])/1e6
            self.ledger.settle(rid,cost,{'provider':'gemini-direct','cell_id':cell_id,'usage':usage,
                        'model_version':result.get('modelVersion'),'pricing':prices},cost_basis='usage_priced')
            candidates=result.get('candidates',[])
            reason=(result.get('promptFeedback') or {}).get('blockReason')
            if not candidates or reason:
                status['status']='provider_blocked';status['block_reason']=reason
                raise ValueError('Gemini returned no candidate: '+str(reason))
            candidate=candidates[0];status['finish_reason']=candidate.get('finishReason')
            text=''.join(p.get('text','') for p in candidate.get('content',{}).get('parts',[]) if not p.get('thought'))
            if candidate.get('finishReason') not in {'STOP',None}:
                raise ValueError('Gemini finish reason: '+str(candidate.get('finishReason')))
            answer=json.loads(text)
            if not isinstance(answer,dict):raise ValueError('Repair action must be a JSON object')
            status.update(status='completed',usage=usage,estimated_list_price_usd=cost,model_version=result.get('modelVersion'))
            return answer, rid
        except Exception as error:
            status.setdefault('status','failed_or_unreconciled');status['error_type']=type(error).__name__
            if isinstance(error,urllib.error.HTTPError):
                status['http_status']=error.code
                (directory/'provider_error.txt').write_text(error.read(32768).decode(errors='replace').replace(key,'[REDACTED]'))
            raise
        finally:
            status.update(finished_utc=utcnow(),elapsed_seconds=time.monotonic()-started)
            write_json(directory/'status.json',status)
