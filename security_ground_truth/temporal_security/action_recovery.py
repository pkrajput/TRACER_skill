"""Bound identical invalid actions without inventing successful observations."""
import hashlib
import json


class RepetitionGuard:
    def __init__(self):
        self.failures={};self.last_error=None;self.streak=0

    def key(self,action,state):
        return hashlib.sha256((state+json.dumps(action,sort_keys=True)).encode()).hexdigest()

    def blocked(self,action,state):
        return self.failures.get(self.key(action,state),0)>=2

    def success(self):
        self.last_error=None;self.streak=0

    def failure(self,action,state,error):
        key=self.key(action,state);self.failures[key]=self.failures.get(key,0)+1
        if not isinstance(action,dict):action={}
        signature=(action.get('action'),action.get('path'),action.get('hypothesis_id'),str(error))
        self.streak=self.streak+1 if signature==self.last_error else 1;self.last_error=signature
        if self.streak<2 and self.failures[key]<2:return None
        hint={'status':'repair_required','identical_call_blocked_next_time':True,
              'instruction':'Change the failed action using this feedback, choose another supported action, or leave the finding unresolved.'}
        if isinstance(error,SyntaxError):
            lines=action.get('python_code','').splitlines();line=error.lineno or 1
            hint.update(generated_check_error={'line':line,'column':error.offset,
                'source_context':[{'line':i+1,'text':lines[i]} for i in range(max(0,line-3),min(len(lines),line+2))]},
                template='ordinary_result = target(ordinary_input)\ntracer_observe("ordinary_behavior", ordinary_result == expected_result)',
                template_note='Replace placeholders with real imports, inputs and expected behavior; do not declare constant success.')
        elif action.get('action')=='edit':
            hint['template']={'action':'read','path':action.get('path'),'instruction':'Use unique current context and inspect the downstream consumer before an unseeded edit.'}
        else:hint['template']={'action':'assess','hypothesis_id':action.get('hypothesis_id'),
                              'decision':'inconclusive','reason':'Explain the missing evidence; do not fabricate a conclusion.'}
        return hint
