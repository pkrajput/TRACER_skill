"""Recorded OpenRouter JSON-action transport for the fixed repair investigator."""
from __future__ import annotations

import json

from security_ground_truth.runtime.model_gateway import Investigator


class OpenRouterRepair(Investigator):
    def __init__(self, run_root, config, response_schema):
        super().__init__(run_root,config)
        self.response_schema=response_schema

    def message_limit(self, system):
        """Reserve the same system/schema overhead in engine and transport."""
        system_bytes=len(json.dumps(system).encode())
        legacy_limit=100000 if self.config.get('protocol','').startswith(('v10','v11','v12')) else 87000
        return min(legacy_limit,self.config.get('max_context_message_bytes',90000)-system_bytes-1000,
                   120000-system_bytes-len(json.dumps(self.response_schema).encode())-4000)

    def generate(self, system, messages, *, cell_id):
        from security_ground_truth.repair_check.repair import bounded_messages
        # Include system/schema overhead when bounding archived exchanges. Never
        # remove the initial treatment or the latest evidence to fit a request.
        limit=self.message_limit(system)
        messages=bounded_messages(messages,limit=limit)
        protocol_messages=[{'role':'system','content':system}]
        protocol_messages.extend({'role':'assistant' if role=='model' else 'user','content':text}
                                 for role,text in messages)
        function={'type':'function','function':{'name':'perform_actions',
                  'description':'Return the next one to three bounded investigation or repair actions.',
                  'parameters':self.response_schema}}
        result=self.complete(protocol_messages,tools=[function],cell_id=cell_id,
                             max_tokens=8192,required_tool='perform_actions')
        message=result['choices'][0]['message'];calls=message.get('tool_calls') or []
        if len(calls)!=1 or calls[0]['function']['name']!='perform_actions':
            raise ValueError('Fixed investigator did not return the required action object')
        answer=json.loads(calls[0]['function']['arguments'])
        if not isinstance(answer,dict):raise ValueError('Investigator actions must be an object')
        return answer,result.get('id') or result.get('model')
