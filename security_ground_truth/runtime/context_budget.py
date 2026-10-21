"""Deterministic context limits; complete evidence remains in trajectory archives."""
import copy
import json


def fit_messages(messages, max_bytes=90000):
    result = copy.deepcopy(messages)
    changes = []
    size = lambda: len(json.dumps(result).encode())
    if size() <= max_bytes:
        return result, changes
    # Provider reasoning is preserved in raw response archives. Older reasoning
    # fields are not needed to execute the latest pending tool call.
    for index, message in enumerate(result[:-3]):
        for key in ('reasoning', 'reasoning_details'):
            if key in message:
                del message[key]
                changes.append({'message_index': index, 'removed_from_context': key})
        if size() <= max_bytes:
            return result, changes
    # Preserve system, seed/history evidence and the most recent exchange.
    # Older long tool outputs are explicitly abbreviated, never silently lost.
    for index, message in enumerate(result[:-4]):
        content = message.get('content')
        if message.get('role') != 'tool' or not isinstance(content, str) or len(content) <= 1800:
            continue
        message['content'] = json.dumps({'context_abbreviated': True, 'tool_call_id': message.get('tool_call_id'),
                                        'full_output_retained_in_trajectory': True, 'prefix': content[:1400],
                                        'note': 'Retrieve relevant evidence again if needed; omitted text is not a negative finding.'})
        changes.append({'message_index': index, 'tool_output_abbreviated': True})
        if size() <= max_bytes:
            return result, changes
    if size() > max_bytes:
        raise ValueError('Evidence cannot fit without removing protected seed or recent execution evidence')
    return result, changes
