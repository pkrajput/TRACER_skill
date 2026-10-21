"""Disambiguate legacy scanner IDs without dropping any scanner result.

Legacy IDs used rule and line range only, so different CodeQL paths could
collide. Raw scanner files remain immutable. The investigator uses this
deterministic view, with a reversible raw-row mapping for later evaluation.
"""
from collections import Counter
import hashlib
import json


def unique_alerts(alerts):
    counts = Counter(a['alert_id'] for a in alerts)
    occurrences = Counter()
    result = []
    for index, alert in enumerate(alerts):
        row = dict(alert)
        original = row['alert_id']
        if counts[original] > 1:
            content = {k: v for k, v in row.items() if k != 'gold_label'}
            digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:16]
            occurrences[(original, digest)] += 1
            row.update(alert_id=f'{original}-{digest}-{occurrences[(original, digest)]}',
                       scanner_original_alert_id=original, scanner_original_row=index)
        result.append(row)
    if len({a['alert_id'] for a in result}) != len(result):
        raise ValueError('Scanner identity collision after disambiguation')
    return result
