"""Focused, offline tests for v11 deterministic completeness cues."""
from __future__ import annotations

import json
import unittest

from . import v11_cards


ARMS = ('C0', 'C1', 'C2', 'C3')


def group(path, symbol, source, sequence):
    return {
        'group_id': 'g%d' % sequence,
        'path': path,
        'symbol': symbol,
        'start_line': 1,
        'end_line': len(source.splitlines()),
        'source': source,
        'source_abbreviated': False,
        'alert_ids': [],
        'calls': [],
        'guards': [],
    }


def common(groups, *, request='', primary=None):
    primary = groups if primary is None else primary
    return {
        'protocol_revision': v11_cards.POLICY,
        'functional_request': request,
        'current_code_groups': groups,
        'change_audit_bases': [
            {'group_id': row['group_id'], 'path': row['path'], 'symbol': row['symbol']}
            for row in primary
        ],
        'scanner_alerts': [],
        'scanner_counts': {},
        'preloaded_source_ranges': [],
        'preload_selection': {'selected_targets': len(primary)},
        'sibling_change_comparisons': {'pairs': []},
    }


def payloads(value):
    history = {'temporal': {}, 'rationale': {}}
    return {arm: v11_cards.arm_input(value, history, arm) for arm in ARMS}


def cue_rows(payload, cue):
    return [row for row in payload['ast_invariant_completeness_cards']['cards']
            if cue in row['cues']]


class V11CardsTests(unittest.TestCase):
    def assert_treatment_only(self, value, cue):
        values = payloads(value)
        self.assertNotIn('ast_invariant_completeness_cards', values['C0'])
        self.assertNotIn(cue.split('.', 1)[0], json.dumps(values['C0']))
        for arm in ('C1', 'C2', 'C3'):
            self.assertTrue(cue_rows(values[arm], cue), arm)
        return values

    def test_html_entity_cue_preserves_malformed_semicolon_spelling(self):
        sources = [
            ('class PreserveParser(HTMLParser):\n'
             '    def __init__(self):\n'
             '        super().__init__()\n'),
            ('class PreserveParser(HTMLParser):\n'
             '    def __init__(self):\n'
             '        super().__init__(convert_charrefs=False)\n'
             '    def handle_entityref(self, name):\n'
             '        self.result.append("&" + name + ";")\n'
             '    def handle_charref(self, name):\n'
             '        self.result.append("&#" + name + ";")\n'),
        ]
        for sequence, source in enumerate(sources):
            with self.subTest(sequence=sequence):
                value = common(
                    [group('html.py', 'PreserveParser', source, sequence)],
                    request='Strip tags while preserving entity and character references.',
                )
                self.assert_treatment_only(value, v11_cards.HTML_ENTITY_CUE)
                self.assertIn('&gotcha without turning it into &gotcha;',
                              v11_cards.HTML_ENTITY_CUE)
                self.assertIn('synthetic ";"', v11_cards.HTML_ENTITY_CUE)

    def test_uri_component_cue_points_to_resolver_field_boundaries(self):
        source = (
            'def _resolve_connection(self):\n'
            '    conn = self.get_connection()\n'
            '    return {\n'
            '        "url": f"{conn.host}:{conn.port}",\n'
            '        "schema": conn.schema,\n'
            '        "conn_prefix": conn.extra_dejson.get("conn_prefix"),\n'
            '    }\n'
        )
        value = common([group('hook.py', 'Hook._resolve_connection', source, 1)])
        values = self.assert_treatment_only(value, v11_cards.URI_COMPONENT_CUE)
        self.assertIn('"/" in host', v11_cards.URI_COMPONENT_CUE)
        self.assertIn('"?" in schema', v11_cards.URI_COMPONENT_CUE)
        self.assertIn('before URL assembly', v11_cards.URI_COMPONENT_CUE)
        for arm in ('C1', 'C2', 'C3'):
            text = json.dumps(values[arm]['ast_invariant_completeness_cards'])
            self.assertNotIn(v11_cards._V10_COMPONENT_CUE, text)

    def test_form_help_text_assignment_gets_escape_and_opt_in_cue(self):
        source = (
            'def get_field_options(self, field):\n'
            '    options = {}\n'
            '    options["label"] = field.label\n'
            '    options["help_text"] = field.help_text\n'
            '    return options\n'
        )
        value = common([group('forms.py', 'FormBuilder.get_field_options', source, 1)])
        values = self.assert_treatment_only(value, v11_cards.FORM_HELP_TEXT_CUE)
        for arm in ('C1', 'C2', 'C3'):
            text = json.dumps(values[arm]['ast_invariant_completeness_cards'])
            self.assertIn('conditional_escape', text)
            self.assertIn('WAGTAILFORMS_HELP_TEXT_ALLOW_HTML', text)

    def test_cross_backend_session_cue_covers_direct_and_inherited_loads(self):
        definitions = [
            ('sessions/backends/db.py',
             'def load(self):\n'
             '    try:\n'
             '        return self.decode(self.get_record())\n'
             '    except Exception:\n'
             '        self.create()\n'
             '        return {}\n'),
            ('sessions/backends/cache.py',
             'def load(self):\n'
             '    value = self.cache.get(self.cache_key)\n'
             '    if value is None:\n'
             '        self.create()\n'
             '        return {}\n'
             '    return self.decode(value)\n'),
            ('sessions/backends/cached_db.py',
             'def load(self):\n'
             '    value = self.cache.get(self.cache_key)\n'
             '    if value is None:\n'
             '        value = super(SessionStore, self).load()\n'
             '    return value\n'),
            ('sessions/backends/file.py',
             'def load(self):\n'
             '    try:\n'
             '        return self.decode(self.read_file())\n'
             '    except Exception:\n'
             '        self.create()\n'
             '        return {}\n'),
        ]
        groups = [group(path, 'SessionStore.load', source, sequence)
                  for sequence, (path, source) in enumerate(definitions)]
        value = common(groups)
        values = payloads(value)
        self.assertNotIn('ast_invariant_completeness_cards', values['C0'])
        for arm in ('C1', 'C2', 'C3'):
            cards = values[arm]['ast_invariant_completeness_cards']['cards']
            cross_rows = [row for row in cards if any(
                cue.startswith('Multiple session load backends are modified together')
                for cue in row['cues'])]
            self.assertEqual(
                {(row['path'], row['symbol']) for row in cross_rows},
                {(path, 'SessionStore.load') for path, _ in definitions},
            )
            text = json.dumps(cross_rows)
            self.assertIn('cache.py, cached_db.py, db.py, file.py', text)
            self.assertIn('including an inherited fallback', text)
            self.assertIn('_get_or_create_session_key', text)
        self.assertNotIn('Multiple session load backends', json.dumps(values['C0']))

    def test_cli_target_cue_covers_validator_and_constructor_consumer(self):
        validator = (
            'def _process_targets(self, targets):\n'
            '    if isinstance(targets, str):\n'
            '        return [value.strip() for value in targets.split(",")]\n'
            '    return list(targets)\n'
        )
        constructor = (
            'def __init__(self, binary, targets, options):\n'
            '    self.binary = binary\n'
            '    self.targets = self._process_targets(targets)\n'
            '    self.command = [binary] + shlex.split(options) + self.targets\n'
        )
        groups = [
            group('process.py', 'Runner._process_targets', validator, 1),
            group('process.py', 'Runner.__init__', constructor, 2),
        ]
        value = common(groups)
        values = self.assert_treatment_only(value, v11_cards.CLI_TARGET_CUE)
        for arm in ('C1', 'C2', 'C3'):
            rows = cue_rows(values[arm], v11_cards.CLI_TARGET_CUE)
            self.assertEqual(
                {row['symbol'] for row in rows},
                {'Runner._process_targets', 'Runner.__init__'},
            )
            text = json.dumps(rows)
            self.assertIn('begin with', text)
            self.assertIn('allowed target grammar', text)
            self.assertIn('shlex parsing and list-form', text)
            self.assertNotIn(v11_cards._V10_COMPONENT_CUE, text)

    def test_verify_arms_reports_full_c0_treatment_isolation(self):
        source = (
            'def get_field_options(field):\n'
            '    return {"help_text": field.help_text}\n'
        )
        value = common([group('forms.py', 'get_field_options', source, 1)])
        result = v11_cards.verify_arms(
            value,
            {'temporal': {}, 'rationale': {}},
        )
        self.assertTrue(result['arm_isolation_verified'])
        self.assertTrue(result['C0_ast_cues_absent'])
        self.assertTrue(result['C0_treatment_cards_absent'])


if __name__ == '__main__':
    unittest.main()
