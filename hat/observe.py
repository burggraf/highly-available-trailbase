"""Offline capture inventory only: never authorizes or performs an action."""
import json
import sys

MAX_INPUT = 1024 * 1024
CATEGORIES = ('authority', 'acknowledged_data', 'auth_state', 'restore_image',
              'fencing', 'node_admission', 'ingress', 'controller_prerequisites')


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError('nonfinite number')


def _finite_float(value):
    number = float(value)
    if not -float('inf') < number < float('inf'):
        raise ValueError('nonfinite number')
    return number


def _report(states, reasons):
    return {'mode': 'observation_only', 'decision': 'refuse',
            'promotion_authorized': False, 'action_capabilities': [],
            'evidence_statuses': states, 'reasons': reasons}


def observe(capture):
    """Inventory declared capture states; contents are never treated as proof."""
    if (not isinstance(capture, dict) or set(capture) != {'version', 'evidence'}
            or type(capture['version']) is not int or capture['version'] != 1
            or not isinstance(capture['evidence'], dict)
            or set(capture['evidence']) - set(CATEGORIES)):
        raise ValueError('invalid envelope')
    states = {}
    for category in CATEGORIES:
        entry = capture['evidence'].get(category, {'state': 'missing'})
        if (not isinstance(entry, dict) or set(entry) - {'state', 'capture'}
                or entry.get('state') not in ('missing', 'uncertain', 'reported')):
            raise ValueError('invalid entry')
        state = entry['state']
        if 'capture' in entry:
            if (state == 'missing' or not isinstance(entry['capture'], (dict, list))
                    or not entry['capture']):
                raise ValueError('invalid capture content')
        elif state == 'reported':
            raise ValueError('reported capture absent')
        states[category] = 'reported_unverified' if state == 'reported' else state
    return _report(states, ['automatic_actions_disabled'] +
                   [f'{state}:{category}' for category, state in states.items()])


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError('arguments unsupported')
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError('capture too large')
        capture = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant, parse_float=_finite_float)
        report = observe(capture)
        status = 0
    except (ValueError, RecursionError):
        report = _report({}, ['invalid_capture'])
        status = 2
    print(json.dumps(report, separators=(',', ':'), allow_nan=False))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
