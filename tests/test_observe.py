"""Actual offline entrypoint checks. No HAT/provider calls or deployment inputs."""
import json
import subprocess
import sys
from pathlib import Path
import unittest

ENTRY = Path(__file__).resolve().parents[1] / 'hat/observe.py'
CATEGORIES = ('authority', 'acknowledged_data', 'auth_state', 'restore_image',
              'fencing', 'node_admission', 'ingress', 'controller_prerequisites')

AUDITED = r'''
import json, os, sys
entry, mode = sys.argv[1:]
code = compile(open(entry, 'rb').read(), entry, 'exec') if mode == 'observe' else None
sys.argv = [entry]
def deny(event, args):
    if (event == 'open' or event.startswith('socket.') or
            event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty',
                      'os.posix_spawn', 'os.exec', 'os.remove', 'os.rename',
                      'os.mkdir', 'os.rmdir', 'os.chmod', 'os.chown',
                      'os.link', 'os.symlink', 'os.truncate', 'os.chdir')):
        raise RuntimeError('blocked observer capability')
sys.addaudithook(deny)
if mode == 'probe':
    try:
        open('observer-must-not-create', 'w')
    except RuntimeError:
        print('blocked'); sys.exit(3)
    sys.exit(99)
exec(code, {'__name__': '__main__', '__file__': entry})
'''


class ObserveTests(unittest.TestCase):
    def invoke(self, data, *, raw=False, args=(), audited=False):
        self.assertTrue(ENTRY.is_file(), 'missing offline observation entrypoint')
        command = ([sys.executable, '-B', '-c', AUDITED, str(ENTRY), 'observe']
                   if audited else [sys.executable, '-B', str(ENTRY), *args])
        return subprocess.run(command, input=data if raw else json.dumps(data).encode(),
                              capture_output=True, timeout=5)

    def refusal(self, process, code=0):
        self.assertEqual(process.returncode, code, process.stderr.decode())
        self.assertEqual(process.stderr, b'')
        report = json.loads(process.stdout)
        self.assertEqual(report['mode'], 'observation_only')
        self.assertEqual(report['decision'], 'refuse')
        self.assertIs(report['promotion_authorized'], False)
        self.assertEqual(report['action_capabilities'], [])
        return report

    def test_missing_evidence_refuses(self):
        report = self.refusal(self.invoke({'version': 1, 'evidence': {}}))
        self.assertEqual(report['evidence_statuses'], dict.fromkeys(CATEGORIES, 'missing'))
        self.assertEqual(report['reasons'], ['automatic_actions_disabled'] +
                         ['missing:' + key for key in CATEGORIES])

    def test_uncertainty_is_not_cleared_by_reported_capture(self):
        report = self.refusal(self.invoke({'version': 1, 'evidence': {
            'fencing': {'state': 'uncertain', 'capture': {'state': 'offline'}},
            'node_admission': {'state': 'uncertain'},
            'auth_state': {'state': 'missing'}}}))
        self.assertEqual(report['evidence_statuses']['fencing'], 'uncertain')
        self.assertEqual(report['evidence_statuses']['node_admission'], 'uncertain')
        self.assertIn('uncertain:fencing', report['reasons'])

    def test_all_reported_still_unverified_and_non_authorizing(self):
        evidence = {key: {'state': 'reported', 'capture': {'verified': True,
                    'healthy': True, 'secret': 'NEVER_ECHO_CAPTURE'}} for key in CATEGORIES}
        process = self.invoke({'version': 1, 'evidence': evidence})
        report = self.refusal(process)
        self.assertEqual(report['evidence_statuses'], dict.fromkeys(CATEGORIES, 'reported_unverified'))
        self.assertNotIn(b'NEVER_ECHO_CAPTURE', process.stdout + process.stderr)
        self.assertIn('reported_unverified:acknowledged_data', report['reasons'])

    def test_array_capture_and_explicit_missing(self):
        report = self.refusal(self.invoke({'version': 1, 'evidence': {
            'restore_image': {'state': 'reported', 'capture': [{'epoch': 'd1-captured'}]},
            'authority': {'state': 'missing'}}}))
        self.assertEqual(report['evidence_statuses']['restore_image'], 'reported_unverified')
        self.assertEqual(report['evidence_statuses']['authority'], 'missing')

    def test_invalid_structures_refuse_without_echo(self):
        invalid = [None, [], {}, {'version': True, 'evidence': {}},
                   {'version': 2, 'evidence': {}}, {'version': 1, 'evidence': []},
                   {'version': 1, 'evidence': {}, 'execute': 'NEVER_ECHO_CAPTURE'},
                   {'version': 1, 'evidence': {'unknown': {'state': 'reported'}}}]
        for record in (None, [], {}, {'state': 'verified'}, {'state': True},
                       {'state': 'reported'}, {'state': 'reported', 'capture': {}},
                       {'state': 'reported', 'capture': []}, {'state': 'reported', 'capture': 'secret'},
                       {'state': 'missing', 'capture': {'x': 1}},
                       {'state': 'uncertain', 'capture': None},
                       {'state': 'uncertain', 'execute': 'NEVER_ECHO_CAPTURE'}):
            invalid.append({'version': 1, 'evidence': {'fencing': record}})
        for value in invalid:
            with self.subTest(value=value):
                process = self.invoke(value)
                report = self.refusal(process, 2)
                self.assertEqual(report['reasons'], ['invalid_capture'])
                self.assertNotIn(b'NEVER_ECHO_CAPTURE', process.stdout + process.stderr)

    def test_invalid_json_and_size_refuse(self):
        cases = [b'', b'NEVER_ECHO_CAPTURE', b'\xff',
                 b'{"version":1,"version":1,"evidence":{}}',
                 b'{"version":1,"evidence":{"fencing":{"state":"reported","capture":{"x":1,"x":2}}}}',
                 b'{"version":1,"evidence":{"fencing":{"state":"reported","capture":{"x":NaN}}}}',
                 b'{"version":1,"evidence":{"fencing":{"state":"reported","capture":{"x":Infinity}}}}',
                 b'{"version":1,"evidence":{"fencing":{"state":"reported","capture":{"x":1e999}}}}',
                 b'[' * 2000 + b']' * 2000, b' ' * (1024 * 1024 + 1)]
        for data in cases:
            with self.subTest(length=len(data)):
                process = self.invoke(data, raw=True)
                self.refusal(process, 2)
                self.assertNotIn(b'NEVER_ECHO_CAPTURE', process.stdout + process.stderr)
        boundary = b'{"version":1,"evidence":{}}'
        self.refusal(self.invoke(boundary + b' ' * (1024 * 1024 - len(boundary)), raw=True))

    def test_action_arguments_are_not_supported(self):
        self.refusal(self.invoke({'version': 1, 'evidence': {}}, args=('--activate', 'NEVER_ECHO_CAPTURE')), 2)

    def test_actual_entrypoint_has_no_effect_or_file_access(self):
        capture = {'version': 1, 'evidence': {'fencing': {'state': 'uncertain', 'capture': {
            'argv': ['power-off', 'NEVER_ECHO_CAPTURE'], 'path': '/must/not/be/read',
            'url': 'https://example.invalid/never-contact', 'action': 'activate'}}}}
        process = self.invoke(capture, audited=True)
        self.refusal(process)
        self.assertNotIn(b'NEVER_ECHO_CAPTURE', process.stdout + process.stderr)

    def test_audit_guard_negative_control(self):
        process = subprocess.run([sys.executable, '-B', '-c', AUDITED, str(ENTRY), 'probe'],
                                 capture_output=True, timeout=5)
        self.assertEqual(process.returncode, 3, process.stderr.decode())
        self.assertEqual(process.stdout, b'blocked\n')


if __name__ == '__main__':
    unittest.main()
