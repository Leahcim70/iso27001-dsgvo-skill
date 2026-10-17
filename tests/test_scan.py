"""Regression tests use synthetic data and the scanner's public CLI only."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / 'plugins/iso27001-dsgvo/skills/iso27001-dsgvo/scripts/scan.py'
SPEC = importlib.util.spec_from_file_location('compliance_scan', SCANNER)
scan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scan
SPEC.loader.exec_module(scan)
FAKE_KEY = 'AKIA' + 'A' * 16


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def run_scan(self, path=None, *args):
        return subprocess.run([sys.executable, '-B', str(SCANNER), str(path or self.root), *args],
                              capture_output=True, text=True)

    def test_sensitive_values_never_appear_in_any_output_format(self):
        self.write('config.env', 'AWS_ACCESS_KEY_ID=' + FAKE_KEY + '\n')
        self.write('log.py', 'logger.info("token=%s", "DUMMY_PRIVATE_VALUE_12345")\n')
        for format_ in ['json', 'md', 'text']:
            with self.subTest(format=format_):
                result = self.run_scan(None, '--format', format_)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(FAKE_KEY, result.stdout + result.stderr)
                self.assertNotIn('DUMMY_PRIVATE_VALUE_12345', result.stdout + result.stderr)
        data = json.loads(self.run_scan(None, '--format', 'json').stdout)
        self.assertEqual({f['rule'] for f in data['findings']}, {'SEC-003', 'LOG-001'})
        self.assertTrue(all(f.get('snippet', '') == '' for f in data['findings']))

    def test_old_suppression_markers_cannot_hide_a_secret(self):
        for line in ['password = "DUMMY_PASSWORD_12345"; label = "compliance-ignore"',
                     'password = "DUMMY_PASSWORD_12345" # compliance-ignore']:
            path = self.write('password.py', line + '\n')
            result = self.run_scan(path, '--format', 'json')
            self.assertEqual(result.returncode, 1)
            self.assertIn('SEC-001', [f['rule'] for f in json.loads(result.stdout)['findings']])

    def test_incomplete_inputs_are_reported_and_fail_the_cli(self):
        cases = [('large.py', ' ' * 1000001, 'size'),
                 ('long.py', 'password = "DUMMY_PASSWORD_12345"' + ' ' * 2100, 'line_length')]
        for name, content, reason in cases:
            with self.subTest(reason=reason):
                result = self.run_scan(self.write(name, content), '--format', 'json')
                data = json.loads(result.stdout)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(data['complete'])
                self.assertIn(reason, [item['reason'] for item in data['skipped']])

    def test_undecodable_file_is_not_silently_accepted(self):
        path = self.root / 'broken.py'
        path.write_bytes(b'\xff\xfe\x00')
        result = self.run_scan(path, '--format', 'json')
        self.assertEqual(result.returncode, 2)
        self.assertIn('encoding', [x['reason'] for x in json.loads(result.stdout)['skipped']])

    def test_file_and_directory_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / 'outside.env'
            outside.write_text('AWS_ACCESS_KEY_ID=' + FAKE_KEY)
            (self.root / 'linked.env').symlink_to(outside)
            (self.root / 'linked_dir').symlink_to(other, target_is_directory=True)
            data_result = self.run_scan(None, '--format', 'json')
            data = json.loads(data_result.stdout)
            self.assertEqual(data_result.returncode, 2)
            self.assertEqual(data['findings'], [])
            self.assertEqual(sum(x['reason'] == 'symlink' for x in data['skipped']), 2)
            direct = self.run_scan(self.root / 'linked.env', '--format', 'json')
            self.assertEqual(direct.returncode, 2)
            self.assertNotIn(FAKE_KEY, direct.stdout)

    def test_read_errors_are_recorded_without_exception_contents(self):
        path = self.write('safe.py', 'x = 1\n')
        issues = []
        with mock.patch('builtins.open', side_effect=PermissionError('PRIVATE_EXCEPTION_VALUE')):
            findings = scan.scan_file(str(path), 'safe.py', issues)
        self.assertEqual(findings, [])
        self.assertEqual(issues[0].reason, 'read_error')
        self.assertNotIn('PRIVATE_EXCEPTION_VALUE', str(issues))

    def test_partial_scan_takes_precedence_over_findings(self):
        self.write('key.env', 'AWS_ACCESS_KEY_ID=' + FAKE_KEY)
        self.write('large.py', ' ' * 1000001)
        result = self.run_scan(None, '--format', 'json')
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data['counts']['CRITICAL'], 1)
        self.assertFalse(data['complete'])

    def test_no_supported_files_and_missing_paths_do_not_pass(self):
        for path in [self.root, self.root / 'missing']:
            with self.subTest(path=path):
                self.assertEqual(self.run_scan(path).returncode, 2)

    def test_filter_does_not_turn_a_high_finding_into_success(self):
        path = self.write('weak.py', 'digest = hashlib.md5(value)\n')
        result = self.run_scan(path, '--format', 'json', '--min-severity', 'CRITICAL')
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(data['counts']['HIGH'], 1)
        self.assertEqual(data['findings'], [])

    def test_clean_source_passes(self):
        path = self.write('safe.py', 'answer = 42\n')
        result = self.run_scan(path, '--format', 'json')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)['complete'])

    def test_output_limits_do_not_hide_counts_or_coverage(self):
        self.write('key.env', 'AWS_ACCESS_KEY_ID=' + FAKE_KEY + '\npassword = "DUMMY_PASSWORD_12345"\n')
        result = self.run_scan(None, '--format', 'json', '--max-findings', '1')
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(data['truncated'])
        self.assertEqual(len(data['findings']), 1)
        self.assertEqual(data['counts']['CRITICAL'], 2)

    def test_invalid_output_limit_is_rejected(self):
        path = self.write('safe.py', 'x = 1\n')
        self.assertEqual(self.run_scan(path, '--max-findings', '0').returncode, 2)

    def test_untrusted_names_cannot_inject_output_lines(self):
        path = self.write('file\n::warning::`[x](https:example).env', 'AWS_ACCESS_KEY_ID=' + FAKE_KEY)
        for format_ in ['md', 'text']:
            result = self.run_scan(path, '--format', format_)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(any(line.startswith('::warning::') for line in result.stdout.splitlines()))
            self.assertNotIn('[x](', result.stdout)

    @unittest.skipIf(sys.platform == 'win32', 'GitHub example uses bash on Ubuntu')
    def test_ci_pipeline_fails_with_a_critical_finding(self):
        import shlex
        path = self.write('key.env', 'AWS_ACCESS_KEY_ID=' + FAKE_KEY)
        script = ' '.join(map(shlex.quote, [sys.executable, str(SCANNER), str(path)]))
        script += ' | tee ' + shlex.quote(str(self.root / 'summary.md'))
        result = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(FAKE_KEY, result.stdout)
        example = (ROOT / 'examples/github-action.yml').read_text()
        self.assertIn('shell: bash', example)


if __name__ == '__main__':
    unittest.main()
