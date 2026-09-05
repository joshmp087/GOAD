"""Offline guards and transition contracts for the opt-in WS01 repair utility."""
import base64
import copy
from pathlib import Path
import re
import shutil
import subprocess
import unittest

import jinja2
from jinja2.nativetypes import NativeEnvironment
import yaml


ROOT = Path(__file__).resolve().parents[2]
PLAY = yaml.safe_load((ROOT / 'scripts/cybercore/repair-ws01.yml').read_text('utf-8'))[0]
TASKS = PLAY['tasks']
ENV = NativeEnvironment(undefined=jinja2.StrictUndefined)
ENV.filters['bool'] = lambda value: str(value).lower() in {'true', 'yes', '1', 'on'}
ENV.tests['match'] = lambda value, pattern: re.match(pattern, value) is not None


def evaluate(expression, context):
    return ENV.compile_expression(expression)(**context)


def assert_task(task, context):
    for expression in task['ansible.builtin.assert']['that']:
        if not evaluate(expression, context):
            raise ValueError(expression)


def fixture():
    context = {
        'cybercore_repair_ws01': True, 'inventory_hostname': 'ws01',
        'ansible_play_hosts_all': ['ws01'], 'domain_name': 'CC-test-lane',
        'cc_main_data': {'lab': {
            'hosts': {'dc01': {'domain': 'course.example'}},
            'domains': {'course.example': {'dc': 'dc01', 'domain_password': 'fixture-root-secret'},
                        'other.example': {'dc': 'dc02', 'domain_password': 'wrong-fixture-secret'}}}},
        'cc_extension_data': {'lab_extension': {'hosts': {'ws01': {
            'hostname': 'WS01', 'domain': 'course.example', 'type': 'workstation'}}}},
        'cc_report': {'lab': 'CC-test-lane', 'identities': [
            {'name': 'ws01', 'hostname': 'WS01', 'domain': 'course.example'}]},
        'cc_before': {'hostname': 'WS01-OWNER', 'pending_hostname': 'WS01-OWNER',
                      'domain': 'course.example', 'joined': True, 'domain_role': 1,
                      'secure_channel': False, 'utc_epoch': 1000000},
        'lookup': lambda kind, command: '1000000',
    }
    for name, template in PLAY['vars'].items():
        context[name] = ENV.from_string(template).render(**context)
    return context


def walk(tasks):
    for task in tasks:
        yield task
        yield from walk(task.get('block', []))
        yield from walk(task.get('rescue', []))


class Ws01RepairTests(unittest.TestCase):
    def test_authorization_and_path_guards_precede_any_file_read(self):
        first_read = next(i for i, task in enumerate(TASKS) if 'ansible.builtin.include_vars' in task)
        self.assertEqual(2, first_read)
        self.assertTrue(all('ansible.builtin.assert' in task for task in TASKS[:first_read]))
        for optin in [False, 'true', None, 1]:
            context = fixture()
            context['cybercore_repair_ws01'] = optin
            with self.subTest(optin=optin), self.assertRaises(ValueError):
                assert_task(TASKS[0], context)
        for lab in ['GOAD-Light', '../GOAD', 'CC-../../GOAD', '/opt/goad', 'CC-x/y', 'CC-evil..name']:
            context = fixture()
            context['domain_name'] = lab
            with self.subTest(lab=lab), self.assertRaises(ValueError):
                assert_task(TASKS[1], context)
        context = fixture()
        assert_task(TASKS[0], context)
        assert_task(TASKS[1], context)
        path = ENV.from_string(TASKS[first_read]['ansible.builtin.include_vars']['file']).render(**context)
        self.assertEqual('/opt/goad/ad/CC-test-lane/data/config.json', path)

    def test_generated_identity_and_credentials_resolve_to_the_ws01_domain(self):
        context = fixture()
        guard = next(task for task in TASKS if task['name'] == 'Require matching generated workstation identities')
        assert_task(guard, context)
        self.assertEqual('administrator@course.example', context['cc_domain_user'])
        self.assertEqual('fixture-root-secret', context['cc_domain_password'])
        for key, value in [('cc_name', 'sixteencharacter'), ('cc_name', '12345'),
                           ('cc_domain', 'missing.example')]:
            changed = copy.deepcopy(context)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                assert_task(guard, changed)
        context['cc_report']['identities'][0]['hostname'] = 'DIFFERENT'
        with self.assertRaises(ValueError):
            assert_task(guard, context)

    def test_foreign_domain_dc_and_clock_skew_refuse_before_service_changes(self):
        guard_index = next(i for i, task in enumerate(TASKS)
                           if task['name'] == 'Refuse an unexpected machine, domain, or unsynchronized clock')
        service_index = next(i for i, task in enumerate(TASKS) if 'ansible.windows.win_service' in task)
        self.assertLess(guard_index, service_index)
        for field, value in [('domain', 'another.example'), ('domain_role', 4), ('utc_epoch', 999000)]:
            context = fixture()
            context['cc_before'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                assert_task(TASKS[guard_index], context)
        workgroup = fixture()
        workgroup['cc_before'].update(joined=False, domain='WORKGROUP', domain_role=0)
        assert_task(TASKS[guard_index], workgroup)

    def test_healthy_membership_skips_unjoin_but_pending_drift_requires_repair(self):
        repair = next(task for task in TASKS if 'block' in task)
        context = fixture()
        self.assertTrue(evaluate(repair['when'], context))
        context['cc_before'].update(hostname='WS01', pending_hostname='WS01', secure_channel=True)
        self.assertFalse(evaluate(repair['when'], context))
        context['cc_before']['pending_hostname'] = 'WS01-OWNER'
        self.assertTrue(evaluate(repair['when'], context))

    def test_canonical_unjoin_precedes_checked_fallback_and_join_follows_reboot(self):
        repair = next(task for task in TASKS if 'block' in task)['block']
        unjoin = repair[0]
        module = 'ansible.windows.win_domain_membership'
        self.assertEqual('workgroup', unjoin['block'][0][module]['state'])
        fallback = unjoin['rescue'][0]['ansible.windows.win_powershell']
        self.assertEqual('stop', fallback['error_action'])
        self.assertIn('FUnjoinOptions=[uint32]0', fallback['script'])
        self.assertIn('$r.ReturnValue -ne 0', fallback['script'])
        self.assertIn('throw ', fallback['script'])
        self.assertIn('ansible.windows.win_reboot', repair[1])
        self.assertIn('$c.PartOfDomain', repair[2]['ansible.windows.win_shell'])
        self.assertEqual('domain', repair[3][module]['state'])
        self.assertIn('ansible.windows.win_reboot', repair[4])
        requirements = yaml.safe_load((ROOT / 'ansible/requirements.yml').read_text('utf-8'))
        windows = next(collection for collection in requirements['collections'] if collection['name'] == 'ansible.windows')
        self.assertEqual('1.11.0', windows['version'])
        supported = {'state', 'workgroup_name', 'dns_domain_name', 'hostname',
                     'domain_admin_user', 'domain_admin_password', 'domain_ou_path'}
        for task in walk(TASKS):
            if module in task:
                self.assertLessEqual(set(task[module]), supported)
        self.assertNotIn('Remove-ADComputer', (ROOT / 'scripts/cybercore/repair-ws01.yml').read_text('utf-8'))

    def test_all_credential_bearing_tasks_are_hidden_and_use_config_values(self):
        context = fixture()
        for task in walk(TASKS):
            text = str({key: value for key, value in task.items() if key not in {'block', 'rescue'}})
            if ('cc_domain_password' in text or task.get('ansible.builtin.include_vars', {}).get('name')
                    in {'cc_main_data', 'cc_extension_data'}):
                self.assertIs(task.get('no_log'), True, task['name'])
            member = task.get('ansible.windows.win_domain_membership')
            if member:
                self.assertEqual('fixture-root-secret', ENV.from_string(member['domain_admin_password']).render(**context))
                self.assertEqual('administrator@course.example', ENV.from_string(member['domain_admin_user']).render(**context))
        self.assertEqual('ws01', PLAY['hosts'])

    def test_workgroup_readback_accepts_observed_pending_name_but_refuses_unknown_identity(self):
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            self.skipTest('PowerShell is unavailable for the offline script check')
        check = next(task for task in walk(TASKS)
                     if task['name'] == 'Require a clean workgroup state before joining again')
        context = fixture()
        context['cc_before']['pending_hostname'] = 'WS01'
        rendered = ENV.from_string(check['ansible.windows.win_shell']).render(**context)
        for name, joined, succeeds in [('WS01-OWNER', False, True), ('ws01', False, True),
                                      ('UNEXPECTED', False, False), ('WS01', True, False)]:
            with self.subTest(name=name, joined=joined):
                # Shadow the only system reader; this never touches AD or the host.
                wrapper = """
function Get-CimInstance {
  return [pscustomobject]@{ Name='%s'; PartOfDomain=$%s }
}
try {
%s
  exit 0
} catch { exit 1 }
""" % (name, str(joined).lower(), rendered)
                encoded = base64.b64encode(wrapper.encode('utf-16le')).decode('ascii')
                result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(0 if succeeds else 1, result.returncode, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
