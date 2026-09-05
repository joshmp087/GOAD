"""Exercise the hostname role's real task conditions and verification script.

No guest or service is modified. Service/hostname modules are stubbed, and the
PowerShell check runs with a mocked registry reader on Windows test machines.
"""
import base64
from pathlib import Path
import shutil
import subprocess
import unittest

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[2]
TASKS = yaml.safe_load((ROOT / 'ansible/roles/settings/hostname/tasks/main.yml').read_text('utf-8'))
ENV = jinja2.Environment(undefined=jinja2.StrictUndefined)
ENV.filters['bool'] = lambda value: str(value).lower() in {'true', 'yes', '1', 'on'}


def run_role(context, service_exists=True, fail_stop=False, reboot_required=True):
    """Evaluate actual YAML conditions around module doubles, preserving order."""
    calls = []

    def run(tasks):
        for task in tasks:
            conditions = task.get('when', [])
            if not isinstance(conditions, list):
                conditions = [conditions]
            if not all(ENV.compile_expression(condition)(**context) for condition in conditions):
                continue
            if 'block' in task:
                run(task['block'])
                continue
            module = next(key for key in task if key in {
                'ansible.windows.win_service', 'win_hostname', 'win_reboot', 'ansible.windows.win_shell'})
            arguments = task[module]
            calls.append((module, arguments))
            if module == 'ansible.windows.win_service':
                if arguments.get('state') == 'stopped' and fail_stop:
                    # No failed_when/ignore_errors override may hide this.
                    if task.get('ignore_errors') or task.get('failed_when') is False:
                        continue
                    raise RuntimeError('Cloudbase stop failed', calls)
                result = {'exists': service_exists}
            elif module == 'win_hostname':
                result = {'reboot_required': reboot_required}
            else:
                result = {}
            if task.get('register'):
                context[task['register']] = result

    run(TASKS)
    return calls


class HostnameOwnershipTests(unittest.TestCase):
    def test_default_and_false_optin_preserve_existing_role_behavior(self):
        for context in [{}, {'cybercore_manage_hostname': False}, {'cybercore_manage_hostname': 'false'}]:
            with self.subTest(context=context):
                self.assertEqual(['win_hostname', 'win_reboot'],
                                 [module for module, _ in run_role(context)])

    def test_optin_stops_and_disables_existing_cloudbase_before_rename(self):
        calls = run_role({'cybercore_manage_hostname': True})
        self.assertEqual(['ansible.windows.win_service', 'ansible.windows.win_service',
                          'win_hostname', 'win_reboot', 'ansible.windows.win_shell'],
                         [module for module, _ in calls])
        self.assertEqual({'name': 'cloudbase-init'}, calls[0][1])
        self.assertEqual({'name': 'cloudbase-init', 'state': 'stopped', 'start_mode': 'disabled'}, calls[1][1])

    def test_absent_service_is_not_created_or_modified(self):
        calls = run_role({'cybercore_manage_hostname': True}, service_exists=False)
        self.assertEqual(['ansible.windows.win_service', 'win_hostname',
                          'win_reboot', 'ansible.windows.win_shell'], [module for module, _ in calls])
        self.assertEqual({'name': 'cloudbase-init'}, calls[0][1])

    def test_service_stop_failure_prevents_rename(self):
        with self.assertRaises(RuntimeError) as raised:
            run_role({'cybercore_manage_hostname': True}, fail_stop=True)
        self.assertNotIn('win_hostname', [module for module, _ in raised.exception.args[1]])

    def test_pending_name_is_checked_even_when_hostname_module_does_not_reboot(self):
        calls = run_role({'cybercore_manage_hostname': True}, reboot_required=False)
        self.assertNotIn('win_reboot', [module for module, _ in calls])
        self.assertEqual('ansible.windows.win_shell', calls[-1][0])
        check = next(task for task in TASKS if 'ansible.windows.win_shell' in task)
        self.assertIs(check['changed_when'], False)

    def test_real_powershell_check_rejects_active_or_pending_name_drift(self):
        powershell = shutil.which('powershell') or shutil.which('pwsh')
        if not powershell:
            self.skipTest('PowerShell is unavailable for the offline script check')
        script = next(task['ansible.windows.win_shell'] for task in TASKS if 'ansible.windows.win_shell' in task)
        rendered = ENV.from_string(script).render(hostname='WS01')
        for active, pending, succeeds in [
            ('WS01', 'ws01', True),
            ('WS01-JOSHUAMPAY', 'WS01', False),
            ('WS01', 'WS01-JOSHUAMPAY', False),
            ('WS01-JOSHUAMPAY', 'WS01-JOSHUAMPAY', False),
        ]:
            with self.subTest(active=active, pending=pending):
                # Shadow the reader before executing the exact rendered role
                # script. No registry reads or writes reach the test machine.
                wrapper = """
function Get-ItemProperty {
  param([string]$LiteralPath)
  if ($LiteralPath.EndsWith('\\ActiveComputerName')) {
    return [pscustomobject]@{ComputerName='%s'}
  }
  return [pscustomobject]@{ComputerName='%s'}
}
try {
%s
  exit 0
} catch { exit 1 }
""" % (active, pending, rendered)
                encoded = base64.b64encode(wrapper.encode('utf-16le')).decode('ascii')
                result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(0 if succeeds else 1, result.returncode, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
