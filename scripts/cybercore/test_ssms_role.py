"""Exercise the real SSMS role's task flow with simulated Windows module results.

No installer is downloaded or executed. Jinja evaluates the actual role conditions,
and the harness models the documented module success/failure contracts. This checks
cached/wrong installers, partial installs, reboot return codes and timeouts; a live
Windows install remains necessary to validate Microsoft's installer itself.
"""
from pathlib import Path
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROLE = Path(__file__).resolve().parents[2] / 'ansible/roles/mssql_ssms'
DEFAULTS = yaml.safe_load((ROLE / 'defaults/main.yml').read_text(encoding='utf-8'))
TASKS = yaml.safe_load((ROLE / 'tasks/main.yml').read_text(encoding='utf-8'))


class TaskFailure(Exception):
    pass


class WindowsRole:
    def __init__(self, installed=False, rc=0, creates_exe=True, timeout=False,
                 download_valid=True):
        self.context = dict(DEFAULTS, inventory_hostname='srv02',
                            ansible_user='lab-admin', ansible_password='test-only')
        self.env = Environment(undefined=StrictUndefined)
        self.installed = installed
        self.rc = rc
        self.creates_exe = creates_exe
        self.timeout = timeout
        self.download_valid = download_valid
        self.calls = []

    def render(self, value):
        if isinstance(value, dict):
            return {k: self.render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.render(v) for v in value]
        if isinstance(value, str):
            while '{{' in value:
                rendered = self.env.from_string(value).render(self.context)
                if rendered == value:
                    break
                value = rendered
        return value

    def condition(self, value):
        if isinstance(value, list):
            return all(self.condition(v) for v in value)
        return bool(self.env.compile_expression(value)(**self.context))

    def run(self, tasks=TASKS):
        for task in tasks:
            if 'when' in task and not self.condition(task['when']):
                continue
            if 'block' in task:
                try:
                    self.run(task['block'])
                except TaskFailure as failure:
                    self.context['ansible_failed_result'] = {'msg': str(failure)}
                    self.run(task['rescue'])
                continue
            module = next(k for k in task if k.startswith('ansible.'))
            args = self.render(task[module])
            self.calls.append((module.rsplit('.', 1)[1], args, task))
            result = {}
            if module.endswith('.win_stat'):
                result = {'stat': {'exists': self.installed, 'isreg': self.installed}}
            elif module.endswith('.win_get_url'):
                if not self.download_valid:
                    raise TaskFailure('Downloaded file checksum does not match')
            elif module.endswith('.win_package'):
                if self.timeout:
                    raise TaskFailure('async task did not complete within the requested time')
                if self.rc not in args['expected_return_code']:
                    raise TaskFailure('Installer return code: ' + str(self.rc))
                self.installed = self.creates_exe
                result = {'rc': self.rc, 'reboot_required': self.rc == 3010}
            elif module.endswith('.assert'):
                if not self.condition(args['that']):
                    raise TaskFailure(args['fail_msg'])
            elif module.endswith('.fail'):
                raise TaskFailure(args['msg'])
            elif not module.endswith(('.win_file', '.win_reboot')):
                raise AssertionError('Unexpected module: ' + module)
            if 'register' in task:
                self.context[task['register']] = result
        return self

    def calls_for(self, module):
        return [args for name, args, _ in self.calls if name == module]


class SsmsRoleTests(unittest.TestCase):
    def test_installed_executable_skips_download_install_and_reboot(self):
        role = WindowsRole(installed=True).run()
        self.assertEqual([name for name, _, _ in role.calls], ['win_stat'])
        self.assertTrue(role.calls[0][1]['path'].lower().endswith(r'\common7\ide\ssms.exe'))

    def test_partial_directory_or_old_cache_cannot_mark_install_complete(self):
        role = WindowsRole(installed=False).run()
        download = role.calls_for('win_get_url')[0]
        install = role.calls_for('win_package')[0]
        self.assertEqual(download['dest'], install['path'])
        self.assertNotIn('ssms_installer.exe', install['path'].lower())
        self.assertIn('18.12.1', install['path'])
        self.assertIn('download.microsoft.com/download/', download['url'])
        self.assertNotIn('aka.ms', download['url'])
        self.assertEqual(download['checksum_algorithm'], 'sha256')
        self.assertEqual(download['checksum'].lower(),
                         'b98e97b83e1068ce322999be7585868815d3e8a7f2bd8d50a65b501ddc4f0103')
        self.assertEqual(install['creates_path'], role.calls_for('win_stat')[-1]['path'])
        self.assertIn('/quiet', install['arguments'])
        self.assertIn('/log "C:\\setup\\mssql\\', install['arguments'])
        self.assertFalse(role.calls_for('win_reboot'))

    def test_installer_uses_connection_admin_with_unrestricted_logon(self):
        role = WindowsRole().run()
        task = next(task for name, _, task in role.calls if name == 'win_package')
        self.assertTrue(task['become'])
        self.assertEqual(task['become_method'], 'runas')
        self.assertEqual(role.render(task['become_user']), role.context['ansible_user'])
        self.assertEqual(role.render(task['vars']['ansible_become_password']),
                         role.context['ansible_password'])

    def test_reboot_success_is_accepted_and_verified_after_reboot(self):
        role = WindowsRole(rc=3010).run()
        names = [name for name, _, _ in role.calls]
        self.assertLess(names.index('win_package'), names.index('win_reboot'))
        self.assertLess(names.index('win_reboot'), len(names) - 1)
        self.assertEqual(names[-2:], ['win_stat', 'assert'])

    def test_bad_download_never_executes_installer(self):
        role = WindowsRole(download_valid=False)
        with self.assertRaisesRegex(TaskFailure, 'checksum.*Inspect .*install.log'):
            role.run()
        self.assertFalse(role.calls_for('win_package'))

    def test_failure_code_is_not_swallowed_or_rebooted_away(self):
        role = WindowsRole(rc=1603)
        with self.assertRaisesRegex(TaskFailure, '1603.*Inspect .*install.log'):
            role.run()
        self.assertFalse(role.calls_for('win_reboot'))

    def test_stalled_installer_has_finite_polled_deadline_and_fails_lane(self):
        role = WindowsRole(timeout=True)
        with self.assertRaisesRegex(TaskFailure, 'async task.*lane is incomplete'):
            role.run()
        for name, _, task in role.calls:
            if name in {'win_get_url', 'win_package'}:
                self.assertGreater(int(role.render(task['async'])), 0)
                self.assertLessEqual(int(role.render(task['async'])), 3600)
                self.assertGreater(int(role.render(task['poll'])), 0)
                self.assertLessEqual(int(role.render(task['poll'])), 60)
        self.assertFalse(role.calls_for('win_reboot'))

    def test_success_code_without_executable_is_still_failure(self):
        role = WindowsRole(creates_exe=False)
        with self.assertRaisesRegex(TaskFailure, 'setup completed without.*Ssms.exe'):
            role.run()


if __name__ == '__main__':
    unittest.main()
