"""Offline artifact and retry contracts for the ELK Windows log collector role."""
from pathlib import Path
import unittest
import zipfile

from jinja2 import Environment, StrictUndefined
import yaml


ROLE = Path(__file__).resolve().parents[2] / 'extensions/elk/ansible/roles/logs_windows'
DEFAULTS = yaml.safe_load((ROLE / 'defaults/main.yml').read_text(encoding='utf-8'))
JINJA = Environment(undefined=StrictUndefined)


def load_tasks(filename='main.yml'):
    tasks = yaml.safe_load((ROLE / 'tasks' / filename).read_text(encoding='utf-8'))
    result = []
    for task in tasks:
        if 'import_tasks' in task:
            result.extend(load_tasks(task['import_tasks']))
        else:
            result.append(task)
    return result


TASKS = load_tasks()


def context(**overrides):
    return dict(DEFAULTS, inventory_hostname='srv02',
                winlogbeat_installed={'exists': False},
                winlogbeat_folder={'stat': {'exists': False}}, **overrides)


class ElkWindowsRoleTests(unittest.TestCase):
    def test_default_fresh_install_has_every_controller_copy_source(self):
        """Catch dangling controller files on the actual default deployment path."""
        variables = context()
        generated = set()
        for task in TASKS:
            # Only copy/template tasks read controller files. Other conditions
            # depend on Windows results and do not affect artifact resolution.
            operation = next((key for key in task if key.rsplit('.', 1)[-1]
                              in {'win_copy', 'template'}), None)
            if not operation:
                continue
            if 'when' in task and not JINJA.compile_expression(task['when'])(**variables):
                continue
            args = task[operation]
            source = JINJA.from_string(args['src']).render(variables)
            if operation.rsplit('.', 1)[-1] == 'template':
                self.assertTrue((ROLE / 'templates' / source).is_file(), source)
                generated.add(JINJA.from_string(args['dest']).render(variables))
            elif source not in generated:
                self.assertTrue(any(path.is_file() for path in
                                    (ROLE / 'files' / source, ROLE / source)),
                                'Missing controller copy source: ' + source)

    def test_only_rendered_config_reaches_the_real_winlogbeat_installation(self):
        variables = context()
        template = next(task['ansible.builtin.template'] for task in TASKS
                        if 'ansible.builtin.template' in task)
        source = JINJA.from_string(template['dest']).render(variables)
        destinations = []
        for task in TASKS:
            args = task.get('ansible.windows.win_copy', task.get('win_copy', {}))
            if args and JINJA.from_string(args['src']).render(variables) == source:
                destinations.append(JINJA.from_string(args['dest']).render(variables))
            self.assertNotIn('chocolatey', str(args).lower())
        self.assertEqual(destinations, [
            r'C:\Program Files\Elastic\winlogbeat\winlogbeat-7.17.6-windows-x86_64\winlogbeat.yml'])
        source_text = (ROLE / 'templates' / template['src']).read_text(encoding='utf-8')
        for elk_ip in ('10.44.0.24', '10.99.24.24'):
            output = yaml.safe_load(JINJA.from_string(source_text).render(
                hostvars={'elk': {'ansible_host': elk_ip}}))
            self.assertEqual(output['output.elasticsearch']['hosts'], [elk_ip + ':9200'])
            self.assertEqual(output['setup.kibana']['host'], elk_ip)

    def test_service_is_recovered_after_interrupted_extraction(self):
        installer = next(task for task in TASKS if 'install-service-winlogbeat.ps1'
                         in task.get('win_shell', '') and
                         'uninstall-service-winlogbeat.ps1' not in task.get('win_shell', ''))
        for service_exists, folder_exists, should_install in (
                (False, False, True), (False, True, True),
                (True, False, True), (True, True, False)):
            with self.subTest(service_exists=service_exists, folder_exists=folder_exists):
                variables = context()
                variables['winlogbeat_installed']['exists'] = service_exists
                variables['winlogbeat_folder']['stat']['exists'] = folder_exists
                self.assertEqual(bool(JINJA.compile_expression(installer['when'])(**variables)),
                                 should_install)

    def test_bundled_sysmon_archive_contains_the_selected_executable(self):
        archive = ROLE / 'files' / (DEFAULTS['sysmon_download_file'] + DEFAULTS['file_ext'])
        with zipfile.ZipFile(archive) as payload:
            self.assertIsNone(payload.testzip())
            self.assertIn('sysmon64.exe', {name.lower() for name in payload.namelist()})


if __name__ == '__main__':
    unittest.main()
