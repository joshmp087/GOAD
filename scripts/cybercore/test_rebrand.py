"""Offline controller compiler tests; all writes use temporary checkout copies.

Run from the GOAD checkout: python -m unittest discover -s scripts/cybercore -v
Requires PyYAML, which the GOAD controller image already installs.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cybercore_rebrand', SOURCE / 'scripts/cybercore-rebrand.py')
compiler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compiler)


def plan_for(root, lab='GOAD-Mini', domain='cy400test.org', extensions=('ws01', 'lx01', 'elk')):
    manifest = compiler.recipe(root, lab)
    stock = manifest['stock']
    definitions = stock.get('domains', {stock['forest_root']: {'netbios': stock['netbios'], 'kind': 'root'}})
    first, suffix = domain.split('.', 1)
    mapping = []
    for old, definition in definitions.items():
        kind = definition['kind']
        target = domain if kind == 'root' else ('corp.' + domain if kind == 'child' else first + '-partner.' + suffix)
        mapping.append({'from': old, 'fromNetbios': definition['netbios'], 'kind': kind,
                        'to': target, 'netbios': {'root': 'CY400TEST', 'child': 'CORP', 'partner': 'PARTNER'}[kind]})
    by_domain = {d['from']: d['to'] for d in mapping}
    identities = [{'name': h['roster_name'], 'hostname': h['roster_name'],
                   'domain': by_domain[h.get('domain', stock['forest_root'])]} for h in stock['hosts'].values()]
    for key in extensions:
        if key in {'ws01', 'lx01'}:
            identities.extend({'name': h['roster_name'], 'hostname': h['roster_name'], 'domain': domain}
                              for h in compiler.recipe(root, key)['stock']['hosts'].values())
    return {'schema': 2, 'base_lab': lab, 'lab_name': 'CC-test-' + lab,
            'domain_mapping': mapping, 'hostnames': {k: h['roster_name'] for k, h in stock['hosts'].items()},
            'selected_extensions': list(extensions), 'expected_identities': identities}


def file_snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*')
            if p.is_file() and p.name != '.cybercore-rebrand.lock'}


class ControllerRebrandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cybercore-controller-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        manifests = SOURCE / 'scripts/cybercore/manifests'
        shutil.copytree(manifests, self.root / 'scripts/cybercore/manifests')
        shutil.copyfile(SOURCE / 'playbooks.yml', self.root / 'playbooks.yml')
        for manifest_path in manifests.glob('*.json'):
            manifest = json.loads(manifest_path.read_text('utf-8'))
            for relative in manifest['files']:
                source = SOURCE / manifest['derived_from'] / relative
                target = self.root / manifest['derived_from'] / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

    def compile(self, plan=None):
        return compiler.compile_plan(self.root, plan or plan_for(self.root))

    def test_all_labs_and_domain_arities_preserve_credentials_binary_and_extension_joins(self):
        initial = file_snapshot(self.root)
        for lab in ['GOAD-Mini', 'GOAD-Light', 'GOAD']:
            for domain in ['cy400test.org', 'lab.cy400test.org', 'lab.class.cy400test.org']:
                with self.subTest(lab=lab, domain=domain):
                    plan = plan_for(self.root, lab, domain)
                    files, extensions, report = self.compile(plan)
                    main = json.loads(files['data/config.json'])['lab']
                    manifest = compiler.recipe(self.root, lab)
                    source = json.loads(compiler.source_bytes(self.root, manifest, 'data/config.json'))['lab']
                    for mapping in plan['domain_mapping']:
                        old, renamed = source['domains'][mapping['from']], main['domains'][mapping['to']]
                        self.assertEqual(old['domain_password'], renamed['domain_password'])
                        self.assertEqual(main['hosts'][renamed['dc']]['local_admin_password'], renamed['domain_password'])
                        self.assertEqual(set(old.get('users', {})), set(renamed.get('users', {})))
                        for user, attributes in old.get('users', {}).items():
                            self.assertEqual(attributes.get('password'), renamed['users'][user].get('password'))
                    for key, host in source['hosts'].items():
                        self.assertEqual(host['local_admin_password'], main['hosts'][key]['local_admin_password'])
                    for relative, metadata in manifest['files'].items():
                        if metadata['encoding'] != 'utf8':
                            self.assertEqual(compiler.source_bytes(self.root, manifest, relative), files[relative])
                    self.assertEqual(json.loads(files['playbooks.yml']), manifest['chain'])
                    self.assertIn(('domain_name=' + plan['lab_name']).encode(), files['data/inventory'])
                    for key, content in extensions.items():
                        ext = json.loads(content)['lab_extension']
                        for host in ext['hosts'].values():
                            self.assertEqual(domain, host['domain'])
                            joined_domain = main['domains'][host['domain']]
                            self.assertIn(joined_domain['dc'], main['hosts'])
                            self.assertTrue(main['hosts'][joined_domain['dc']]['hostname'])
                        stock_ext = json.loads(compiler.source_bytes(self.root, compiler.recipe(self.root, key), 'data/config.json'))
                        self.assertTrue(all(h['domain'] not in main['domains'] for h in stock_ext['lab_extension']['hosts'].values()))
                    self.assertEqual(sorted(plan['expected_identities'], key=lambda h: h['name']),
                                     sorted(report['identities'], key=lambda h: h['name']))
        self.assertEqual(initial, file_snapshot(self.root), 'Compile must never mutate controller sources')

    def test_distinguished_names_rebase_only_the_trailing_domain(self):
        stock = {'dc01': {'hostname': 'kingslanding'}}
        for domain in ['cy400test.org', 'lab.cy400test.org', 'lab.class.cy400test.org']:
            transform = compiler.Transform([{'from': 'sevenkingdoms.local', 'to': domain,
                                             'fromNetbios': 'SEVENKINGDOMS', 'netbios': 'CY400TEST'}], stock, {'dc01': 'DC01'})
            prefix = 'CN=Untouched Name, OU=Preserve Spaces'
            self.assertEqual(prefix + ',' + compiler.root_dn(domain),
                             transform.dn(prefix + ',DC=sevenkingdoms,DC=local'))

    def test_cli_reports_installed_tree_and_each_rewritten_extension(self):
        plan = plan_for(self.root, 'GOAD', 'lab.cy400test.org')
        plan_path = self.root / 'plan.json'
        plan_path.write_text(json.dumps(plan), encoding='utf-8')
        result = subprocess.run([sys.executable, str(SOURCE / 'scripts/cybercore-rebrand.py'),
                                 '--goad-root', str(self.root), '--plan', str(plan_path)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['ok'])
        self.assertEqual(plan['lab_name'], report['lab'])
        self.assertRegex(report['treeSha256'], r'^[a-f0-9]{64}$')
        self.assertEqual('per-lab+shared', report['chainMode'])
        self.assertEqual({'ws01', 'lx01'}, set(report['extensionConfigs']))
        for extension in report['extensionConfigs'].values():
            self.assertRegex(extension['sha256'], r'^[a-f0-9]{64}$')
        self.assertEqual(sorted(plan['expected_identities'], key=lambda h: h['name']),
                         sorted(report['identities'], key=lambda h: h['name']))
        installed = json.loads((self.root / 'ad' / plan['lab_name'] / '.cybercore/result.json').read_text('utf-8'))
        self.assertEqual({k: v for k, v in report.items() if k != 'ok'}, installed)

    def test_cli_refusal_leaves_sources_unchanged_and_returns_json(self):
        plan = plan_for(self.root)
        plan['domain_mapping'][0]['to'] = 'invalid..org'
        plan_path = self.root / 'plan.json'
        plan_path.write_text(json.dumps(plan), encoding='utf-8')
        before = file_snapshot(self.root)
        result = subprocess.run([sys.executable, str(SOURCE / 'scripts/cybercore-rebrand.py'),
                                 '--goad-root', str(self.root), '--plan', str(plan_path)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(1, result.returncode)
        report = json.loads(result.stdout)
        self.assertFalse(report['ok'])
        self.assertIn('Invalid destination domain', report['error'])
        self.assertEqual(before, file_snapshot(self.root))

    def test_source_and_chain_drift_refuse_before_any_write(self):
        for relative in ['ad/GOAD-Mini/data/config.json', 'playbooks.yml']:
            with self.subTest(relative=relative):
                target = self.root / relative
                original = target.read_bytes()
                target.write_bytes(original.replace(b'build.yml', b'changed.yml') if relative == 'playbooks.yml' else original + b' ')
                before = file_snapshot(self.root)
                with self.assertRaises(compiler.Refusal):
                    self.compile()
                self.assertEqual(before, file_snapshot(self.root))
                target.write_bytes(original)

    def test_install_retry_and_second_identity_reuse_verified_original_extensions(self):
        plan = plan_for(self.root)
        files, extensions, report = self.compile(plan)
        compiler.install(self.root, files, extensions, report)
        self.assertEqual('per-lab+shared', report['chainMode'])
        chain_map = yaml.safe_load((self.root / 'playbooks.yml').read_text('utf-8'))
        self.assertEqual(report['chain'], chain_map[plan['lab_name']])
        retry_files, retry_extensions, retry_report = self.compile(plan)
        self.assertEqual(files, retry_files)
        self.assertEqual(extensions, retry_extensions)
        compiler.install(self.root, retry_files, retry_extensions, retry_report)
        self.assertTrue(all(ext['skipped'] for ext in retry_report['extensionConfigs'].values()))
        second = plan_for(self.root, domain='another.org')
        second['lab_name'] = 'CC-another'
        files, extensions, report = self.compile(second)
        compiler.install(self.root, files, extensions, report)
        self.assertTrue(all(host['domain'] == 'another.org' for host in report['identities']))

    def test_unrecorded_extension_edit_refuses(self):
        compiler.install(self.root, *self.compile())
        target = self.root / 'extensions/ws01/data/config.json'
        target.write_bytes(target.read_bytes() + b' ')
        before = file_snapshot(self.root)
        with self.assertRaises(compiler.Refusal):
            self.compile()
        self.assertEqual(before, file_snapshot(self.root))

    def test_write_failures_restore_the_prior_lab_chain_and_extensions(self):
        compiler.install(self.root, *self.compile())
        for fail_suffix in ['playbooks.yml', 'extensions/ws01/data/config.json', 'lab-activation']:
            with self.subTest(failure=fail_suffix):
                before = file_snapshot(self.root)
                plan = plan_for(self.root, domain='another.org')
                if fail_suffix == 'playbooks.yml':
                    plan['lab_name'] = 'CC-new-chain-entry'
                files, extensions, report = self.compile(plan)
                failed = False
                real_atomic, real_replace = compiler.atomic_file, compiler.os.replace

                def fail_file(destination, data):
                    nonlocal failed
                    if not failed and str(destination.relative_to(self.root)).replace('\\', '/') == fail_suffix:
                        failed = True
                        raise OSError('injected write failure')
                    return real_atomic(destination, data)

                def fail_replace(source, destination):
                    nonlocal failed
                    if not failed and fail_suffix == 'lab-activation' and Path(source).name.startswith('.cybercore-stage-'):
                        failed = True
                        raise OSError('injected activation failure')
                    return real_replace(source, destination)

                with mock.patch.object(compiler, 'atomic_file', side_effect=fail_file), mock.patch.object(compiler.os, 'replace', side_effect=fail_replace):
                    with self.assertRaises(OSError):
                        compiler.install(self.root, files, extensions, report)
                self.assertTrue(failed, 'Failure injection must exercise the requested operation')
                self.assertEqual(before, file_snapshot(self.root))
                self.assertNotIn('rollbackFailed', report)
                self.assertFalse(list((self.root / 'ad').glob('.cybercore-*')))

    def test_atomic_file_cleans_partial_write_when_fsync_fails(self):
        target = self.root / 'existing-file.json'
        target.write_bytes(b'prior bytes')
        before = file_snapshot(self.root)
        with mock.patch.object(compiler.os, 'fsync', side_effect=OSError('injected fsync failure')):
            with self.assertRaises(OSError):
                compiler.atomic_file(target, b'replacement bytes')
        self.assertEqual(before, file_snapshot(self.root))

    def test_existing_unowned_directory_is_never_replaced(self):
        plan = plan_for(self.root)
        target = self.root / 'ad' / plan['lab_name']
        target.mkdir()
        (target / 'keep.txt').write_text('unrelated content', encoding='utf-8')
        before = file_snapshot(self.root)
        with self.assertRaisesRegex(compiler.Refusal, 'not owned'):
            compiler.install(self.root, *self.compile(plan))
        self.assertEqual(before, file_snapshot(self.root))

    def test_output_symlink_to_stock_lab_is_refused(self):
        plan = plan_for(self.root)
        target = self.root / 'ad' / plan['lab_name']
        try:
            target.symlink_to(self.root / 'ad/GOAD-Mini', target_is_directory=True)
        except OSError as error:
            self.skipTest('Creating symlinks is unavailable: ' + str(error))
        before = file_snapshot(self.root / 'ad/GOAD-Mini')
        with self.assertRaisesRegex(compiler.Refusal, 'symlink'):
            compiler.install(self.root, *self.compile(plan))
        self.assertEqual(before, file_snapshot(self.root / 'ad/GOAD-Mini'))


if __name__ == '__main__':
    unittest.main()
