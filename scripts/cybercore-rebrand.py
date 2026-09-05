#!/usr/bin/env python3
"""Compile a CyberCore identity plan using this controller's own GOAD source.

No source is downloaded or accepted from the webserver. Recipes pin consumed
source bytes (LF canonical for UTF-8; exact for binaries). Every artifact and
extension join is validated before any generated lab or extension is installed.
"""
import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def encoded_json(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def root_dn(domain):
    return ','.join('DC=' + label for label in domain.split('.'))


def normalized_dn(value):
    return ','.join(re.sub(r'\s*=\s*', '=', part.strip()).lower() for part in value.split(','))


def safe_child(root, relative):
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Source path escapes checkout')
    target = (root / relative).resolve()
    require(root in target.parents, 'Source symlink escapes checkout')
    return target


def recipe(root, name):
    require(re.fullmatch(r'[A-Za-z0-9_-]+', name) is not None, 'Invalid recipe name')
    try:
        return json.loads(safe_child(root, 'scripts/cybercore/manifests/' + name + '.json').read_text('utf-8'))
    except (OSError, ValueError):
        raise Refusal('Controller does not contain the required rename recipe') from None


def source_bytes(root, manifest, relative):
    meta = manifest['files'][relative]
    try:
        data = safe_child(root, manifest['derived_from'] + '/' + relative).read_bytes()
    except OSError:
        raise Refusal('Required source file is missing: ' + relative) from None
    if meta['encoding'] == 'utf8':
        try:
            data = data.decode('utf-8').replace('\r\n', '\n').encode('utf-8')
        except UnicodeError:
            raise Refusal('Invalid source encoding: ' + relative) from None
    if hashlib.sha256(data).hexdigest() != meta['sha256'] and manifest.get('extension'):
        # A prior successful compile installed this extension's renamed config.
        # Reuse the verified original only if the current file is our recorded
        # output; unrelated edits still fail rather than being silently hidden.
        key = manifest['extension']
        try:
            state = json.loads(safe_child(root, 'extensions/' + key + '/.cybercore-rebrand.json').read_text('utf-8'))
            require(hashlib.sha256(data).hexdigest() in state.get('accepted', [state.get('sha256')]), 'Extension source was edited after compilation')
            data = safe_child(root, 'extensions/' + key + '/.cybercore-original.json').read_bytes()
        except (OSError, ValueError, KeyError):
            raise Refusal('Extension source differs from pinned recipe') from None
    require(hashlib.sha256(data).hexdigest() == meta['sha256'], 'Source differs from pinned recipe: ' + relative)
    return data


class Transform:
    def __init__(self, mapping, stock_hosts, hosts):
        self.mapping = mapping
        self.stock_hosts = stock_hosts
        self.hosts = hosts
        self.pairs = {}
        for d in mapping:
            self.pairs[root_dn(d['from']).lower()] = (root_dn(d['to']), 'dn')
            self.pairs[d['from'].lower()] = (d['to'], 'dns')
            for prefix in {d['fromNetbios'], d['from'].split('.')[0]}:
                self.pairs[(prefix + '\\').lower()] = (d['netbios'] + '\\', 'principal')
        for key, host in stock_hosts.items():
            self.pairs[host['hostname'].lower()] = (hosts[key], 'host')
        self.tokens = re.compile('|'.join(re.escape(k) for k in sorted(self.pairs, key=len, reverse=True)), re.I)

    def text(self, text):
        def replace(hit):
            replacement, kind = self.pairs[hit.group().lower()]
            before = text[hit.start() - 1] if hit.start() else ''
            after = text[hit.end()] if hit.end() < len(text) else ''
            if re.match(r'[A-Za-z0-9_-]', before) or (kind != 'principal' and re.match(r'[A-Za-z0-9_-]', after)):
                return hit.group()
            return replacement
        return self.tokens.sub(replace, text)

    def domain(self, value):
        found = next((d for d in self.mapping if d['from'].lower() == value.lower()), None)
        require(found is not None, 'Domain reference is not covered by the identity plan')
        return found['to']

    def dn(self, value):
        parts = value.split(',')
        require(all(re.fullmatch(r'\s*[A-Za-z][A-Za-z0-9-]*\s*=\s*[^,]+', p) for p in parts), 'Unsupported DN syntax')
        index = len(parts)
        while index > 0 and re.match(r'\s*DC\s*=', parts[index - 1], re.I):
            index -= 1
        tail = normalized_dn(','.join(parts[index:]))
        found = next((d for d in self.mapping if normalized_dn(root_dn(d['from'])) == tail), None)
        require(found is not None, 'DN root is not covered by the identity plan')
        return ','.join(parts[:index] + root_dn(found['to']).split(','))

    def principal(self, value):
        if '\\' not in value:
            return value
        prefix, account = value.split('\\', 1)
        if prefix.lower() in {'nt authority', 'builtin', '.'}:
            return value
        found = next((d for d in self.mapping if prefix.lower() in {d['from'].lower(), d['fromNetbios'].lower(), d['from'].split('.')[0].lower()}), None)
        require(found is not None, 'Principal domain is not covered by the identity plan')
        return (found['to'] if prefix.lower() == found['from'].lower() else found['netbios']) + '\\' + account

    def references(self, value):
        if isinstance(value, list):
            return [self.references(v) for v in value]
        if not isinstance(value, dict):
            return self.text(value) if isinstance(value, str) else value
        result = {}
        for key, item in value.items():
            next_key = self.text(key) if '\\' in key or key.startswith('TERMSRV/') else key
            opaque = re.search(r'password|secret|^(city|description|display_name|src|dest|template_file|template_name|setup)$', key, re.I)
            result[next_key] = item if opaque else self.references(item)
        return result

    def acl_principal(self, value):
        if re.search(r'(^|,)\s*(CN|OU|DC)=', value, re.I):
            return self.dn(value)
        if value.endswith('$'):
            key = next((k for k, h in self.stock_hosts.items() if h['hostname'].lower() == value[:-1].lower()), None)
            if key:
                return self.hosts[key] + '$'
        return self.principal(value)

    def paths(self, value):
        out = copy.deepcopy(value)
        for entry in out.values():
            if not isinstance(entry, dict) or 'path' not in entry:
                continue
            entry['path'] = self.dn(entry['path'])
            if isinstance(entry.get('spns'), list):
                entry['spns'] = [self.text(v) for v in entry['spns']]
            if isinstance(entry.get('members'), list):
                entry['members'] = [self.principal(v) for v in entry['members']]
        return out

    def host(self, key, host):
        out = copy.deepcopy(host)
        require(key in self.stock_hosts and host['hostname'].lower() == self.stock_hosts[key]['hostname'].lower(), 'Host differs from pinned identity metadata')
        out['hostname'] = self.hosts[key]
        out['domain'] = self.domain(host['domain'])
        if 'path' in host:
            out['path'] = self.dn(host['path'])
        if 'local_groups' in host:
            out['local_groups'] = {g: [self.principal(v) for v in members] for g, members in host['local_groups'].items()}
        for field in ['vulns_vars', 'mssql', 'Remote Desktop Users']:
            if field in host:
                out[field] = self.references(host[field])
        return out

    def config(self, config, extension=False):
        top = 'lab_extension' if extension else 'lab'
        require(list(config) == [top], 'Unexpected config top-level keys')
        source = config[top]
        require(not extension or 'domains' not in source, 'Extension declares its own domains')
        out = copy.deepcopy(source)
        require(set(source['hosts']) == set(self.stock_hosts), 'Host roster differs from recipe')
        out['hosts'] = {key: self.host(key, host) for key, host in source['hosts'].items()}
        if not extension:
            require(set(source['domains']) == {d['from'] for d in self.mapping}, 'Domain roster differs from recipe')
            out['domains'] = {}
            for old_name, domain in source['domains'].items():
                d = next(d for d in self.mapping if d['from'] == old_name)
                require(domain['netbios_name'].lower() == d['fromNetbios'].lower(), 'NetBIOS identity differs from recipe')
                renamed = copy.deepcopy(domain)
                renamed['netbios_name'] = d['netbios']
                if domain.get('trust'):
                    renamed['trust'] = self.domain(domain['trust'])
                if 'laps_path' in domain:
                    renamed['laps_path'] = self.dn(domain['laps_path'])
                for field in ['organisation_units', 'users']:
                    if field in domain:
                        renamed[field] = self.paths(domain[field])
                if 'groups' in domain:
                    renamed['groups'] = {scope: self.paths(groups) for scope, groups in domain['groups'].items()}
                if 'acls' in domain:
                    renamed['acls'] = {name: {key: self.acl_principal(value) if key in {'for', 'to'} else value for key, value in acl.items()} for name, acl in domain['acls'].items()}
                for field in ['multi_domain_groups_member', 'gmsa', 'ca_server']:
                    if field in domain:
                        renamed[field] = self.references(domain[field])
                out['domains'][d['to']] = renamed
            for domain in out['domains'].values():
                dc = out['hosts'].get(domain['dc'])
                require(dc and dc.get('local_admin_password') == domain['domain_password'], 'DC promotion credential invariant failed')
        result = {top: out}
        self.residue(result)
        return result

    def residue(self, value):
        destinations = sorted([v for d in self.mapping for v in [d['to'], root_dn(d['to']), d['netbios']]] + list(self.hosts.values()), key=len, reverse=True)
        sources = [v for d in self.mapping for v in [d['from'], root_dn(d['from'])]] + [h['hostname'] for h in self.stock_hosts.values()]
        def visit(item):
            if isinstance(item, str):
                masked = item.lower()
                for destination in destinations:
                    masked = masked.replace(destination.lower(), '\x00')
                require(not any(source.lower() in masked for source in sources), 'An unrewritten identity remains in configuration')
            elif isinstance(item, list):
                for child in item:
                    visit(child)
            elif isinstance(item, dict):
                for key, child in item.items():
                    if not re.search(r'password|secret|^(city|description|display_name)$', key, re.I):
                        visit(child)
        visit(value)


def compile_plan(root, plan):
    require(plan.get('schema') == 2 and plan.get('base_lab') in {'GOAD-Mini', 'GOAD-Light', 'GOAD'}, 'Unsupported rename schema or base lab')
    require(re.fullmatch(r'CC-[A-Za-z0-9._-]{1,60}', plan.get('lab_name', '')) is not None, 'Invalid generated lab name')
    manifest = recipe(root, plan['base_lab'])
    import yaml
    try:
        chain_map = yaml.safe_load(safe_child(root, 'playbooks.yml').read_text('utf-8'))
    except (OSError, ValueError, yaml.YAMLError):
        raise Refusal('Controller playbook map is unavailable or invalid') from None
    require(isinstance(chain_map, dict) and chain_map.get(manifest['chain_source']['key']) == manifest['chain'], 'Base playbook chain differs from recipe')
    mapping, hosts = plan['domain_mapping'], plan['hostnames']
    stock = manifest['stock']
    definitions = stock.get('domains', {stock['forest_root']: {'netbios': stock['netbios'], 'kind': 'root'}})
    require(len(mapping) == len(definitions) and {d['from'] for d in mapping} == set(definitions), 'Domain plan does not match recipe')
    for d in mapping:
        require(d['fromNetbios'] == definitions[d['from']]['netbios'] and d['kind'] == definitions[d['from']]['kind'], 'Domain plan changes source identity')
        require(len(d['to']) <= 253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in d['to'].split('.')) and len(d['to'].split('.')) >= 2, 'Invalid destination domain')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,14}', d['netbios']) is not None, 'Invalid destination NetBIOS name')
    require(len({d['to'].lower() for d in mapping}) == len(mapping) and len({d['netbios'].lower() for d in mapping}) == len(mapping), 'Domain identity collision')
    root_mapping = next(d for d in mapping if d['kind'] == 'root')
    for d in mapping:
        if d['kind'] == 'child':
            require(d['to'].endswith('.' + root_mapping['to']) and len(d['to'].split('.')) == len(root_mapping['to'].split('.')) + 1, 'Child domain is outside its parent')
        if d['kind'] == 'partner':
            first, suffix = root_mapping['to'].split('.', 1)
            require(d['to'] == first + '-partner.' + suffix, 'Trust partner is not an independent sibling forest')
    require(set(hosts) == set(stock['hosts']), 'Host plan does not match recipe')
    require(all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?', v) for v in hosts.values()), 'Invalid destination hostname')
    require(len({h.lower() for h in hosts.values()}) == len(hosts), 'Hostname collision')
    selected = plan.get('selected_extensions', [])
    require(isinstance(selected, list) and all(k in {'ws01', 'lx01', 'elk', 'wazuh'} for k in selected) and len(set(selected)) == len(selected), 'Unsupported extension selection')
    transform = Transform(mapping, stock['hosts'], hosts)
    # Verify every consumed input before transforming or installing any output.
    inputs = {relative: source_bytes(root, manifest, relative) for relative in manifest['files']}
    config = transform.config(json.loads(inputs['data/config.json']))
    files = {}
    for relative, data in inputs.items():
        if relative == 'data/config.json':
            files[relative] = encoded_json(config)
        elif relative == 'data/inventory':
            text = data.decode('utf-8')
            require(re.search(r'^\s*domain_name=' + re.escape(plan['base_lab']) + r'\s*$', text, re.M) is not None, 'Inventory lab name differs from recipe')
            files[relative] = re.sub(r'(?m)^(\s*domain_name=)' + re.escape(plan['base_lab']) + r'(?=\s*$)', lambda m: m[1] + plan['lab_name'], text).encode('utf-8')
        elif manifest['files'][relative]['encoding'] == 'utf8':
            files[relative] = '\n'.join(line if re.match(r'^\s*\$(password|secret|keyData)\s*=', line, re.I) else transform.text(line) for line in data.decode('utf-8').split('\n')).encode('utf-8')
        else:
            files[relative] = data
    extension_files = {}
    main = config['lab']
    identities = [{'name': stock['hosts'][key]['roster_name'], 'hostname': host['hostname'], 'domain': host['domain']} for key, host in main['hosts'].items()]
    for key in selected:
        if key not in {'ws01', 'lx01'}:
            continue
        ext = recipe(root, key)
        extension = json.loads(source_bytes(root, ext, 'data/config.json'))
        root_domain = main['domains'][root_mapping['to']]
        known = {'administrator'} | {u.lower() for u in root_domain.get('users', {})}
        for groups in root_domain.get('groups', {}).values():
            known.update(g.lower() for g in groups)
        substitutions = manifest.get('extension_principals', {}).get(key, {})
        for host in extension['lab_extension']['hosts'].values():
            for group, members in host.get('local_groups', {}).items():
                for index, member in enumerate(members):
                    prefix, separator, user = member.rpartition('\\')
                    mapped = substitutions.get(user, user)
                    require(mapped.lower() in known, 'Extension principal is absent from target root domain')
                    members[index] = (prefix + separator if separator else '') + mapped
        ext_hosts = {h: v['roster_name'] for h, v in ext['stock']['hosts'].items()}
        require(not {v.lower() for v in ext_hosts.values()} & {i['hostname'].lower() for i in identities}, 'Extension hostname collision')
        ext_mapping = [{'from': ext['stock']['forest_root'], 'fromNetbios': ext['stock']['netbios'], 'to': root_mapping['to'], 'netbios': root_mapping['netbios'], 'kind': 'root'}]
        emitted = Transform(ext_mapping, ext['stock']['hosts'], ext_hosts).config(extension, extension=True)
        for h, host in emitted['lab_extension']['hosts'].items():
            domain = main['domains'].get(host['domain'])
            require(domain and domain.get('domain_password') and main['hosts'].get(domain['dc'], {}).get('hostname'), 'Extension domain/DC join is invalid')
            identities.append({'name': ext_hosts[h], 'hostname': host['hostname'], 'domain': host['domain']})
        extension_files[key] = encoded_json(emitted)
    expected = sorted(plan.get('expected_identities', []), key=lambda h: h['name'].lower())
    require(expected == sorted(identities, key=lambda h: h['name'].lower()), 'Compiled identities disagree with authored roster plan')
    files['playbooks.yml'] = encoded_json(manifest['chain'])
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        digest.update(name.encode('utf-8') + b'\0' + data + b'\0')
    return files, extension_files, {'lab': plan['lab_name'], 'treeSha256': digest.hexdigest(), 'chain': manifest['chain'], 'chainMode': 'per-lab', 'identities': identities, 'extensionConfigs': {}}


@contextlib.contextmanager
def controller_lock(root):
    # The production controller is Linux. The Windows branch supports offline
    # tests against a temporary checkout without changing the live fork.
    lock_path = root / '.cybercore-rebrand.lock'
    with lock_path.open('a+b') as handle:
        if os.name != 'nt':
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def atomic_file(destination, data):
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def output_child(root, relative):
    lexical = root / relative
    require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'Output path escapes checkout')
    require(lexical.resolve() == lexical, 'Output path follows a symlink or junction')
    return lexical


def install(root, files, extensions, report):
    import yaml
    lab = report['lab']
    ad_root = output_child(root, 'ad')
    require(ad_root.is_dir(), 'GOAD ad directory is missing')
    target = output_child(root, 'ad/' + lab)
    staging = Path(tempfile.mkdtemp(prefix='.cybercore-stage-', dir=ad_root))
    os.chmod(staging, 0o755)
    backup = None
    activated = False
    changed_files = []
    try:
        for relative, data in files.items():
            dest = safe_child(staging, relative)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            os.chmod(dest, 0o644)
        report['failedStep'] = 'chain-validation'
        with controller_lock(root):
            chain_path = output_child(root, 'playbooks.yml')
            chain_map = yaml.safe_load(chain_path.read_text('utf-8'))
            require(isinstance(chain_map, dict), 'Shared playbook map is invalid')
            if target.exists():
                try:
                    prior = json.loads(output_child(root, 'ad/' + lab + '/.cybercore/result.json').read_text('utf-8'))
                except (OSError, ValueError):
                    raise Refusal('Existing generated lab is not owned by this compiler') from None
                require(prior.get('lab') == lab, 'Existing generated lab has conflicting ownership')
            chain_map[lab] = report['chain']
            changes = [(chain_path, yaml.safe_dump(chain_map, sort_keys=False).encode('utf-8'), 'chain-install')]
            report['chainMode'] = 'per-lab+shared'
            for key, data in extensions.items():
                dest = output_child(root, 'extensions/' + key + '/data/config.json')
                original = source_bytes(root, recipe(root, key), 'data/config.json')
                previous_hash = hashlib.sha256(dest.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                changes.append((output_child(root, 'extensions/' + key + '/.cybercore-original.json'), original, 'extension-' + key))
                changes.append((output_child(root, 'extensions/' + key + '/.cybercore-rebrand.json'), encoded_json({'accepted': [previous_hash, hashlib.sha256(data).hexdigest()]}), 'extension-' + key))
                skipped = dest.exists() and dest.read_bytes() == data
                changes.append((dest, data, 'extension-' + key))
                report['extensionConfigs'][key] = {'sha256': hashlib.sha256(data).hexdigest(), 'skipped': skipped, 'dest': str(dest)}
            report.pop('failedStep', None)
            atomic_file(staging / '.cybercore/result.json', encoded_json(report))
            # Snapshot every external mutation, install all files, and activate
            # the generated lab last. Any failure restores the prior lane state.
            try:
                for dest, data, step in changes:
                    if dest.exists() and dest.read_bytes() == data:
                        continue
                    report['failedStep'] = step
                    changed_files.append((dest, dest.read_bytes() if dest.exists() else None))
                    atomic_file(dest, data)
                report['failedStep'] = 'lab-install'
                if target.exists():
                    backup = Path(tempfile.mkdtemp(prefix='.cybercore-backup-', dir=ad_root))
                    backup.rmdir()
                    os.replace(target, backup)
                os.replace(staging, target)
                activated = True
                report.pop('failedStep', None)
            except Exception:
                rollback_errors = []
                if backup and backup.exists() and not activated:
                    try:
                        os.replace(backup, target)
                        backup = None
                    except OSError:
                        rollback_errors.append('lab')
                for dest, prior_bytes in reversed(changed_files):
                    try:
                        if prior_bytes is None:
                            dest.unlink(missing_ok=True)
                        else:
                            atomic_file(dest, prior_bytes)
                    except OSError:
                        rollback_errors.append('file')
                if rollback_errors:
                    report['rollbackFailed'] = True
                raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup and backup.exists() and activated:
            shutil.rmtree(backup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goad-root', required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--check', action='store_true', help='Validate and compile without installing')
    args = parser.parse_args()
    report = {'failedStep': 'compile'}
    try:
        root = Path(args.goad_root).resolve(strict=True)
        plan = json.loads(Path(args.plan).read_text('utf-8'))
        files, extensions, report = compile_plan(root, plan)
        if not args.check:
            install(root, files, extensions, report)
        print(json.dumps({'ok': True, **report}))
        return 0
    except Exception as exc:
        # Never serialize source objects, credentials or external tracebacks.
        message = str(exc) if isinstance(exc, Refusal) else 'Controller compilation failed (' + type(exc).__name__ + ')'
        print(json.dumps({'ok': False, 'error': message, 'delivery': report}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
