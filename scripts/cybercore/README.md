# CyberCore forest rename

`../cybercore-rebrand.py` runs on the GOAD controller. CyberCore sends a small
schema 2 identity plan containing the base lab, target domains, hostnames,
extensions, and expected machine identities. The helper reads the GOAD checkout
already installed on that controller. No GOAD source or compiler is uploaded by
the webserver.

Supported bases are GOAD-Mini, GOAD-Light, and GOAD. GOAD-Light retains its parent
and child domain; GOAD also retains the independent trust partner forest. WS01
and LX01 configurations are rewritten together with the base lab. ELK and Wazuh
have no lab identity configuration to rewrite.

The controller needs Python 3 and PyYAML (`python3-yaml` on Debian/Ubuntu), both
installed by the CyberCore controller bake. After publishing these files in the
GOAD fork, use the resulting commit as `GOAD_REF` when refreshing or rebuilding
the controller template. An older template without the helper cannot rename a
forest. The existing bake pin must not be changed to a revision that has not yet
been published.

To validate a plan without changing the checkout:

```sh
python3 scripts/cybercore-rebrand.py --goad-root /opt/goad --plan /tmp/plan.json --check
```

Omit `--check` to install the generated lab and selected extension configurations.
The helper returns one JSON report and a nonzero exit status on refusal or
failure. CyberCore checks its identity report and content hashes before running
the GOAD playbooks, then checks actual Windows domain membership and hostnames
before marking the lane ready.

CyberCore controllers set `cybercore_manage_hostname: true` after creating the
Windows bootstrap account. With this opt-in, the GOAD hostname role stops and
disables Cloudbase-Init on those managed guests before renaming them, then checks
both active and pending computer names. This prevents a later reboot from
restoring the Proxmox display name and breaking domain membership. The default
is off for other GOAD callers; reusable workstation templates are not modified.

The helper verifies every consumed source file against `manifests/*.json` before
writing. UTF-8 source hashes use LF line endings; binary files are checked and
copied byte for byte. Generated files are staged, shared playbook and extension
changes are snapshotted, and the generated lab is activated last. A failed
installation restores the prior files. Only compiler-owned generated lab
directories can be replaced; output symlinks are refused. Verified original
extension configurations are retained beside each extension so a retry can
compile from the same input. Unrecorded extension edits cause refusal.

When updating the GOAD fork, review changes to the consumed files and playbook
chain before refreshing their manifest hashes. A hash update alone does not
prove the transform understands new domain references. Update the structural
rules and tests for new encodings or extension principals, run the tests, and
validate a disposable lane. Keep CyberCore's small base identity metadata in
agreement with any roster or domain topology changes.

Run offline tests from the GOAD checkout:

```sh
python3 -m unittest discover -s scripts/cybercore -v
```

Tests use temporary checkout copies and never install into the working fork or
contact a live controller. They cover all three bases, two to four DNS labels,
credentials and binary preservation, extension joins, CLI reports, source drift,
retries, output ownership, symlink refusal, and injected rollback failures.

## Recover WS01 after a hostname or trust failure

`repair-ws01.yml` is an explicit manual recovery for a generated CyberCore lab
whose WS01 extension was already configured. It is never run by the normal
deployment chain. Correct the controller, domain controllers, and workstation
clocks first; the playbook refuses a workstation more than two minutes from the
controller's UTC time.

On that lane's controller, use its saved inventories and extra variables:

```sh
R=/var/lib/goad-run
ANSIBLE_CONFIG=/opt/goad/ansible/ansible.cfg ansible-playbook \
  -i "$R/inventory_proxmox" \
  -i "$R/inventory_ext_ws01" \
  -i "$R/inventory_ext_elk" \
  -i "$R/inventory_overrides" \
  /opt/goad/scripts/cybercore/repair-ws01.yml \
  --limit ws01 --extra-vars "@$R/extra_vars.yml" \
  --extra-vars '{"cybercore_repair_ws01":true}'
```

Omit the ELK inventory argument if that extension was not selected. Run the same
command with `--syntax-check` first. Keep the normal credential overrides last;
do not substitute the initial Administrator overlay. No passwords belong in the
command. The playbook reads `domain_name` from the saved extra variables, checks
that it names a generated lab before reading its files, and requires the main
configuration, rewritten WS01 configuration, and compiler identity report to
agree. It refuses a domain controller or a workstation joined to another forest.

The recovery stops and disables Cloudbase-Init on this GOAD workstation, leaves
the broken membership, reboots, and joins using the hostname and credentials
from the generated configuration. A second reboot verifies the active and
pending names and secure channel. Credential-bearing tasks are hidden from
Ansible output. The installed `ansible.windows.win_domain_membership` module
(1.11.0) performs the transitions; a checked local-unjoin fallback handles a
missing current-name AD account. No AD computer object is deleted. A successful
normal unjoin can disable the old account, and the desired existing account is
reused on join. Already healthy canonical membership skips the unjoin/join.
