#
# tests for the audit rule text of harden-workstation.sh (stdlib + bash, no root): the
# rules are written in the text scap-security-guide's checks match (review 2026-11-17,
# C-2), path rules once per arch, and the two places that stay in another form on
# purpose (docs/deviations.md, scanner false positives) stay that way.
#
#   python3 -I -B -m unittest discover -s tests -v
#
# Patterns: the augenrules branch of the OVAL checks in scap-security-guide 0.1.82
# (ssg-fedora-ds.xml, profile cis_workstation_l2), one line each, as the scanner uses them
# (multi-line mode: ^ and $ per line, every *.rules file in /etc/audit/rules.d).
#
import os
import re
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(HERE, 'harden-workstation.sh')

KEY = r'[\s]+(?:-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'


def path_rule(arch, path):
    """audit_rules_execution_* / audit_rules_privileged_commands_* (one per arch)"""
    p = path.replace('/', r'\/')
    return (r'^[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=' + arch + r'[\s]+-F[\s]+path=' + p
            + r'(?:[\s]+-F[\s]+perm=x)[\s]+-F[\s]+auid>=1000[\s]+-F[\s]+auid!=(?:4294967295|unset|-1)'
            + KEY)


def watch(path):
    """audit_rules_mac_modification_*, _sysadmin_actions, _usergroup_modification_*, ..."""
    return (r'^\-w[\s]+' + path.replace('/', r'\/')
            + r'[\s]+\-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b.*$')


def suid_auid(arch):
    """audit_rules_suid_auid_privilege_function"""
    return (r'^[\s]*-a[\s]+always,exit[\s]+-F[\s]+arch=' + arch
            + r'[\s]+-S[\s]+execve[\s]+-C[\s]+euid!=uid[\s]+-F[\s]+auid!=unset' + KEY)


def privileged(arch):
    """audit_rules_privileged_commands: group 1 = the path (must be a setuid / setgid file)"""
    return (r'^[\s]*-a always,exit -F arch=' + arch + r' (?:-F path=([\S]+))+(?: -F perm=x)?'
            r' -F auid>=1000 -F auid!=(?:4294967295|unset)' + KEY)


def hostname_ssg(arch, call):
    """audit_rules_networkconfig_modification_sethostname / _setdomainname (login users only)"""
    return (r'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=' + arch + r'[\s]+)(?:.*(-S[\s]+' + call
            + r'[\s]+|([\s]+|[,])' + call + r'([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)'
            r'(?:.*-F\s+auid!=(?:4294967295|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')


# rule id -> patterns that must each match exactly one line
MATCH_ONCE = {
    'audit_rules_execution_chcon': [path_rule(a, '/usr/bin/chcon') for a in ('b32', 'b64')],
    'audit_rules_execution_setfacl': [path_rule(a, '/usr/bin/setfacl') for a in ('b32', 'b64')],
    'audit_rules_execution_chacl': [path_rule(a, '/usr/bin/chacl') for a in ('b32', 'b64')],
    'audit_rules_privileged_commands_kmod': [path_rule(a, '/usr/bin/kmod') for a in ('b32', 'b64')],
    'audit_rules_privileged_commands_usermod': [path_rule(a, '/usr/sbin/usermod')
                                                for a in ('b32', 'b64')],
    'audit_rules_mac_modification_etc_selinux': [watch('/etc/selinux/')],
    'audit_rules_mac_modification_usr_share': [watch('/usr/share/selinux/')],
    'audit_rules_mac_modification_var_lib_selinux': [watch('/var/lib/selinux/')],
    'audit_rules_sysadmin_actions': [watch('/etc/sudoers'), watch('/etc/sudoers.d/')],
    'audit_rules_usergroup_modification_pamd': [watch('/etc/pam.d/')],
    'audit_rules_networkconfig_modification_etc_sysconfig_network': [watch('/etc/sysconfig/network')],
    'audit_rules_networkconfig_modification_networkmanager': [watch('/etc/NetworkManager')],
    'audit_rules_suid_auid_privilege_function': [suid_auid('b32'), suid_auid('b64')],
}


def bash(body, *args):
    r = subprocess.run(['bash', '-c', f'source "$1"; shift; {body}', 'test', SCRIPT, *args],
                       capture_output=True, text=True, timeout=60,
                       env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
    if r.returncode:
        raise AssertionError(r.stdout + r.stderr)
    return r.stdout


def heredoc(name):
    """rules of a file the section writes from a here-document (70-*.rules)"""
    with open(SCRIPT) as f:
        text = f.read()
    m = re.search(r'write_file "\$d/' + re.escape(name) + r'" 0640 <<\'EOF\'\n(.*?)\nEOF\n', text, re.S)
    return m.group(1)


class AuditRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cis = bash('rules_cis')
        cls.rules = [ln for ln in cls.cis.splitlines() if ln.startswith('-')]

    def test_scanner_text(self):
        for rule, pats in MATCH_ONCE.items():
            for p in pats:
                n = len(re.findall(p, self.cis, re.M))
                self.assertEqual(n, 1, f'{rule}: {n} lines match {p}')

    def test_path_rules_once_per_arch(self):
        paths = [ln for ln in self.rules if ' -F path=' in ln]
        self.assertTrue(paths)
        for ln in paths:
            self.assertRegex(ln, r'^-a always,exit -F arch=b(32|64) -F path=')
        b32 = sorted(ln.replace('arch=b32', 'arch=') for ln in paths if 'arch=b32' in ln)
        b64 = sorted(ln.replace('arch=b64', 'arch=') for ln in paths if 'arch=b64' in ln)
        self.assertEqual(b32, b64)

    def test_syscall_rules_both_arches(self):
        sys_rules = [ln for ln in self.rules if ' -S ' in ln]
        b32 = sorted(ln.replace('arch=b32', 'arch=') for ln in sys_rules if 'arch=b32' in ln)
        b64 = sorted(ln.replace('arch=b64', 'arch=') for ln in sys_rules if 'arch=b64' in ln)
        self.assertEqual(len(b32) + len(b64), len(sys_rules))
        self.assertEqual(b32, b64)

    def test_kept_on_purpose(self):
        # every caller of sethostname / setdomainname (systemd-hostnamed has no login uid):
        # broader than the scanner's rule, which wants auid>=1000
        for call in ('sethostname', 'setdomainname'):
            for a in ('b32', 'b64'):
                self.assertEqual(re.findall(hostname_ssg(a, call), self.cis, re.M), [])
        self.assertIn('-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale',
                      self.rules)
        # /etc/NetworkManager is watched as a whole (folder watch = whole tree): no own
        # line for system-connections/
        self.assertNotIn('system-connections', '\n'.join(self.rules))

    def test_rule_count(self):
        # docs/verification.md and sectop's posture default (audit-rules want): 53 rules
        # of other keys, then two per setuid / setgid file (key privileged)
        others = self.rules + [ln for n in ('70-io-uring.rules', '70-af-alg.rules')
                               for ln in heredoc(n).splitlines() if ln.startswith('-')]
        self.assertEqual(len(others), 53)
        self.assertNotIn('-k privileged', '\n'.join(others))

    def test_privileged_rules(self):
        with tempfile.TemporaryDirectory() as d:
            for name, mode in (('su', 0o4755), ('write', 0o2755), ('ls', 0o755)):
                p = os.path.join(d, name)
                with open(p, 'w') as f:
                    f.write('#!/bin/sh\n')
                os.chmod(p, mode)
            text = bash('rules_privileged "$1"', d)
            setuid = sorted(os.path.join(d, n) for n in ('su', 'write'))
            for a in ('b32', 'b64'):
                found = sorted(m.group(1) for m in re.finditer(privileged(a), text, re.M))
                self.assertEqual(found, setuid, text)
            self.assertNotIn('/ls ', text)
            self.assertTrue(all(ln.endswith('-k privileged') for ln in text.splitlines()
                                if ln.startswith('-')))
            self.assertTrue(os.stat(setuid[0]).st_mode & (stat.S_ISUID | stat.S_ISGID))



SYNC = os.path.join(HERE, 'audit', 'audit-privileged-sync')


class PrivilegedSync(unittest.TestCase):
    """audit/audit-privileged-sync write mode (boot unit), on a copy with test paths:
    rules file, scanned dir and the root check replaced (the real one takes no input)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.usr, self.out = os.path.join(t, 'usr'), os.path.join(t, 'rules.d', '55-privileged.rules')
        os.makedirs(self.usr)
        os.makedirs(os.path.dirname(self.out))
        with open(SYNC) as f:
            text = f.read()
        for old, new in (('OUT=/etc/audit/rules.d/55-privileged.rules', f'OUT={self.out}'),
                         ('SCAN=/usr', f'SCAN={self.usr}'),
                         ('[[ $EUID -eq 0 ]] ||', '[[ -n x ]] ||')):
            self.assertEqual(text.count(old), 1, old)
            text = text.replace(old, new)
        self.script = os.path.join(t, 'sync')
        with open(self.script, 'w') as f:
            f.write(text)

    def tearDown(self):
        self.tmp.cleanup()

    def prog(self, name, mode=0o4755):
        p = os.path.join(self.usr, name)
        with open(p, 'w') as f:
            f.write('#!/bin/sh\n')
        os.chmod(p, mode)
        return p

    def run_sync(self, *args):
        return subprocess.run(['bash', self.script, *args], capture_output=True, text=True,
                              timeout=60, env={'PATH': '/usr/bin:/bin'})

    def read(self):
        with open(self.out) as f:
            return f.read()

    def test_write_then_no_change(self):
        su, wr = self.prog('su'), self.prog('write', 0o2755)
        self.prog('ls', 0o755)
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('written (2 programs)', r.stdout)
        text = self.read()
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o640)
        for a in ('b32', 'b64'):
            found = sorted(m.group(1) for m in re.finditer(privileged(a), text, re.M))
            self.assertEqual(found, sorted([su, wr]))
        self.assertEqual(text, subprocess.run(['bash', self.script, '--print'], capture_output=True,
                                              text=True, env={'PATH': '/usr/bin:/bin'}).stdout)
        r = self.run_sync()
        self.assertIn('no change (2 programs)', r.stdout)
        self.assertEqual(os.listdir(os.path.dirname(self.out)), ['55-privileged.rules'])

    def test_new_and_gone_named(self):
        su = self.prog('su')
        self.run_sync()
        os.unlink(su)
        new = self.prog('newuid')
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'new: {new}', r.stdout)
        self.assertIn(f'gone: {su}', r.stdout)
        self.assertNotIn(su, self.read())

    def test_failed_scan_keeps_old_file(self):
        self.prog('su')
        self.run_sync()
        before = self.read()
        for p in os.listdir(self.usr):
            os.unlink(os.path.join(self.usr, p))
        r = self.run_sync()                       # empty: never an empty list
        self.assertEqual(r.returncode, 1)
        self.assertIn('kept', r.stderr)
        self.assertEqual(self.read(), before)
        os.rmdir(self.usr)
        r = self.run_sync()                       # find fails
        self.assertEqual(r.returncode, 1)
        self.assertIn('kept', r.stderr)
        self.assertEqual(self.read(), before)
        self.assertEqual(os.listdir(os.path.dirname(self.out)), ['55-privileged.rules'])

    def test_unusable_name_skipped(self):
        self.prog('su')
        self.prog('bad name')
        self.prog('x\n-D')
        r = self.run_sync()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('written (1 programs)', r.stdout)
        self.assertEqual(r.stderr.count('skipped'), 2)
        self.assertNotIn('bad', self.read())
        self.assertNotIn('-D', self.read().replace('-D ', ''))
        rules = [ln for ln in self.read().splitlines() if ln and not ln.startswith('##')]
        self.assertEqual(len(rules), 2)

    def test_arguments(self):
        self.assertEqual(self.run_sync('--bogus').returncode, 2)


if __name__ == '__main__':
    unittest.main()
