#
# tests for the integrity section (AIDE + root drift check, review D-U1): aide.conf in
# the form scap-security-guide 0.1.82 checks (patterns copied from ssg-fedora-ds.xml),
# the unit and harden-check agree on paths and properties, harden-check's checks on temp
# files (stdlib, no root, nothing outside a temp dir).
#
#   python3 -I -B -m unittest discover -s tests
#
import importlib.machinery
import importlib.util
import json
import os
import re
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF = os.path.join(HERE, 'integrity', 'aide.conf')
UNIT = os.path.join(HERE, 'integrity', 'aidecheck.service')
TIMER = os.path.join(HERE, 'integrity', 'aidecheck.timer')
TOOL = os.path.join(HERE, 'integrity', 'harden-check')
SCRIPT = os.path.join(HERE, 'harden-workstation.sh')

# scap-security-guide 0.1.82, ssg-fedora-ds.xml (OVAL objects / states of the aide_* rules)
SSG_DBDIR = r'^@@define[\s]DBDIR[\s]+(/.*)$'
SSG_DB_IN = r'^database_in=file:(?:@@{DBDIR})?/(?:[a-z.]+/)*([a-z.]+)$'
SSG_TOOL = r'^(?:/usr)?/sbin/{}\s+([^\n]+)$'
SSG_TOOL_STATE = r'^p\+i\+n\+u\+g\+s\+b\+acl(|\+selinux)\+xattrs\+sha512$'
SSG_TOOLS = ('auditctl', 'auditd', 'ausearch', 'aureport', 'audispd', 'augenrules')


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(text)
    if mode is not None:
        os.chmod(path, mode)


def load_tool():
    loader = importlib.machinery.SourceFileLoader('harden_check', TOOL)
    spec = importlib.util.spec_from_loader('harden_check', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


hc = load_tool()


class Conf(unittest.TestCase):
    def setUp(self):
        self.text = read(CONF)

    def test_ascii_no_tabs(self):
        self.assertTrue(self.text.isascii())
        self.assertNotIn('\t', self.text)

    def test_ssg_database(self):
        dbdir = [m.group(1) for m in re.finditer(SSG_DBDIR, self.text, re.M)]
        name = [m.group(1) for m in re.finditer(SSG_DB_IN, self.text, re.M)]
        self.assertEqual(len(dbdir), 1)
        self.assertEqual(len(name), 1)
        self.assertEqual(dbdir[0] + '/' + name[0], hc.AIDE_DB)
        self.assertIn('database_out=file:@@{DBDIR}/' + os.path.basename(hc.AIDE_NEW), self.text)

    def test_ssg_audit_tools(self):
        for tool in SSG_TOOLS:
            m = re.findall(SSG_TOOL.format(tool), self.text, re.M)
            self.assertEqual(len(m), 1, tool)          # instance 1: exactly one line
            self.assertRegex(m[0], SSG_TOOL_STATE, tool)
        self.assertEqual(tuple('/usr/sbin/' + t for t in SSG_TOOLS), hc.AUDIT_TOOLS)

    def test_reports(self):
        # plain list to the journal, json for harden-check; options bind to the url after
        lines = [ln for ln in self.text.splitlines() if ln.startswith('report_')]
        self.assertEqual(lines, ['report_level=list_entries', 'report_format=plain',
                                 'report_url=stdout', 'report_level=changed_attributes',
                                 'report_format=json',
                                 'report_url=file:@@{LOGDIR}/' + os.path.basename(hc.AIDE_JSON)])
        self.assertIn('@@define LOGDIR ' + os.path.dirname(hc.AIDE_JSON), self.text)

    def test_etc_without_times(self):
        groups = dict(re.findall(r'^([A-Z]+) = (\S+)$', self.text, re.M))
        for g in ('CONTENT', 'DIRS', 'NAMES'):
            attrs = groups[g].split('+')
            for a in ('m', 'c', 'a', 'i', 'n', 'b', 'S', 'R', 'L'):
                self.assertNotIn(a, attrs, f'{g}: {a}')
        self.assertIn('sha512', groups['CONTENT'].split('+'))
        self.assertNotIn('sha512', groups['NAMES'].split('+'))

    def test_scope(self):
        rules = [ln.split()[0] for ln in self.text.splitlines()
                 if ln.startswith(('/', '!/'))]
        for root in ('/etc', '/boot', '/var/usrlocal', '/var/roothome', '/var/spool/cron'):
            self.assertIn(root, rules)
        # restricted dir rule before the general one of the same node (first match wins)
        for root in ('/etc', '/boot', '/var/usrlocal', '/var/roothome', '/var/spool/cron'):
            d = self.text.index(f'\n{root} d DIRS\n')
            c = self.text.index(f'\n{root} 0 CONTENT\n')
            self.assertLess(d, c, root)
        self.assertFalse([r for r in rules if r == '/usr' or r.startswith('/var/lib')])
        # '@' must be escaped in a rule (aide.conf(5))
        for ln in self.text.splitlines():
            if ln.startswith(('/', '!/')):
                self.assertIsNone(re.search(r'(?<!\\)@', ln), ln)

    def test_daemon_files_names_only(self):
        rx = [(ln.split()[0], ln.split()[-1]) for ln in self.text.splitlines()
              if ln.startswith('/etc/') and ln.split()[-1] == 'NAMES']
        def names_rule(path):
            for r, _ in rx:
                pat = r.replace('\\@', '@')
                if re.match(pat, path):
                    return True
            return False
        for p in ('/etc/NetworkManager/system-connections/x.nmconnection',
                  '/etc/mullvad-vpn/settings.json', '/etc/asusd/fan_curves.ron',
                  '/etc/supergfxd.conf', '/etc/tuned/bootcmdline', '/etc/adjtime',
                  '/etc/cups/subscriptions.conf.O',
                  '/etc/systemd/system.control/user@1000.service.d/50-MemoryMin.conf',
                  '/etc/systemd/system.control/user-60578.slice.d/50-CPUWeight.conf',
                  '/etc/systemd/system.control/user.slice.d/50-MemoryLow.conf'):
            self.assertTrue(names_rule(p), p)
        for p in ('/etc/shadow', '/etc/modprobe.d/supergfxd.conf', '/etc/tuned/tuned-main.conf',
                  '/etc/systemd/system.control/user@1000.service.d/90-other.conf',
                  '/etc/mullvad-vpn/other.toml'):
            self.assertFalse(names_rule(p), p)


class Units(unittest.TestCase):
    def test_service(self):
        text = read(UNIT)
        execs = re.findall(r'^ExecStart=(.*)$', text, re.M)
        # CIS example first (exact), then the drift check
        self.assertEqual(execs, ['/usr/sbin/aide --check', '/usr/local/sbin/harden-check'])
        self.assertIn('SuccessExitStatus=1 2 3 4 5 6 7\n', text)
        self.assertIn(f'ConditionPathExists={hc.AIDE_DB}\n', text)
        for p in hc.UNIT_PROPS:
            self.assertIn(p + '\n', text)
        # bind mounts by PID 1 (SELinux mounton) and no_new_privs (domain change): never
        for bad in ('ProtectSystem', 'ReadWritePaths', 'ReadOnlyPaths', 'ProtectHome',
                    'NoNewPrivileges', 'SystemCallFilter', 'RestrictAddressFamilies'):
            self.assertNotRegex(text, rf'(?m)^{bad}=', bad)

    def test_timer(self):
        text = read(TIMER)
        for line in ('OnBootSec=5min', 'OnCalendar=daily', 'Persistent=true',
                     'WantedBy=timers.target'):
            self.assertIn(line + '\n', text)

    def test_section_listed_last(self):
        text = read(SCRIPT)
        sections = re.search(r'^SECTIONS=\((.*)\)$', text, re.M).group(1).split()
        self.assertEqual(sections[-1], 'integrity')
        self.assertIn('      integrity)   sec_integrity ;;\n', text)

    def test_auditd_values_as_the_section(self):
        text = read(SCRIPT)
        body = text[text.index('sec_auditd() {'):]
        body = body[:body.index('\n}\n')]
        want = dict(re.findall(r'set_kv "\$f" (\S+) (\S+)', body))
        self.assertEqual(want, hc.AUDITD_WANT)


class Tool(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = self.dir.name
        self.saved = {k: getattr(hc, k) for k in dir(hc) if k.isupper()}
        self.saved_fn = {'usr_etc_changes': hc.usr_etc_changes, 'run': hc.run,
                         'booted_target': hc.booted_target}

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(hc, k, v)
        for k, v in self.saved_fn.items():
            setattr(hc, k, v)
        self.dir.cleanup()

    def p(self, *parts):
        return os.path.join(self.d, *parts)

    def test_booted_deployment(self):
        dep = self.p('ostree', 'deploy', 'fedora', 'deploy', 'abc123.0')
        os.makedirs(dep)
        link = self.p('ostree', 'boot.1', 'fedora', 'bcs9', '0')
        os.makedirs(os.path.dirname(link))
        os.symlink(dep, link)
        cmd = f'BOOT_IMAGE=(hd0,gpt2)/x rhgb ostree={link} quiet\n'
        csum, bootcsum = hc.booted_deployment(cmd)
        self.assertEqual(csum, 'abc123')
        self.assertEqual(hc.booted_deployment('quiet\n'), ('', ''))
        # /ostree/boot.1/fedora/<bootcsum>/<serial>: the boot checksum is part 4
        self.assertEqual(hc.booted_deployment('ostree=/ostree/boot.1/fedora/bcs9/0')[1], 'bcs9')

    def test_aide_entries(self):
        grouped = {'added': {'/etc/b': 'f++++'}, 'removed': {'/etc/a': 'f----'},
                   'changed': {'/etc/c': 'f   ...'}}
        self.assertEqual(hc.aide_entries(grouped), [('-', '/etc/a'), ('+', '/etc/b'), ('~', '/etc/c')])
        self.assertEqual(hc.aide_entries({'changed': ['/etc/x']}), [('~', '/etc/x')])
        self.assertEqual(hc.aide_entries({}), [])

    def test_update_explained(self):
        etc = {'/etc/pki/ca-trust/extracted/java/cacerts'}
        self.assertTrue(hc.update_explained('/etc/pki/ca-trust/extracted/java/cacerts', etc))
        self.assertTrue(hc.update_explained('/boot/ostree/fedora-x/initramfs-1.img', set()))
        self.assertTrue(hc.update_explained('/boot/loader.1/entries/ostree-1.conf', set()))
        self.assertTrue(hc.update_explained('/etc/ld.so.cache', set()))
        self.assertTrue(hc.update_explained('/etc/selinux/targeted/policy/policy.35', set()))
        self.assertTrue(hc.update_explained('/usr/sbin/auditctl', set()))
        self.assertFalse(hc.update_explained('/etc/shadow', etc))
        self.assertFalse(hc.update_explained('/etc/pki/other', None))
        self.assertFalse(hc.update_explained('/var/usrlocal/sbin/hostfw', etc))

    def aide_setup(self, report, accepted='dep1 2026-11-22T13:00+03:00', age=0):
        hc.AIDE_DB = self.p('aide.db.gz')
        hc.AIDE_JSON = self.p('aide.json')
        hc.ACCEPTED = self.p('accepted')
        write(hc.AIDE_DB, '')
        write(hc.AIDE_JSON, json.dumps(report))
        t = time.time() - age
        os.utime(hc.AIDE_JSON, (t, t))
        if accepted is not None:
            write(hc.ACCEPTED, accepted + '\n')
        elif os.path.exists(hc.ACCEPTED):
            os.unlink(hc.ACCEPTED)

    def test_check_aide(self):
        now = time.time()
        self.aide_setup({'number_of_entries': {'total': 5000}})
        c = hc.check_aide(now, 'dep1')
        self.assertEqual((c.status, c.summary),
                         ('pass', '5000 entries, no change since 2026-11-22T13:00+03:00'))
        # same deployment: everything is "other"
        self.aide_setup({'changed': {'/etc/shadow': 'f', '/etc/ld.so.cache': 'f'},
                         'added': {'/var/spool/cron/null': 'f'}})
        c = hc.check_aide(now, 'dep1')
        self.assertEqual(c.status, 'fail')
        self.assertEqual(c.summary, '3 changed since 2026-11-22T13:00+03:00: 3 other, '
                                    '0 from the OS update')
        # new deployment: the update explains some (ostree diff of /usr/etc)
        hc.usr_etc_changes = lambda old, new: {'/etc/pki/x'} if (old, new) == ('dep1', 'dep2') else set()
        self.aide_setup({'changed': {'/etc/shadow': 'f', '/etc/ld.so.cache': 'f', '/etc/pki/x': 'f'}})
        c = hc.check_aide(now, 'dep2')
        self.assertEqual(c.summary.split(': ')[1], '1 other, 2 from the OS update')
        self.assertEqual(c.items, ['other ~ /etc/shadow', 'update ~ /etc/ld.so.cache',
                                   'update ~ /etc/pki/x'])
        # old commit pruned: /etc not grouped, said so
        hc.usr_etc_changes = lambda old, new: None
        c = hc.check_aide(now, 'dep2')
        self.assertTrue(c.items[0].startswith('note: ostree diff'))
        self.assertEqual(c.summary.split(': ')[1], '2 other, 1 from the OS update')

    def test_check_aide_stale_missing_many(self):
        now = time.time()
        self.aide_setup({}, age=3 * 3600)
        c = hc.check_aide(now, 'dep1')
        self.assertEqual(c.status, 'fail')
        self.assertIn('did not report', c.summary)
        os.unlink(hc.AIDE_JSON)
        self.assertEqual(hc.check_aide(now, 'dep1').status, 'unknown')
        os.unlink(hc.AIDE_DB)
        self.assertIn('no database', hc.check_aide(now, 'dep1').summary)
        self.aide_setup({'added': {f'/etc/n{i:04d}': 'f' for i in range(450)}}, accepted=None)
        c = hc.check_aide(now, 'dep1')
        self.assertEqual(c.summary, '450 changed: 450 other, 0 from the OS update')
        self.assertEqual(len(c.items), hc.MAX_ITEMS + 1)
        self.assertEqual(c.items[-1], '... 250 more: sudo harden-check --accept shows all')

    def test_boot_image(self):
        boot = self.p('boot')
        dep = self.p('deploy', 'c1.0')
        os.makedirs(os.path.join(dep, 'usr', 'lib', 'modules', '7.3.4'))
        for name, data in (('vmlinuz', 'K'), ('initramfs.img', 'I')):
            write(os.path.join(dep, 'usr', 'lib', 'modules', '7.3.4', name), data)
        write(os.path.join(boot, 'ostree', 'fedora-b1', 'vmlinuz-7.3.4'), 'K')
        write(os.path.join(boot, 'ostree', 'fedora-b1', 'initramfs-7.3.4.img'), 'I')
        link = self.p('ob', 'boot.1', 'fedora', 'b1', '0')
        os.makedirs(os.path.dirname(link))
        os.symlink(dep, link)
        write(os.path.join(boot, 'loader', 'entries', 'ostree-1.conf'),
              'title Fedora\nversion 1\nlinux /ostree/fedora-b1/vmlinuz-7.3.4\n'
              'initrd /ostree/fedora-b1/initramfs-7.3.4.img\n'
              f'options root=x rw ostree={link}\n')
        hc.booted_target = lambda: ''                    # not booted: its own folder's /usr
        c = hc.check_boot_image(boot)
        self.assertEqual((c.status, c.summary), ('pass', '2 files = image (1 entries)'))
        write(os.path.join(boot, 'ostree', 'fedora-b1', 'initramfs-7.3.4.img'), 'X')
        c = hc.check_boot_image(boot)
        self.assertEqual(c.status, 'fail')
        self.assertIn('initramfs-7.3.4.img differs', c.items[0])
        write(os.path.join(boot, 'ostree', 'fedora-b1', 'initramfs-7.3.4.img'), 'I')
        os.makedirs(os.path.join(boot, 'ostree', 'fedora-zz'))
        c = hc.check_boot_image(boot)
        self.assertEqual(c.status, 'fail')
        self.assertIn('without an entry', c.summary)

    def test_accounts_uids_only(self):
        hc.PASSWD_DB = self.p('passwd')
        hc.SHADOW = self.p('shadow')
        write(hc.PASSWD_DB, 'root:x:0:0::/root:/bin/bash\nbin:x:1:1::/:/sbin/nologin\n'
                         'adm1:x:1001:1001::/h:/bin/bash\nday1:x:1000:1000::/h:/bin/bash\n')
        write(hc.SHADOW, 'root:!locked::0:99999:7:::\nbin:*:1:0:99999:7:::\n'
                         'adm1:$y$j9T$abc:1:1:365:14:::\nday1:$y$j9T$def:1:1:365:14:::\n')
        c = hc.check_accounts()
        self.assertEqual((c.status, c.summary),
                         ('pass', '2 login accounts, root and system accounts locked'))
        write(hc.SHADOW, 'root:$6$x:1::::::\nbin::1:0::::\nadm1:$y$a:1::::::\n')
        c = hc.check_accounts()
        self.assertEqual(c.status, 'fail')
        self.assertEqual(c.items, ['uid 0: root has a password (root stays locked)',
                                   'uid 1: empty password'])
        text = hc.render([c], time.time())
        self.assertNotIn('adm1', text)
        self.assertNotIn('day1', text)

    def test_conf_checks(self):
        hc.AUDITD_CONF = self.p('auditd.conf')
        write(hc.AUDITD_CONF, '# x\n' + ''.join(f'{k} = {v}\n' for k, v in hc.AUDITD_WANT.items()))
        self.assertEqual(hc.check_auditd_conf().status, 'pass')
        write(hc.AUDITD_CONF, 'disk_full_action = HALT\n')
        c = hc.check_auditd_conf()
        self.assertEqual(c.status, 'fail')
        self.assertIn('disk_full_action = HALT, want SUSPEND', c.items)
        hc.FIREWALLD_CONF = self.p('firewalld.conf')
        write(hc.FIREWALLD_CONF, '# DefaultZone=public\nDefaultZone=drop\n')
        self.assertEqual(hc.check_firewalld_conf().status, 'pass')
        write(hc.FIREWALLD_CONF, 'DefaultZone=public\n')
        self.assertEqual(hc.check_firewalld_conf().status, 'fail')
        hc.BPF_JIT = self.p('bpf')
        write(hc.BPF_JIT, '2\n')
        self.assertEqual(hc.check_bpf_jit().status, 'pass')
        write(hc.BPF_JIT, '1\n')
        self.assertEqual(hc.check_bpf_jit().status, 'fail')
        hc.APPLIED = self.p('applied')
        self.assertEqual(hc.check_applied().status, 'fail')
        write(hc.APPLIED, '# x\nkargs\nsysctl\n')
        self.assertEqual(hc.check_applied().summary, '2 sections applied: kargs sysctl')

    def test_audit_loaded(self):
        hc.RULES_D = self.p('rules.d')
        write(os.path.join(hc.RULES_D, '50.rules'), '## c\n-a always,exit -S x\n-w /etc/a -p wa\n-e 2\n')
        write(os.path.join(hc.RULES_D, 'x.prev'), '-a always,exit\n')   # not *.rules

        class R:
            returncode, stderr = 0, ''
            stdout = '-a always,exit -S x\n-w /etc/a -p wa -k k\n'
        hc.run = lambda argv, timeout=120: R()
        self.assertEqual(hc.check_audit_loaded().summary, '2 loaded = rules.d')
        R.stdout = '-a always,exit -S x\n'
        self.assertEqual(hc.check_audit_loaded().status, 'fail')

    def test_render_and_write(self):
        c = hc.Check('aide').set('fail', 'x')
        c.item('other + /etc/a\tb\x1b[31m')
        text = hc.render([c, hc.Check('bpf-jit').set('pass', 'ok')], 1763800000)
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith('#'))
        self.assertEqual(lines[1].split('\t')[:2], ['time', '1763800000'])
        self.assertEqual(lines[2], 'check\taide\tfail\tx')
        self.assertEqual(lines[3], 'item\taide\tother + /etc/a b?[31m')
        self.assertEqual(lines[4], 'check\tbpf-jit\tpass\tok')
        self.assertTrue(text.isascii())
        out = self.p('result')
        hc.GROUP = 'no-such-group-x'
        hc.write_result(text, out)
        self.assertEqual(read(out), text)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        self.assertEqual([f for f in os.listdir(self.d) if f.startswith('.result')], [])


if __name__ == '__main__':
    unittest.main()
