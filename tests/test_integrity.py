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
                  '/etc/cups/subscriptions.conf.O', '/etc/suricata/harden-ids/net.yaml',
                  '/etc/systemd/system.control/user@1000.service.d/50-MemoryMin.conf',
                  '/etc/systemd/system.control/user-60578.slice.d/50-CPUWeight.conf',
                  '/etc/systemd/system.control/user.slice.d/50-MemoryLow.conf'):
            self.assertTrue(names_rule(p), p)
        for p in ('/etc/shadow', '/etc/modprobe.d/supergfxd.conf', '/etc/tuned/tuned-main.conf',
                  '/etc/systemd/system.control/user@1000.service.d/90-other.conf',
                  '/etc/mullvad-vpn/other.toml', '/etc/suricata/harden-ids/local.rules'):
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
        # own network namespace: no net.core.bpf_* sysctls there (host 2026-11-22)
        self.assertIn('IPAddressDeny=any\n', text)
        for bad in ('ProtectSystem', 'ReadWritePaths', 'ReadOnlyPaths', 'ProtectHome',
                    'NoNewPrivileges', 'SystemCallFilter', 'RestrictAddressFamilies',
                    'PrivateNetwork'):
            self.assertNotRegex(text, rf'(?m)^{bad}=', bad)

    def test_selinux_module_one_narrow_rule(self):
        text = read(os.path.join(HERE, 'integrity', 'harden_aide_efi.cil'))
        self.assertTrue(text.isascii())
        rules = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith(';')]
        # aide may stat the EFI partition's file system: nothing else
        self.assertEqual(rules, ['(allow aide_t dosfs_t (filesystem (getattr)))'])

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
                         'booted_target': hc.booted_target,
                         'journal_greeter_uids': hc.journal_greeter_uids,
                         'live_greeter_uids': hc.live_greeter_uids,
                         'greeter_file_ok': hc.greeter_file_ok, 'greeter_dir_ok': hc.greeter_dir_ok,
                         'booted_deployment': hc.booted_deployment}

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
        self.assertTrue(hc.update_explained('/etc/audit/audit.rules', set()))
        self.assertTrue(hc.update_explained('/etc/audit/audit.rules.prev', set()))
        self.assertFalse(hc.update_explained('/etc/audit/rules.d/30-x.rules', set()))
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
                                    '0 GDM greeter, 0 from the OS update')
        # new deployment: the update explains some (ostree diff of /usr/etc)
        hc.usr_etc_changes = lambda old, new: {'/etc/pki/x'} if (old, new) == ('dep1', 'dep2') else set()
        self.aide_setup({'changed': {'/etc/shadow': 'f', '/etc/ld.so.cache': 'f', '/etc/pki/x': 'f'}})
        c = hc.check_aide(now, 'dep2')
        self.assertEqual(c.summary.split(': ')[1], '1 other, 0 GDM greeter, 2 from the OS update')
        self.assertEqual(c.items, ['other ~ /etc/shadow', 'update ~ /etc/ld.so.cache',
                                   'update ~ /etc/pki/x'])
        # old commit pruned: /etc compared with /usr/etc (none here: not grouped), said so
        hc.usr_etc_changes = lambda old, new: None
        hc.ETC, hc.USR_ETC = self.p('etc'), self.p('usr', 'etc')
        c = hc.check_aide(now, 'dep2')
        self.assertTrue(c.items[0].startswith('note: ostree diff'))
        self.assertEqual(c.summary.split(': ')[1], '2 other, 0 GDM greeter, 1 from the OS update')

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
        self.assertEqual(c.summary, '450 changed: 450 other, 0 GDM greeter, 0 from the OS update')
        self.assertEqual(len(c.items), hc.MAX_ITEMS + 1)
        self.assertEqual(c.items[-1], '... 250 more: sudo harden-check --list shows all')

    def test_same_as_image(self):
        """Old commit pruned (host 2026-11-27, admin 78): an /etc file the same as the
        image's /usr/etc copy came with the update."""
        hc.ETC, hc.USR_ETC = self.p('etc'), self.p('usr', 'etc')
        for root in (hc.ETC, hc.USR_ETC):
            write(os.path.join(root, 'pki', 'cacerts'), 'certs', 0o644)
            write(os.path.join(root, 'brlapi.key'), 'key', 0o640)
            os.symlink('cacerts', os.path.join(root, 'pki', 'link'))
        e = lambda *x: os.path.join(hc.ETC, *x)        # noqa: E731
        self.assertTrue(hc.same_as_image('~', e('pki', 'cacerts')))
        self.assertTrue(hc.same_as_image('~', e('brlapi.key'), {'sha512', 'size'}))
        self.assertTrue(hc.same_as_image('~', e('pki', 'link')))
        self.assertTrue(hc.same_as_image('~', e('pki')))
        self.assertFalse(hc.same_as_image('~', e('brlapi.key'), {'sha512', 'selinux'}))
        write(e('brlapi.key'), 'other', 0o640)
        self.assertFalse(hc.same_as_image('~', e('brlapi.key')))          # content
        write(e('brlapi.key'), 'key', 0o644)
        self.assertFalse(hc.same_as_image('~', e('brlapi.key')))          # mode
        self.assertFalse(hc.same_as_image('+', e('new.conf')))            # not in the image
        self.assertTrue(hc.same_as_image('-', e('gone.conf')))            # gone from both
        write(os.path.join(hc.USR_ETC, 'kept.conf'), 'x')
        self.assertFalse(hc.same_as_image('-', e('kept.conf')))           # image still has it
        self.assertFalse(hc.same_as_image('~', '/var/x'))

    def test_pruned_commit_falls_back_to_image(self):
        now = time.time()
        hc.ETC, hc.USR_ETC = self.p('etc'), self.p('usr', 'etc')
        hc.usr_etc_changes = lambda old, new: None
        hc.journal_greeter_uids = lambda lines=None: set()
        hc.live_greeter_uids = lambda: set()
        same, changed = os.path.join(hc.ETC, 'cacerts'), os.path.join(hc.ETC, 'shadow')
        for root in (hc.ETC, hc.USR_ETC):
            write(os.path.join(root, 'cacerts'), 'certs', 0o644)
            write(os.path.join(root, 'shadow'), 'image', 0o600)
        write(changed, 'edited', 0o600)
        self.aide_setup({'changed': {same: 'f', changed: 'f'},
                         'details': {same: {'sha512': {}, 'size': {}}}})
        c = hc.check_aide(now, 'dep2')
        self.assertIn('compared with /usr/etc', c.items[0])
        self.assertEqual(c.summary.split(': ')[1], '1 other, 0 GDM greeter, 1 from the OS update')
        self.assertIn('other ~ ' + changed, c.items)
        self.assertIn('update ~ ' + same, c.items)
        c = hc.check_aide(now, 'dep1')                    # same deployment: never
        self.assertIn('2 other', c.summary)

    def test_privileged_rules_from_the_sync(self):
        now = time.time()
        hc.journal_greeter_uids = lambda lines=None: set()
        hc.live_greeter_uids = lambda: set()
        hc.usr_etc_changes = lambda old, new: set()
        hc.PRIV_RULES = self.p('55-privileged.rules')
        hc.PRIV_OWNER = os.getuid()
        rules = '## x\n-a always,exit -F arch=b64 -F path=/usr/bin/su -k privileged\n'
        calls = []

        def run(argv, timeout=120):
            calls.append(argv)
            return hc.subprocess.CompletedProcess(argv, 0, rules, '')
        hc.run = run
        write(hc.PRIV_RULES, rules, 0o640)
        self.assertTrue(hc.priv_rules_explained())
        self.assertEqual(calls[-1], [hc.PRIV_SYNC, '--print'])
        self.aide_setup({'changed': {hc.PRIV_RULES: 'f'}})
        self.assertIn('1 from the OS update', hc.check_aide(now, 'dep2').summary)
        self.assertIn('1 other', hc.check_aide(now, 'dep1').summary)      # same deployment
        write(hc.PRIV_RULES, rules + '# edited\n', 0o640)
        self.assertFalse(hc.priv_rules_explained())                       # not the sync's
        write(hc.PRIV_RULES, rules, 0o660)
        self.assertFalse(hc.priv_rules_explained())                       # group writable
        os.chmod(hc.PRIV_RULES, 0o640)
        hc.PRIV_OWNER = os.getuid() + 1
        self.assertFalse(hc.priv_rules_explained())                       # not root's

    # --- GDM greeter drop-ins (host 2026-11-24, admin 62 / 63) --------------------------

    SC = '/etc/systemd/system.control/'
    # a drop-in as logind writes it (systemctl set-property form)
    DROPIN = ('# This is a drop-in unit file extension, created via "systemctl set-property"\n'
              '# or an equivalent operation. Do not edit.\n[Slice]\n{}\n')
    PAM = ('pam_unix(gdm-launch-environment:session): session opened for user '
           'gdm-greeter(uid={}) by (uid=0)')

    def test_greeter_uid(self):
        self.assertEqual(hc.greeter_uid(self.SC + 'user-60580.slice.d'), 60580)
        self.assertEqual(hc.greeter_uid(self.SC + 'user@60580.service.d/50-MemoryMin.conf'), 60580)
        self.assertEqual(hc.greeter_uid(self.SC + 'user-60705.slice.d/50-CPUWeight.conf'), 60705)
        self.assertIsNone(hc.greeter_uid(self.SC + 'user-1000.slice.d/50-CPUWeight.conf'))
        self.assertIsNone(hc.greeter_uid(self.SC + 'user-60706.slice.d'))
        self.assertIsNone(hc.greeter_uid(self.SC + 'user-60580.slice.d/50-TasksMax.conf'))
        self.assertIsNone(hc.greeter_uid(self.SC + 'user-60580.slice.d/override.conf'))
        self.assertIsNone(hc.greeter_uid('/etc/systemd/system/user-60580.slice.d'))

    def test_journal_greeter_uids_root_lines_only(self):
        lines = '\n'.join([
            json.dumps({'MESSAGE': self.PAM.format(60580), '_UID': '0'}),
            json.dumps({'MESSAGE': self.PAM.format(60581), '_UID': '1000'}),   # logger line
            json.dumps({'MESSAGE': self.PAM.replace('gdm-greeter', 'gdm-greeter-3')
                        .format(60582), '_UID': '0'}),
            json.dumps({'MESSAGE': 'session opened for user gdm-greeter(uid=60583)', '_UID': '0'}),
            'not json', '[1]'])
        self.assertEqual(hc.journal_greeter_uids(lines), {60580, 60582})
        hc.run = lambda argv, timeout=120: hc.subprocess.CompletedProcess(argv, 1, '', '')
        self.assertEqual(hc.journal_greeter_uids(), set())        # no line: grep exit 1
        hc.run = lambda argv, timeout=120: hc.subprocess.CompletedProcess(
            argv, 0, json.dumps({'MESSAGE': self.PAM.format(60600), '_UID': '0'}) + '\n', '')
        self.assertEqual(hc.journal_greeter_uids(), {60600})

    def test_greeter_files(self):
        hc.GREETER_OWNER = os.getuid()
        d = self.p('user-60580.slice.d')
        write(os.path.join(d, '50-CPUWeight.conf'), self.DROPIN.format('CPUWeight=100'), 0o644)
        write(os.path.join(d, '50-MemoryMin.conf'), self.DROPIN.format('MemoryMin=0'), 0o644)
        os.chmod(d, 0o755)              # Fedora users have umask 0002: folder group writable
        self.assertTrue(hc.greeter_file_ok(os.path.join(d, '50-CPUWeight.conf'), 'CPUWeight'))
        self.assertTrue(hc.greeter_dir_ok(d))
        self.assertFalse(hc.greeter_file_ok(os.path.join(d, '50-CPUWeight.conf'), 'IOWeight'))
        bad = os.path.join(d, '50-IOWeight.conf')
        for text in ('[Slice]\nIOWeight=100\nExecStart=/bin/sh\n', '[Slice]\nIOWeight=x\n',
                     '[Unit]\nIOWeight=100\n', '', '[Slice]\nIOWeight=100 200\n'):
            write(bad, text, 0o644)
            self.assertFalse(hc.greeter_file_ok(bad, 'IOWeight'), text)
            self.assertFalse(hc.greeter_dir_ok(d), text)
        write(bad, '[Service]\nIOWeight=100\n', 0o664)              # group writable
        self.assertFalse(hc.greeter_file_ok(bad, 'IOWeight'))
        os.chmod(bad, 0o644)
        self.assertTrue(hc.greeter_dir_ok(d))
        write(os.path.join(d, 'other.conf'), '[Slice]\nCPUWeight=100\n', 0o644)
        self.assertFalse(hc.greeter_dir_ok(d))                        # a file of another name
        os.unlink(os.path.join(d, 'other.conf'))
        os.symlink(bad, os.path.join(d, '50-MemoryLow.conf'))
        self.assertFalse(hc.greeter_dir_ok(d))                        # a link
        os.unlink(os.path.join(d, '50-MemoryLow.conf'))
        hc.GREETER_OWNER = os.getuid() + 1
        self.assertFalse(hc.greeter_dir_ok(d))                        # not the owner

    def test_check_aide_greeter_group(self):
        now = time.time()
        hc.journal_greeter_uids = lambda lines=None: {60580}
        hc.live_greeter_uids = lambda: set()
        hc.greeter_file_ok = lambda path, prop: True
        hc.greeter_dir_ok = lambda path: True
        new = [self.SC + 'user-60580.slice.d', self.SC + 'user-60580.slice.d/50-CPUWeight.conf',
               self.SC + 'user@60580.service.d', self.SC + 'user@60580.service.d/50-IOWeight.conf']
        report = {'added': {p: 'f' for p in new + [self.SC + 'user-60590.slice.d',
                                                     self.SC + 'user-1000.slice.d']},
                  'removed': {self.SC + 'user-60580.slice.d/50-MemoryLow.conf': 'f'},
                  'changed': {'/etc/ssh/sshd_config': 'f'}}
        self.aide_setup(report)
        c = hc.check_aide(now, 'dep1')
        self.assertEqual(c.summary, '8 changed since 2026-11-22T13:00+03:00: 3 other, '
                                    '5 GDM greeter, 0 from the OS update')
        self.assertEqual(c.items[:3], ['other ~ /etc/ssh/sshd_config',
                                       'other + ' + self.SC + 'user-1000.slice.d',
                                       'other + ' + self.SC + 'user-60590.slice.d'])
        self.assertTrue(all(i.startswith('greeter ') for i in c.items[3:]))
        # content not as logind writes it: other
        hc.greeter_file_ok = lambda path, prop: not path.endswith('IOWeight.conf')
        c = hc.check_aide(now, 'dep1')
        self.assertIn('4 other, 4 GDM greeter', c.summary)
        # no journal line, no greeter now: all other
        hc.journal_greeter_uids = lambda lines=None: set()
        c = hc.check_aide(now, 'dep1')
        self.assertIn('8 other, 0 GDM greeter', c.summary)
        hc.live_greeter_uids = lambda: {60590}
        self.assertIn('7 other, 1 GDM greeter', hc.check_aide(now, 'dep1').summary)

    def test_list(self):
        hc.booted_deployment = lambda cmdline=None: ('dep1', '')   # not this host's ostree=
        hc.journal_greeter_uids = lambda lines=None: set()
        hc.live_greeter_uids = lambda: set()
        self.aide_setup({'changed': {'/etc/shadow': 'f', '/etc/tab\tx': 'f'}})
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(hc.do_list(), 0)
        self.assertEqual(buf.getvalue(), 'other\t~\t/etc/shadow\nother\t~\t/etc/tab x\n')
        os.unlink(hc.AIDE_JSON)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hc.do_list(), 1)

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


class Accept(unittest.TestCase):
    """--accept (decision 2026-11-25): counts on the screen, the other items paged, the
    numbered list for the daily user, the code binds the accept to that list + database."""
    FNS = ('aidecheck_state', 'aide_update_quiet', 'ask_line', 'page', 'start_check',
           'booted_deployment', 'journal_greeter_uids', 'live_greeter_uids', 'usr_etc_changes')

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = self.dir.name
        self.saved = {k: getattr(hc, k) for k in dir(hc) if k.isupper()}
        self.saved_fn = {k: getattr(hc, k) for k in self.FNS}
        self.env = {k: os.environ.get(k) for k in ('SUDO_USER', 'SUDO_UID')}
        for k in self.env:
            os.environ.pop(k, None)
        hc.STATE = self.p('state')
        os.makedirs(hc.STATE)
        hc.ACCEPTED = self.p('state', 'accepted')
        hc.ACCEPTS = self.p('state', 'accepts')
        hc.RESULT = self.p('state', 'result')
        hc.AIDE_DB = self.p('aide.db.gz')
        hc.AIDE_NEW = self.p('aide.db.new.gz')
        hc.AIDE_JSON = self.p('aide.json')
        hc.OUTBOX = self.p('from-admin')
        write(hc.AIDE_DB, 'old db')
        write(hc.ACCEPTED, 'dep1 2026-11-25T18:40+03:00\n')
        write(hc.RESULT, 'check\taide\tpass\tno change\n')
        hc.booted_deployment = lambda cmdline=None: ('dep1', '')
        hc.journal_greeter_uids = lambda lines=None: set()
        hc.live_greeter_uids = lambda: set()
        hc.aidecheck_state = lambda: ('inactive', '500')
        hc.start_check = lambda: None
        self.report = {'changed': {'/etc/shadow': 'f', '/var/spool/cron/gtx': 'f'},
                       'added': {'/var/usrlocal/sbin/harden-ids': 'f'},
                       'details': {'/etc/shadow': {'sha512': {'old': 'a', 'new': 'b'},
                                                   'size': {'old': 1, 'new': 2}}}}
        self.updates = 0

        def update():
            self.updates += 1
            write(hc.AIDE_NEW, 'new db')
            write(hc.AIDE_JSON, json.dumps(self.report))
            return 5
        hc.aide_update_quiet = update
        self.pages = []
        hc.page = lambda text: self.pages.append(text)

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(hc, k, v)
        for k, v in self.saved_fn.items():
            setattr(hc, k, v)
        for k, v in self.env.items():
            if v is not None:
                os.environ[k] = v
        self.dir.cleanup()

    def p(self, *parts):
        return os.path.join(self.d, *parts)

    def listed(self):
        names = os.listdir(hc.OUTBOX)
        self.assertEqual(len(names), 1)
        return read(os.path.join(hc.OUTBOX, names[0]))

    def answers(self, *answers):
        """ask_line: Enter for the paging question; each "CODE" = the code of the list."""
        it = iter(answers)

        def ask(prompt):
            if not prompt.startswith('accept?'):
                return ''
            a = next(it)
            if a == 'CODE':
                text = self.listed() if os.path.isdir(hc.OUTBOX) else self.pages[-1]
                a = re.search(r'^code: ([0-9a-f]{8}) ', text, re.M).group(1)
            return a
        hc.ask_line = ask

    def accept(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = hc.do_accept()
        return rc, buf.getvalue()

    def test_build_list(self):
        grouped = [('update', '~', '/etc/ld.so.cache'), ('other', '~', '/etc/shadow'),
                   ('other', '+', '/var/spool/cron/gtx')]
        os.environ['SUDO_USER'] = 'gtx'
        text, code, other = hc.build_list(grouped, self.report, 'f' * 64, ['head line'])
        lines = text.splitlines()
        self.assertEqual(lines[0], 'head line')
        self.assertTrue(lines[1].startswith(f'code: {code}   '))
        import hashlib
        rest = '\n'.join([lines[0]] + lines[2:]) + '\n'
        self.assertEqual(code, hashlib.sha256(rest.encode()).hexdigest()[:hc.CODE_LEN])
        self.assertIn('changes: 3   other 2 | greeter 0 | update 1', text)
        # numbered over all groups, other first; attribute names only; no admin name
        self.assertEqual(other, ['1  ~ /etc/shadow   changed: sha512 size',
                                 '2  + /var/spool/cron/<admin>'])
        self.assertIn('3  ~ /etc/ld.so.cache', text)
        self.assertIn('== greeter (0): GDM login screen drop-ins\n  (none)', text)
        self.assertNotIn('gtx', text)
        self.assertNotIn("'old'", text)
        self.assertTrue(text.isascii())
        # another database or another list: another code
        self.assertNotEqual(hc.build_list(grouped, self.report, 'e' * 64, ['head line'])[1], code)
        self.assertNotEqual(hc.build_list(grouped[:2], self.report, 'f' * 64, ['head line'])[1], code)
        self.assertEqual(hc.build_list(grouped, self.report, 'f' * 64, ['head line'])[1], code)

    def test_hide_admin(self):
        self.assertEqual(hc.hide_admin('/var/spool/cron/gtx gtxy xgtx gtx.', 'gtx'),
                         '/var/spool/cron/<admin> gtxy xgtx gtx.')
        self.assertEqual(hc.hide_admin('/var/spool/cron/root', 'root'), '/var/spool/cron/root')
        self.assertEqual(hc.hide_admin('/a/x', ''), '/a/x')
        self.assertEqual(hc.hide_admin('/a/.*', '.*'), '/a/.*')        # not a user name

    def test_write_outbox(self):
        me = os.getuid()
        path = hc.write_outbox('a.txt', 'list\n', owner=me)
        self.assertEqual(path, os.path.join(hc.OUTBOX, 'a.txt'))
        self.assertEqual(read(path), 'list\n')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        st = os.stat(hc.OUTBOX)
        self.assertEqual((st.st_uid, st.st_mode & 0o777), (me, 0o755))
        with self.assertRaises(FileExistsError):                       # never over a file
            hc.write_outbox('a.txt', 'x\n', owner=me)
        if me != 0:                                                    # root's is allowed
            with self.assertRaises(ValueError):                        # someone else's
                hc.write_outbox('b.txt', 'x\n', owner=me + 1)
        os.chmod(hc.OUTBOX, 0o775)
        with self.assertRaises(ValueError):                            # group may write
            hc.write_outbox('c.txt', 'x\n', owner=me)
        link = self.p('link')
        os.symlink(hc.OUTBOX, link)
        with self.assertRaises(OSError):                               # a link
            hc.write_outbox('d.txt', 'x\n', path=link, owner=me)

    def test_keep_record(self):
        hc.KEEP_ACCEPTS = 3
        for i in range(5):
            hc.keep_record(f'aide-accept-2026112{i}-000000.txt', f'{i}\n')
        names = sorted(os.listdir(hc.ACCEPTS))
        self.assertEqual(names, [f'aide-accept-2026112{i}-000000.txt' for i in (2, 3, 4)])
        self.assertEqual(os.stat(os.path.join(hc.ACCEPTS, names[0])).st_mode & 0o777, 0o600)

    def test_accept_with_the_code(self):
        os.environ['SUDO_UID'] = str(os.getuid())
        os.environ['SUDO_USER'] = 'gtx'
        self.answers('', 'CODE')                    # Enter alone: asked again
        rc, out = self.accept()
        self.assertEqual(rc, 0, out)
        self.assertEqual(read(hc.AIDE_DB), 'new db')
        self.assertEqual(read(hc.AIDE_DB + '.prev'), 'old db')
        self.assertFalse(os.path.exists(hc.AIDE_NEW))
        self.assertIn('3 changes since the last accept (2026-11-25T18:40+03:00)', out)
        self.assertRegex(out, r'other +3 +not explained')
        text = self.listed()
        self.assertNotIn('gtx', text + out)
        self.assertIn('deployment: the same', text)
        # the other items paged on the screen, numbered as in the list
        self.assertEqual(len(self.pages), 1)
        self.assertIn('1  ~ /etc/shadow   changed: sha512 size', self.pages[0])
        self.assertIn('1  ~ /etc/shadow', text)
        kept = os.listdir(hc.ACCEPTS)
        self.assertEqual(read(os.path.join(hc.ACCEPTS, kept[0])), text)
        self.assertTrue(read(hc.ACCEPTED).startswith('dep1 '))

    def test_accept_wrong_code_or_no(self):
        os.environ['SUDO_UID'] = str(os.getuid())
        self.answers('12345678', 'abcdefab', 'ffffffff')
        rc, out = self.accept()
        self.assertEqual(rc, 1)
        self.assertIn('try 3 of 3', out)
        self.assertEqual(read(hc.AIDE_DB), 'old db')
        self.assertFalse(os.path.exists(hc.AIDE_NEW))
        self.assertFalse(os.path.exists(hc.ACCEPTS))
        for no in ('0', None):
            self.answers(no)
            self.assertEqual(self.accept()[0], 1)
            self.assertEqual(read(hc.AIDE_DB), 'old db')

    def test_accept_list_not_written(self):
        write(hc.OUTBOX, 'a file, not a folder')
        self.answers('CODE')                         # read from the page of the whole list
        rc, out = self.accept()
        self.assertEqual(rc, 0, out)
        self.assertIn('NOT written', out)
        self.assertIn('== update (', self.pages[0])

    def test_accept_refusals(self):
        os.environ['SUDO_UID'] = str(os.getuid())
        # the daily check is running: aide is not started
        hc.aidecheck_state = lambda: ('activating', '500')
        rc, out = self.accept()
        self.assertEqual((rc, self.updates), (1, 0))
        self.assertIn('running now', out)
        # the daily check ran during the update: its report may be the one read
        states = iter([('inactive', '500'), ('inactive', '900')])
        hc.aidecheck_state = lambda: next(states)
        rc, out = self.accept()
        self.assertEqual(rc, 1)
        self.assertIn('ran at the same time', out)
        self.assertFalse(os.path.exists(hc.AIDE_NEW))
        # the new database changed while the list was read
        hc.aidecheck_state = lambda: ('inactive', '500')
        self.answers('CODE')
        ask = hc.ask_line

        def ask_and_change(prompt):
            a = ask(prompt)
            if prompt.startswith('accept?'):
                write(hc.AIDE_NEW, 'another db')
            return a
        hc.ask_line = ask_and_change
        rc, out = self.accept()
        self.assertEqual(rc, 1)
        self.assertIn('changed while you read', out)
        self.assertEqual(read(hc.AIDE_DB), 'old db')
        # aide failed
        hc.aide_update_quiet = lambda: 17
        rc, out = self.accept()
        self.assertIn('aide --update failed (exit 17', out)


if __name__ == '__main__':
    unittest.main()
