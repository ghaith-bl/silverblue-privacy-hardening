#
# tests for section ids (stdlib, no root, no network): ids/harden-ids (network part of
# Suricata's config), ids/local.rules (form, variables), ids/disable.conf (which ET
# categories stay), ids/suricata.yaml (privacy settings), the made-up capture of
# tests/ids_pcap.py; with suricata installed also tests/ids-rules.sh (rules against it).
#
#   python3 -I -m unittest discover -s tests -t .
#
import contextlib
import importlib.machinery
import io
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDS = os.path.join(ROOT, 'ids')


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


HI = load('harden_ids', os.path.join(IDS, 'harden-ids'))
PCAP = load('ids_pcap', os.path.join(ROOT, 'tests', 'ids_pcap.py'))

ROUTES = [{'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'wlx0', 'protocol': 'dhcp'},
          {'dst': 'default', 'dev': 'wg0-mullvad'}]
LINKS = [
    {'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8,
                                    'scope': 'host'}]},
    {'ifname': 'wlx0', 'addr_info': [{'family': 'inet', 'local': '192.0.2.10', 'prefixlen': 24,
                                      'scope': 'global'}]},
    {'ifname': 'virbr0', 'addr_info': [{'family': 'inet', 'local': '192.168.122.1',
                                        'prefixlen': 24, 'scope': 'global'}]},
    {'ifname': 'wg0-mullvad', 'addr_info': [{'family': 'inet', 'local': '203.0.113.2',
                                             'prefixlen': 32, 'scope': 'global'}]},
]
NAMES = ['lo', 'wlx0', 'virbr0', 'wg0-mullvad', 'virbr-browse']
CONF = {'vm_bridges': ['virbr0', 'virbr-browse'], 'browse_net': '192.168.123.0/24'}


def groups(text):
    """address / port groups of a rendered net.yaml"""
    return dict(re.findall(r'^    ([A-Z_]+): (.+)$', text, re.M))


class NetPart(unittest.TestCase):
    def test_gather_uplink_bridges_tunnel_left_out(self):
        st = HI.gather(ROUTES, LINKS, NAMES, CONF, ['203.0.113.20/32'])
        self.assertEqual(st['uplinks'], ['wlx0'])
        self.assertEqual(st['laptop'], ['192.0.2.10/32'])
        self.assertEqual(st['lan'], ['192.0.2.0/24'])
        self.assertEqual(st['gateways'], ['192.0.2.1/32'])
        # virbr-browse exists but has no address yet: watched, VM_GW without it
        self.assertEqual(st['bridges'], ['virbr0', 'virbr-browse'])
        self.assertEqual(st['bridges_without_address'], ['virbr-browse'])
        self.assertEqual(st['vm_gw'], ['192.168.122.1/32'])
        # browsevm's subnet is fixed: in VM_NET bridge up or not
        self.assertEqual(st['vm_net'], ['192.168.123.0/24', '192.168.122.0/24'])

    def test_bridge_never_uplink_and_missing_bridge_not_watched(self):
        routes = [{'dst': 'default', 'gateway': '192.168.122.2', 'dev': 'virbr0'}]
        st = HI.gather(routes, LINKS, ['lo', 'virbr0'], CONF, [])
        self.assertEqual(st['uplinks'], [])
        self.assertEqual(st['bridges'], ['virbr0'])
        text = HI.render(st)
        g = groups(text)
        self.assertEqual(g['LAN'], '"[%s]"' % HI.UNSET)
        self.assertEqual(g['VPN_API'], '"[%s]"' % HI.UNSET)
        self.assertNotIn('virbr-browse', text)

    def test_render_groups_never_empty_and_cluster_ids_differ(self):
        st = HI.gather(ROUTES, LINKS, NAMES, CONF, [])
        text = HI.render(st)
        g = groups(text)
        for k in ('HOME_NET', 'LAPTOP_LAN', 'LAN', 'GATEWAY', 'VM_NET', 'VM_GW', 'BROWSE_NET',
                  'VPN_API', 'PRIVATE_NET'):
            self.assertRegex(g[k], r'^"\[[0-9./,]+\]"$', k)
        self.assertEqual(g['HOME_NET'], '"[192.0.2.10/32,192.168.123.0/24,192.168.122.0/24]"')
        self.assertEqual(g['EXTERNAL_NET'], '"!$HOME_NET"')
        ids = re.findall(r'cluster-id: (\d+)', text)
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual(text.count('disable-promisc: yes'), 3)
        self.assertNotIn('wg0', text)
        self.assertTrue(text.startswith('%YAML 1.1\n---\n'))

    def test_nothing_to_watch(self):
        st = HI.gather([], [], [], {'vm_bridges': [], 'browse_net': ''}, [])
        text = HI.render(st)
        self.assertIn('af-packet: []', text)
        self.assertEqual(groups(text)['VM_NET'], '"[%s]"' % HI.UNSET)

    def test_unset_lies_inside_private_net(self):
        # rules cut BROWSE_NET out of PRIVATE_NET: Suricata refuses a negation outside it
        import ipaddress
        unset = ipaddress.ip_network(HI.UNSET)
        self.assertTrue(any(unset.subnet_of(ipaddress.ip_network(n)) for n in HI.PRIVATE_NET))

    def test_conf_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'ids.conf')
            with open(p, 'w') as f:
                f.write('# x\nvm_bridges = virbr0 bad/name virbr-browse\nbrowse_net = 192.168.123.0/24\n')
            self.assertEqual(HI.read_conf(p), CONF)
            q = os.path.join(d, 'local.conf')
            with open(q, 'w') as f:
                f.write('vpn_dns4 203.0.113.53\nvpn_api4 203.0.113.20,203.0.113.21 # api\n')
            self.assertEqual(HI.read_vpn_api(q), ['203.0.113.20/32', '203.0.113.21/32'])
            with open(q, 'w') as f:
                f.write('vpn_api4 not-an-address\n')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(HI.read_vpn_api(q), [])
            self.assertIn('VPN_API unset', out.getvalue())
            self.assertEqual(HI.read_vpn_api(os.path.join(d, 'missing')), [])

    def test_write_if_changed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'net.yaml')
            if os.geteuid() != 0:
                orig = os.chown
                os.chown = lambda *a: None
            try:
                self.assertTrue(HI.write_if_changed(p, 'a\n'))
                self.assertFalse(HI.write_if_changed(p, 'a\n'))
                self.assertTrue(HI.write_if_changed(p, 'b\n'))
            finally:
                if os.geteuid() != 0:
                    os.chown = orig
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), '0o640')
            self.assertEqual(os.listdir(d), ['net.yaml'])

    def test_written_file_gets_the_policy_label(self):
        """restorecon -F after each write (sudo leaves unconfined_u, services system_u:
        AIDE compares the whole label); not when unchanged, not without SELinux."""
        with tempfile.TemporaryDirectory() as d:
            calls = os.path.join(d, 'calls')
            fake = os.path.join(d, 'restorecon')
            with open(fake, 'w') as f:
                f.write('#!/bin/sh\necho "$@" >> %s\n' % calls)
            os.chmod(fake, 0o755)
            enforce = os.path.join(d, 'enforce')
            p = os.path.join(d, 'net.yaml')
            saved = HI.RESTORECON, HI.SELINUX_ENFORCE, os.chown
            HI.RESTORECON, HI.SELINUX_ENFORCE = fake, enforce
            if os.geteuid() != 0:
                os.chown = lambda *a: None
            try:
                self.assertTrue(HI.write_if_changed(p, 'a\n'))      # no SELinux: no call
                self.assertFalse(os.path.exists(calls))
                open(enforce, 'w').close()
                self.assertTrue(HI.write_if_changed(p, 'b\n'))
                self.assertFalse(HI.write_if_changed(p, 'b\n'))     # unchanged: no call
                with open(calls) as f:
                    self.assertEqual(f.read(), '-F %s\n' % p)
                with open(fake, 'w') as f:
                    f.write('#!/bin/sh\necho denied >&2\nexit 1\n')
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertTrue(HI.write_if_changed(p, 'c\n'))  # fails: a warning only
                self.assertIn('WARNING: restorecon %s: exit 1 denied' % p, out.getvalue())
            finally:
                HI.RESTORECON, HI.SELINUX_ENFORCE, os.chown = saved

    def sync(self, changed, active, watch=True, enabled=True):
        """cmd_sync with a made-up network: (exit code, systemctl actions, output)."""
        state = HI.gather(ROUTES, LINKS, NAMES, CONF, []) if watch else \
            HI.gather([], [], [], {'vm_bridges': [], 'browse_net': ''}, [])
        acts = []

        def systemctl(*args):
            if args[0] in ('is-enabled', 'is-active'):
                ok = enabled if args[0] == 'is-enabled' else active
                return subprocess.CompletedProcess(args, 0 if ok else 3, '', '')
            acts.append(args[0])
            return subprocess.CompletedProcess(args, 0, '', '')
        saved = HI.read_conf, HI.current, HI.write_if_changed, HI.systemctl
        HI.read_conf, HI.current = (lambda: CONF), (lambda conf: state)
        HI.write_if_changed, HI.systemctl = (lambda p, t: changed), systemctl
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = HI.cmd_sync(['sync'])
        finally:
            HI.read_conf, HI.current, HI.write_if_changed, HI.systemctl = saved
        return rc, acts, out.getvalue()

    def test_sync_offline_stops_not_restarts(self):
        rc, acts, out = self.sync(changed=True, active=True, watch=False)
        self.assertEqual((rc, acts), (1, ['stop']))
        self.assertIn('suricata.service stopped', out)
        self.assertNotIn('restarted', out)
        self.assertEqual(self.sync(changed=False, active=False, watch=False)[:2], (1, []))
        self.assertEqual(self.sync(changed=True, active=True)[:2], (0, ['restart']))
        self.assertEqual(self.sync(changed=False, active=False)[:2], (0, ['start']))
        self.assertEqual(self.sync(changed=False, active=True)[:2], (0, []))
        self.assertEqual(self.sync(changed=True, active=True, enabled=False)[:2], (0, []))


class LocalRules(unittest.TestCase):
    def rules(self):
        with open(os.path.join(IDS, 'local.rules')) as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]

    def test_form(self):
        sids = []
        for r in self.rules():
            self.assertRegex(r, r'^alert (tcp|udp|icmp|ip|dns|http|tls) ', r)
            self.assertRegex(r, r'msg:"HARDEN [^"]+";', r)
            self.assertRegex(r, r'metadata:harden (scan|probe|leak|vm_lan|vm_probe);', r)
            self.assertRegex(r, r'priority:[12];', r)
            self.assertRegex(r, r'rev:\d+;\)$', r)
            self.assertIn('threshold:', r)
            sid = int(re.search(r'sid:(\d+);', r).group(1))
            self.assertTrue(9200001 <= sid <= 9200099, sid)
            sids.append(sid)
        self.assertEqual(len(sids), len(set(sids)))

    def test_variables_defined_by_net_yaml(self):
        g = groups(HI.render(HI.gather(ROUTES, LINKS, NAMES, CONF, [])))
        for r in self.rules():
            for v in re.findall(r'\$([A-Z_]+)', r):
                self.assertIn(v, g, r)

    def test_no_negation_outside_its_group(self):
        # [$PRIVATE_NET,!$X]: X must be a group that always lies inside PRIVATE_NET
        for r in self.rules():
            for grp in re.findall(r'\[([^\]]*![^\]]*)\]', r):
                parts = grp.split(',')
                pos = [p for p in parts if not p.startswith('!')]
                if pos:
                    self.assertEqual(pos, ['$PRIVATE_NET'], r)
                    self.assertEqual([p for p in parts if p.startswith('!')], ['!$BROWSE_NET'], r)


class DisableConf(unittest.TestCase):
    def matcher(self):
        with open(os.path.join(IDS, 'disable.conf')) as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('re:'))
        # as suricata-update: re.compile(<after "re:">, re.I).search(rule)
        return re.compile(lines[0].split(':', 1)[1].strip(), re.I)

    def test_kept_and_disabled(self):
        rx = self.matcher()
        rule = 'alert ip any any -> any any (msg:"%s"; sid:1; rev:1;)'
        kept = ['ET SCAN Nmap', 'ET MALWARE x', 'ET MOBILE_MALWARE x', 'ET EXPLOIT x',
                'ET EXPLOIT_KIT x', 'ET DNS x', 'ET COINMINER x', 'ET WORM x',
                'ET ATTACK_RESPONSE x', 'ET CNC Shadowserver Reported CnC Server']
        off = ['ET INFO x', 'ET POLICY x', 'ET HUNTING x', 'ET SCANNER x', 'ET DNSX x',
               'SURICATA STREAM x', 'ET WEB_CLIENT x', 'GPL ATTACK_RESPONSE x']
        for m in kept:
            self.assertIsNone(rx.search(rule % m), m)
        for m in off:
            self.assertIsNotNone(rx.search(rule % m), m)


class SuricataYaml(unittest.TestCase):
    def text(self):
        with open(os.path.join(IDS, 'suricata.yaml')) as f:
            return f.read()

    def test_privacy_and_form(self):
        t = self.text()
        self.assertTrue(t.startswith('%YAML 1.1\n---\n'))
        self.assertIn('\ninclude: net.yaml\n', t)
        for k in ('payload', 'payload-printable', 'packet', 'http-body', 'http-body-printable',
                  'tagged-packets'):
            self.assertRegex(t, r'\n {12}%s: no\n' % k, k)
        self.assertIn('app-layer: false', t)
        self.assertIn('max-dump: 0', t)
        self.assertRegex(t, r'unix-command:\n  enabled: no')
        # only alert / anomaly / dhcp records
        types = re.findall(r'^        - ([a-z-]+):', t, re.M)
        self.assertEqual(types, ['alert', 'anomaly', 'dhcp'])
        self.assertIn('  - /etc/suricata/harden-ids/local.rules', t)
        self.assertNotIn('af-packet', re.sub(r'#.*', '', t))
        self.assertNotIn('vars:', t)

    def test_parses(self):
        try:
            import yaml  # noqa: F401 (optional: python3-pyyaml comes with suricata)
        except ImportError:
            self.skipTest('no PyYAML')
        d = yaml.safe_load(self.text())
        self.assertEqual(d['outputs'][0]['eve-log']['types'][0]['alert']['metadata']['app-layer'],
                         False)
        st = HI.gather(ROUTES, LINKS, NAMES, CONF, [])
        n = yaml.safe_load(HI.render(st))
        self.assertEqual([x['interface'] for x in n['af-packet']], ['wlx0', 'virbr0', 'virbr-browse'])


class Units(unittest.TestCase):
    def test_files(self):
        self.assertTrue(os.access(os.path.join(IDS, 'harden-ids'), os.X_OK))
        self.assertTrue(os.access(os.path.join(IDS, '91-harden-ids'), os.X_OK))
        r = subprocess.run(['sh', '-n', os.path.join(IDS, '91-harden-ids')])
        self.assertEqual(r.returncode, 0)
        with open(os.path.join(IDS, 'suricata-harden-ids.conf')) as f:
            d = f.read()
        # the package's ExecStart / options cleared before ours; never the tunnel, never IPS
        self.assertRegex(d, r'\nExecStart=\nExecStart=/usr/bin/suricata -c /etc/suricata/harden-ids/suricata.yaml --af-packet ')
        self.assertIn('\nExecCondition=+/usr/local/sbin/harden-ids sync --no-restart\n', d)
        self.assertNotIn('-q ', d)
        with open(os.path.join(IDS, 'harden-ids-update.service')) as f:
            u = f.read()
        self.assertIn('\nUser=suricata\n', u)
        self.assertIn('\nCapabilityBoundingSet=\n', u)


class Capture(unittest.TestCase):
    def test_checksums(self):
        p = PCAP.udp('192.0.2.10', 40000, '198.51.100.53', 53, PCAP.dns_query('example.org'))
        ip = p[14:34]
        self.assertEqual(PCAP.csum(ip), 0)
        seg = p[34:]
        pseudo = PCAP.ip4('192.0.2.10') + PCAP.ip4('198.51.100.53') + struct.pack('!BBH', 0, 17, len(seg))
        self.assertEqual(PCAP.csum(pseudo + seg), 0)
        t = PCAP.tcp('192.0.2.10', 1, '198.51.100.7', 80, 'PA', 5, 6, b'GET / HTTP/1.1\r\n\r\n')
        seg = t[34:]
        pseudo = PCAP.ip4('192.0.2.10') + PCAP.ip4('198.51.100.7') + struct.pack('!BBH', 0, 6, len(seg))
        self.assertEqual(PCAP.csum(pseudo + seg), 0)

    def test_build_and_check(self):
        with tempfile.TemporaryDirectory() as d:
            n, e = PCAP.build(d)
            self.assertGreater(n, 50)
            with open(os.path.join(d, 'capture.pcap'), 'rb') as f:
                self.assertEqual(struct.unpack('<I', f.read(4))[0], 0xa1b2c3d4)
            # no eve.json: every "min" check fails, every "max" check passes
            with open(os.path.join(d, 'expected.json')) as f:
                exp = json.load(f)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(PCAP.check(d), 1)
            self.assertIn('%d of %d checks passed' % (sum('max' in x for x in exp), e),
                          out.getvalue())
            self.assertEqual(len(exp), e)

    @unittest.skipUnless(shutil.which('suricata'), 'no suricata here')
    def test_rules_against_suricata(self):
        r = subprocess.run(['bash', os.path.join(ROOT, 'tests', 'ids-rules.sh')],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class Section(unittest.TestCase):
    def test_in_sections_and_not_installed(self):
        script = os.path.join(ROOT, 'harden-workstation.sh')
        code = ('source "$1"; rpm() { return 1; }; CHANGE_LOG=$(mktemp); CUR_SECTION=ids; '
                'sec_ids; echo "rc=$? changes=$(section_changes)"; '
                'echo " ${SECTIONS[*]} " | grep -q " ids " && echo listed')
        r = subprocess.run(['bash', '-c', code, 'test', script], capture_output=True, text=True,
                           timeout=60, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
        out = r.stdout + r.stderr
        self.assertIn('suricata not installed', out)
        self.assertIn('rc=0 changes=0', out)
        self.assertIn('listed', out)


if __name__ == '__main__':
    unittest.main()
