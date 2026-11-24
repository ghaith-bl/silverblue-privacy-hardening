#
# tests for the sshd and services sections of harden-workstation.sh (stdlib + bash, no
# root, nothing outside a temp dir): SSH server fully off (generated local sockets masked,
# kernel arg systemd.ssh_auto=no), SSH_SERVER=on refused while no sshusers member has a
# key, printing masked with PRINTING=off.
#
#   python3 -I -m unittest discover -s tests -t .
#
# The script is sourced; systemctl, getent, groupadd, the kernel arg and mask helpers are
# replaced by shell functions that only print what they were asked.
#
import os
import re
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      'harden-workstation.sh')
ANSI = re.compile(r'\x1b\[[0-9;]*m')

STUBS = '''
add_karg()   { echo "KARG $*"; }
mask_units() { echo "MASK $*"; }
groupadd()   { echo "GROUPADD $*"; }
getent() {
  case "$1 $2" in
    "group sshusers") [[ -n ${GROUP_LINE:-} ]] && echo "$GROUP_LINE" || return 2 ;;
    "passwd alice")   echo "alice:x:1001:1001::$HOMES/alice:/bin/bash" ;;
    "passwd bob")     echo "bob:x:1002:1002::$HOMES/bob:/bin/bash" ;;
    *) return 2 ;;
  esac
}
'''


class Sections(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = self.dir.name
        self.bin = os.path.join(self.d, 'bin')
        os.makedirs(self.bin)
        sshd = os.path.join(self.bin, 'sshd')        # sshd -t: config ok (first on PATH)
        with open(sshd, 'w') as f:
            f.write('#!/bin/sh\nexit 0\n')
        os.chmod(sshd, 0o755)
        self.conf = os.path.join(self.d, 'sshd_config.d', '40-cis.conf')

    def tearDown(self):
        self.dir.cleanup()

    def bash(self, body, env=None):
        code = (f'source "$1"; BACKUP_ROOT="{self.d}/backup"; APPLIED_LIST="{self.d}/applied"; '
                f'SSHD_CONF="{self.conf}"; HOMES="{self.d}/home"; restorecon() {{ :; }}\n'
                f'{STUBS}\n{body}')
        e = {'PATH': f'{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': self.d}
        e.update(env or {})
        r = subprocess.run(['bash', '-c', code, 'test', SCRIPT], capture_output=True,
                           text=True, timeout=60, env=e)
        return r.returncode, ANSI.sub('', r.stdout + r.stderr)

    def key(self, user, text):
        p = os.path.join(self.d, 'home', user, '.ssh')
        os.makedirs(p)
        with open(os.path.join(p, 'authorized_keys'), 'w') as f:
            f.write(text)

    def test_off_masks_server_and_generated_sockets(self):
        rc, out = self.bash('SSH_SERVER=off; sec_sshd')
        self.assertEqual(rc, 0, out)
        self.assertIn('KARG systemd.ssh_auto=no', out)
        self.assertIn('MASK sshd-unix-local.socket sshd-vsock.socket', out)
        self.assertIn('MASK sshd.socket sshd.service', out)
        with open(self.conf) as f:
            conf = f.read().splitlines()
        for line in ('PasswordAuthentication no', 'KbdInteractiveAuthentication no',
                     'PermitRootLogin no', 'AllowGroups sshusers', 'MaxAuthTries 3',
                     'X11Forwarding no', 'AllowTcpForwarding no', 'AllowAgentForwarding no',
                     'DisableForwarding yes'):
            self.assertIn(line, conf)
        self.assertEqual(os.stat(self.conf).st_mode & 0o777, 0o600)

    def test_no_sshd_binary_no_socket_steps(self):
        # have_sshd replaced: the test host may have a real sshd (Fedora: /usr/bin/sshd)
        rc, out = self.bash('have_sshd() { return 1; }; SSH_SERVER=off; sec_sshd')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('KARG', out)
        self.assertIn('MASK sshd.socket sshd.service', out)

    def test_on_refused_without_a_key(self):
        self.key('alice', '# ssh-ed25519 AAAAC3 commented out\n')
        rc, out = self.bash('SSH_SERVER=on; GROUP_LINE="sshusers:x:980:alice"; sec_sshd')
        self.assertEqual(rc, 0, out)
        self.assertIn('MASK sshd.socket sshd.service', out)
        self.assertIn('SSH_SERVER=on refused', out)
        self.assertIn('KARG systemd.ssh_auto=no', out)       # local socket off either way

    def test_on_group_made_when_missing(self):
        rc, out = self.bash('SSH_SERVER=on; sec_sshd')
        self.assertEqual(rc, 0, out)
        self.assertIn('GROUPADD -r sshusers', out)
        self.assertIn('SSH_SERVER=on refused', out)

    def test_on_allowed_with_a_key(self):
        self.key('bob', 'no-pty,from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1 bob@lab\n')
        rc, out = self.bash('SSH_SERVER=on; GROUP_LINE="sshusers:x:980:alice,bob"; sec_sshd')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('MASK sshd.socket', out)
        self.assertIn('SSH server allowed for sshusers (keys: bob)', out)

    def test_printing_masked_when_off(self):
        rc, out = self.bash('unit_exists() { return 1; }; PRINTING=off; DISABLE_AVAHI=no; '
                            'DISABLE_BLUETOOTH=no; sec_services')
        self.assertEqual(rc, 0, out)
        self.assertIn('MASK cups-browsed.service cups.path cups.socket cups.service', out)

    def test_printing_left_when_on(self):
        rc, out = self.bash('unit_exists() { return 1; }; PRINTING=on; DISABLE_AVAHI=no; '
                            'DISABLE_BLUETOOTH=no; sec_services')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('cups', out)


if __name__ == '__main__':
    unittest.main()
