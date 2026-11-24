#
# tests for the kargs section of harden-workstation.sh (stdlib + bash, no root, nothing
# outside a temp dir): IOMMU args by CPU vendor + iommu.passthrough=0, early PCI DMA off
# on EFI boots only, wrong settings stop.
#
#   python3 -I -m unittest discover -s tests -t .
#
# The script is sourced; add_karg is a shell function that only prints its args, the CPU
# info and the EFI folder are files in the temp dir.
#
import os
import re
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      'harden-workstation.sh')
ANSI = re.compile(r'\x1b\[[0-9;]*m')
BASE = ('initcall_blacklist=af_alg_init page_alloc.shuffle=1 rd.shell=0 rd.emergency=halt '
        'init_on_free=1 iommu.strict=1 hash_pointers=always proc_mem.force_override=never '
        'module.sig_enforce=1 debugfs=off bdev_allow_write_mounted=0')
# /proc/cpuinfo head (host 2026-11-24: Alder Lake-P; AMD line from a Ryzen)
INTEL = 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n'
AMD = 'processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 25\n'


class Kargs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = self.dir.name
        self.efi = os.path.join(self.d, 'efi')
        os.makedirs(self.efi)

    def tearDown(self):
        self.dir.cleanup()

    def bash(self, cpuinfo, body='sec_kargs'):
        p = os.path.join(self.d, 'cpuinfo')
        with open(p, 'w') as f:
            f.write(cpuinfo)
        code = (f'source "$1"; BACKUP_ROOT="{self.d}/backup"; APPLIED_LIST="{self.d}/applied"; '
                f'CPUINFO="{p}"; EFI_DIR="{self.efi}"\n'
                'add_karg() { echo "KARG $*"; }\n' + body)
        r = subprocess.run(['bash', '-c', code, 'test', SCRIPT], capture_output=True,
                           text=True, timeout=60,
                           env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': self.d})
        return r.returncode, ANSI.sub('', r.stdout + r.stderr)

    def karg_line(self, out):
        lines = [ln for ln in out.splitlines() if ln.startswith('KARG ')]
        self.assertEqual(len(lines), 1, out)
        return lines[0][5:].split()

    def test_intel(self):
        rc, out = self.bash(INTEL)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.karg_line(out), BASE.split() + [
            'intel_iommu=on', 'iommu.passthrough=0', 'efi=disable_early_pci_dma'])

    def test_amd(self):
        rc, out = self.bash(AMD)
        self.assertEqual(rc, 0, out)
        args = self.karg_line(out)
        self.assertIn('amd_iommu=force_isolation', args)
        self.assertNotIn('intel_iommu=on', args)
        self.assertIn('iommu.passthrough=0', args)

    def test_unknown_vendor_warns_keeps_passthrough(self):
        rc, out = self.bash('processor\t: 0\nvendor_id\t: HygonGenuine\n')
        self.assertEqual(rc, 0, out)
        self.assertIn("CPU vendor 'HygonGenuine': no IOMMU arg", out)
        args = self.karg_line(out)
        self.assertNotIn('intel_iommu=on', args)
        self.assertIn('iommu.passthrough=0', args)

    def test_not_efi_no_early_pci_arg(self):
        os.rmdir(self.efi)
        rc, out = self.bash(INTEL)
        self.assertEqual(rc, 0, out)
        self.assertNotIn('efi=disable_early_pci_dma', self.karg_line(out))
        self.assertIn('not an EFI boot', out)

    def test_both_off(self):
        rc, out = self.bash(INTEL, 'IOMMU=no; EARLY_PCI_DMA_OFF=no; sec_kargs')
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.karg_line(out), BASE.split())

    def test_nothing_wanted(self):
        rc, out = self.bash(INTEL, 'KERNEL_ARGS=(); IOMMU=no; EARLY_PCI_DMA_OFF=no; sec_kargs')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('KARG', out)
        self.assertIn('nothing to add', out)

    def test_wrong_values_stop(self):
        rc, out = self.bash(INTEL, 'IOMMU=on; sec_kargs')
        self.assertNotEqual(rc, 0)
        self.assertIn('IOMMU must be vendor or no', out)
        rc, out = self.bash(INTEL, 'EARLY_PCI_DMA_OFF=maybe; sec_kargs')
        self.assertNotEqual(rc, 0)
        self.assertIn('EARLY_PCI_DMA_OFF must be yes or no', out)


if __name__ == '__main__':
    unittest.main()
