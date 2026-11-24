"""tests/net-flows.sh --evaluate: saved nmap -oG results + counters against the flow table.

No scan here: fixture files as the lab VM writes them, then the verdict lines and exit code.
"""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "net-flows.sh")

BR, UP, VPN, GW = "192.168.122.1", "192.0.2.10", "203.0.113.2", "192.0.2.1"
H6 = "fe80::fc54:ff:fe00:1"


def gnmap(target, ports="", ignored="filtered (65534)", done=True):
    lines = [f"# Nmap 7.95 scan initiated Tue Nov 24 14:40:00 2026 as: nmap -n -Pn {target}",
             f"Host: {target} ()\tStatus: Up"]
    if ports:
        lines.append(f"Host: {target} ()\tPorts: {ports}\tIgnored State: {ignored}")
    if done:
        lines.append("# Nmap done at Tue Nov 24 14:40:33 2026 -- 1 IP address (1 host up) scanned in 33.10 seconds")
    return "\n".join(lines) + "\n"


COUNTERS = ["fwd_vm_lan", "fwd_vm_new", "out_leak", "out_lan", "out_dns", "out_split",
            "in_lan", "in_vpn", "fwd_in"]


class NetFlowsEvaluate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.files = {
            "meta": "\n".join([f"hbr={BR}", f"hup={UP}", f"hvpn={VPN}", f"gw={GW}", "quick=0", "inet=1",
                               "mode=enforce", "vmsrc=ok", "udpx=53,67,33487", f"h6={H6}"]) + "\n",
            "remote.done": "ok\n",
            "gw-ping.txt": "rc=1\n",
            "v6-self.txt": "fe80::5054:ff:fe00:2\n",
            "v6-responders.txt": "fe80::5054:ff:fe00:2\n",
            "inet.txt": "You are connected to Mullvad (server se-sto-wg-001). Your IP address is 198.51.100.7\n",
            "tcp-br.gnmap": gnmap(BR, "53/open/tcp//domain///"),
            "sport53-br.gnmap": gnmap(BR, "53/open/tcp//domain///", "filtered (999)"),
            "frag-br.gnmap": gnmap(BR, "53/open/tcp//domain///", "filtered (999)"),
            "ack-br.gnmap": gnmap(BR, "53/unfiltered/tcp//domain///", "filtered (999)"),
            "udp-br.gnmap": gnmap(BR, "53/open/udp//domain///, 67/open|filtered/udp//dhcps///", "closed (98)"),
            "udpx-br.gnmap": gnmap(BR, "53/open/udp//domain///, 67/open|filtered/udp//dhcps///, "
                                       "33487/closed/udp/////", "closed (0)"),
            "gw.gnmap": gnmap(GW, "53/filtered/tcp//domain///, 80/filtered/tcp//http///, "
                                  "443/filtered/tcp//https///", "filtered (0)"),
            "tcp6-1.gnmap": gnmap(f"{H6}%enp1s0", "", ""),
        }
        for n, t in (("up", UP), ("vpn", VPN)):
            self.files[f"tcp-{n}.gnmap"] = gnmap(t, "53/closed/tcp//domain///", "filtered (65534)")
            self.files[f"sport53-{n}.gnmap"] = gnmap(t)
            self.files[f"udp-{n}.gnmap"] = gnmap(t, "53/closed/udp//domain///", "closed (99)")
            self.files[f"udpx-{n}.gnmap"] = gnmap(t, "53/closed/udp//domain///, 67/open|filtered/udp//dhcps///, "
                                                     "33487/closed/udp/////", "closed (0)")
        self.before = {c: 100 for c in COUNTERS}
        self.after = dict(self.before, fwd_vm_lan=104, fwd_vm_new=112)

    def tearDown(self):
        self.tmp.cleanup()

    def run_eval(self):
        for name, text in self.files.items():
            with open(os.path.join(self.d, name), "w") as f:
                f.write(text)
        for label, vals in (("before", self.before), ("after", self.after)):
            with open(os.path.join(self.d, f"counters-{label}.txt"), "w") as f:
                f.writelines(f"{k} {v} {v * 60}\n" for k, v in vals.items())
        p = subprocess.run(["bash", SCRIPT, "--evaluate", self.d], capture_output=True, text=True,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def lines(self, out, verdict):
        return [ln for ln in out.splitlines() if ln.startswith(verdict)]

    def test_all_as_expected(self):
        rc, out = self.run_eval()
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.lines(out, "FAIL"), [], out)
        self.assertIn("server se-sto-wg-001", out)
        self.assertNotIn("198.51.100.7", out)
        self.assertNotIn("fe80::5054", out)          # interface ids carry the MAC

    def test_extra_open_port_fails(self):
        self.files["tcp-br.gnmap"] = gnmap(BR, "22/open/tcp//ssh///, 53/open/tcp//domain///", "filtered (65533)")
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("BR tcp " in ln and "22/tcp:open" in ln for ln in self.lines(out, "FAIL")), out)

    def test_dns_must_be_open(self):
        self.files["udp-br.gnmap"] = gnmap(BR, "53/closed/udp//domain///", "closed (99)")
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("BR udp top 100" in ln and "53/udp:closed" in ln for ln in self.lines(out, "FAIL")), out)

    def test_listener_reachable_on_uplink_fails(self):
        self.files["udpx-up.gnmap"] = gnmap(UP, "33487/open/udp/////", "closed (2)")
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("UP udp listeners" in ln for ln in self.lines(out, "FAIL")), out)

    def test_ack_unfiltered_fails(self):
        self.files["ack-br.gnmap"] = gnmap(BR, "53/unfiltered/tcp//domain///, 80/unfiltered/tcp//http///")
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("BR ack" in ln and "80/tcp" in ln for ln in self.lines(out, "FAIL")), out)

    def test_gateway_reached_fails(self):
        self.files["gw.gnmap"] = gnmap(GW, "80/closed/tcp//http///", "filtered (2)")
        self.files["gw-ping.txt"] = "rc=0\n"
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        fails = "\n".join(self.lines(out, "FAIL"))
        self.assertIn("GW tcp", fails)
        self.assertIn("GW ping", fails)

    def test_unfinished_scan_fails(self):
        self.files["tcp-vpn.gnmap"] = gnmap(VPN, done=False)
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("VPN tcp " in ln and "not finished" in ln for ln in self.lines(out, "FAIL")), out)

    def test_v6_neighbour_fails(self):
        self.files["v6-responders.txt"] = "fe80::5054:ff:fe00:2\nfe80::1\n"
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("v6 neighbours" in ln for ln in self.lines(out, "FAIL")), out)

    def test_counters(self):
        self.after.update(out_leak=101, fwd_vm_lan=100)
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        fails = "\n".join(self.lines(out, "FAIL"))
        self.assertIn("counter out_leak", fails)
        self.assertIn("counter fwd_vm_lan", fails)

    def test_observe_mode_fails(self):
        self.files["meta"] = self.files["meta"].replace("mode=enforce", "mode=observe")
        rc, out = self.run_eval()
        self.assertEqual(rc, 1)
        self.assertTrue(any("hostfw mode" in ln for ln in self.lines(out, "FAIL")), out)

    def test_hostile_text_is_not_run(self):
        # the VM's files are data: a line that looks like a command stays text
        marker = os.path.join(self.d, "pwned")
        self.files["tcp-br.gnmap"] += f"$(touch {marker})\n`touch {marker}`\n"
        self.files["meta"] += f"hbr=$(touch {marker})\n"
        self.run_eval()
        self.assertFalse(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
