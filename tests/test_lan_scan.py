"""tools/lan-scan.py (step 11b2b-1): refusals, ids, consent list, nmap XML, report.

Addresses: made up (10.9.8.0/24, .private-info-allow) and RFC 5737; MACs: RFC 7042
documentation MACs, the random (locally administered) ones built at run time.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import ipaddress
import json
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


LS = load("lan_scan", os.path.join(ROOT, "tools", "lan-scan.py"))

NET = "10.9.8.0/24"
GW, ME, PHONE, TV = "10.9.8.1", "10.9.8.23", "10.9.8.40", "10.9.8.41"
DOC = "00:00:5e:00:53:"                       # RFC 7042 documentation MACs
GW_MAC, TV_MAC = DOC + "01", DOC + "02"
RND_MAC = ":".join(["02", "00", "00", "00", "00", "07"])     # locally administered
KEY = b"k" * 32


def hexip(ip):
    """/proc/net/route field: the address as a host-order u32."""
    return f"{struct.unpack('=I', ipaddress.IPv4Address(ip).packed)[0]:08X}"


def route(*rows):
    head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    return head + "".join(f"{d}\t{hexip(dst)}\t{hexip(gw)}\t{fl:04X}\t0\t0\t{m}\t"
                          f"{hexip(ipaddress.IPv4Network(f'0.0.0.0/{plen}').netmask)}"
                          "\t0\t0\t0\n" for d, dst, gw, fl, m, plen in rows)


ROUTES = route(("wg0-mullvad", "0.0.0.0", "0.0.0.0", 1, 0, 0),     # last: prefix length
               ("wlo1", "0.0.0.0", GW, 3, 600, 0),
               ("wlo1", "10.9.8.0", "0.0.0.0", 1, 600, 24),
               ("wlo1", "10.9.0.0", "0.0.0.0", 1, 600, 16))
ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
       f"{GW}         0x1         0x2         {GW_MAC.upper()}     *        wlo1\n"
       f"{PHONE}        0x1         0x0         00:00:00:00:00:00     *        wlo1\n")


def xml(hosts):
    """nmap -sn -oX output (the parts read)."""
    out = ['<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sn">']
    for ip, mac, vendor, state in hosts:
        out.append(f'<host><status state="{state}" reason="arp-response"/>'
                   f'<address addr="{ip}" addrtype="ipv4"/>')
        if mac:
            v = f' vendor="{vendor}"' if vendor else ""
            out.append(f'<address addr="{mac.upper()}" addrtype="mac"{v}/>')
        out.append("<hostnames/></host>")
    out.append("</nmaprun>")
    return "".join(out)


SCAN = xml([(GW, GW_MAC, "ICANN, IANA Department", "up"), (ME, None, "", "up"),
            (PHONE, RND_MAC, "", "up"), (TV, TV_MAC, "Some Maker\u00e9", "up"),
            ("10.9.8.99", DOC + "09", "x", "down")])


class NetworkTest(unittest.TestCase):
    def test_uplink(self):
        dev, gw, subnet = LS.uplink(ROUTES)
        self.assertEqual((dev, gw, str(subnet)), ("wlo1", GW, NET))
        self.assertIsNone(LS.uplink(route(("wg0-mullvad", "0.0.0.0", "10.9.8.1", 3, 0, 0))))

    def test_arp(self):
        self.assertEqual(LS.arp_mac(ARP, GW, "wlo1"), GW_MAC)
        self.assertIsNone(LS.arp_mac(ARP, PHONE, "wlo1"))          # incomplete
        self.assertIsNone(LS.arp_mac(ARP, GW, "enp44s0"))

    def test_refusals(self):
        up = LS.uplink(ROUTES)
        self.assertEqual(LS.refuse(up, True, True, GW_MAC), "")
        self.assertIn("enforce", LS.refuse(up, False, True, GW_MAC))
        self.assertIn("Mullvad", LS.refuse(up, True, False, GW_MAC))
        self.assertIn("no IPv4 default route", LS.refuse(None, True, True, None))
        self.assertIn("ARP entry", LS.refuse(up, True, True, None))
        big = ("wlo1", GW, ipaddress.IPv4Network("10.9.0.0/21"))
        self.assertIn("larger than a /22", LS.refuse(big, True, True, GW_MAC))
        ok22 = ("wlo1", GW, ipaddress.IPv4Network("10.9.8.0/22"))
        self.assertEqual(LS.refuse(ok22, True, True, GW_MAC), "")
        for net in ("100.64.0.0/10", "198.51.100.0/24"):
            pub = ("wlo1", GW, ipaddress.IPv4Network(net))
            self.assertIn("not a private", LS.refuse(pub, True, True, GW_MAC))
        self.assertIn("tunnel or a bridge", LS.refuse(("virbr0",) + up[1:], True, True, GW_MAC))

    def test_ids(self):
        a = LS.net_id(KEY, GW_MAC, NET)
        self.assertRegex(a, r"^[0-9a-f]{64}$")
        self.assertNotEqual(a, LS.net_id(KEY, TV_MAC, NET))
        self.assertNotEqual(a, LS.net_id(KEY, GW_MAC, "10.9.8.0/23"))
        self.assertNotEqual(a, LS.net_id(b"x" * 32, GW_MAC, NET))
        self.assertEqual(LS.dev_id(KEY, GW_MAC.upper()), LS.dev_id(KEY, GW_MAC))
        self.assertTrue(LS.random_mac(RND_MAC))
        self.assertFalse(LS.random_mac(GW_MAC))

    def test_argv(self):
        argv = LS.discover_argv("wlo1", ipaddress.IPv4Network(NET), "/x.xml")
        self.assertEqual(argv, [LS.NMAP, "-sn", "-PR", "-n", "-e", "wlo1", "--max-retries", "2",
                                "-oX", "/x.xml", NET])


class FilesTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.d = d.name

    def test_key_made_once_root_only(self):
        p = os.path.join(self.d, "k")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            k = LS.load_key(p)
        self.assertIn("made (root 0600, random)", out.getvalue())
        self.assertEqual(len(k), 32)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual(LS.load_key(p), k)
        os.chmod(p, 0o644)
        with self.assertRaises(ValueError):
            LS.load_key(p)

    def test_known(self):
        known = {"a" * 64: "2026-11-27"}
        text = LS.render_known(known)
        self.assertEqual(LS.parse_known(text + "junk\nab 1\n"), known)
        self.assertEqual(LS.parse_known(None), {})

    def test_ask(self):
        tty, lines = os.path.join(self.d, "tty"), []
        for answer, want in (("1\n", "1"), (" 2 \n", "2"), ("", "0"), ("y\nyes\n9\n", "0")):
            with open(tty, "w") as f:
                f.write(answer)
            self.assertEqual(LS.ask(tty, out=lines.append), want, answer)
        self.assertTrue(all(line.endswith(":") or "is not" in line for line in lines))


class ReportTest(unittest.TestCase):
    def test_parse_up_hosts_only(self):
        hosts = LS.parse_xml(SCAN)
        self.assertEqual([h["ip"] for h in hosts], [GW, ME, PHONE, TV])
        self.assertEqual(hosts[1]["mac"], None)
        self.assertEqual(hosts[3]["vendor"], "Some Maker?")       # printable ASCII only

    def test_first_scan_then_new_and_gone(self):
        lines, keep = LS.report(LS.parse_xml(SCAN), KEY, GW, {}, "2026-11-27")
        text = "\n".join(lines)
        self.assertIn(f"{GW:<16} router  ICANN, IANA Department", text)
        self.assertIn(f"{ME:<16} this laptop", text)
        self.assertIn(f"{PHONE:<16}         random MAC", text)
        self.assertEqual(text.count("first scan"), 3)
        for mac in (GW_MAC, TV_MAC, RND_MAC, GW_MAC.upper()):
            self.assertNotIn(mac, text)
            self.assertNotIn(mac, json.dumps(keep))
        self.assertEqual(len(keep), 3)
        # next scan: the TV gone, a new device
        new_mac = DOC + "05"
        scan2 = xml([(GW, GW_MAC, "ICANN, IANA Department", "up"), (PHONE, RND_MAC, "", "up"),
                     ("10.9.8.50", new_mac, "Other", "up")])
        lines, keep2 = LS.report(LS.parse_xml(scan2), KEY, GW, keep, "2026-11-28")
        text = "\n".join(lines)
        self.assertIn("known since 2026-11-27", text)
        self.assertTrue(any(line.endswith("NEW") and "10.9.8.50" in line for line in lines))
        self.assertIn(f"{TV:<16} gone    Some Maker", text)
        self.assertEqual(len(keep2), 4)
        self.assertFalse(keep2[LS.dev_id(KEY, TV_MAC)]["up"])
        # third scan: the TV still away = not "gone" again; back later = known
        lines, keep3 = LS.report(LS.parse_xml(scan2), KEY, GW, keep2, "2026-11-29")
        self.assertNotIn("gone", "\n".join(lines))
        lines, _ = LS.report(LS.parse_xml(SCAN), KEY, GW, keep3, "2026-11-30")
        self.assertIn(f"{TV:<16}         Some Maker?                  known since 2026-11-27",
                      "\n".join(lines))


class MainTest(unittest.TestCase):
    def test_usage_and_root(self):
        self.assertEqual(LS.main(["x"]), 2)
        if os.geteuid() != 0:
            self.assertEqual(LS.main([]), 2)

    def test_main_with_fake_tools(self):
        """The whole run as root with fake nmap / nft / mullvad and a fake network:
        2 = this time only keeps nothing, 1 = consent kept, files root-only, no MAC."""
        if os.geteuid() != 0:
            self.skipTest("root only (CI: the root run)")
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        xml_text = SCAN.replace("\u00e9", "")
        tools = {"nmap": "out=; p=; for a; do [ \"$p\" = -oX ] && out=$a; p=$a; done\n"
                         f"printf '%s' '{xml_text}' > \"$out\"\n"
                         f"echo 'MAC Address: {TV_MAC.upper()}' >&2\n",
                 "nft": "echo 'chain enforce { reject }'\n",
                 "mullvad": "echo 'Connected to relay'\n"}
        for name, body in tools.items():
            with open(os.path.join(d, name), "w") as f:
                f.write("#!/bin/sh\n" + body)
            os.chmod(os.path.join(d, name), 0o755)
        with open(os.path.join(d, "route"), "w") as f:
            f.write(ROUTES)
        with open(os.path.join(d, "arp"), "w") as f:
            f.write(ARP)
        old = {k: getattr(LS, k) for k in ("ROUTE", "ARP", "NMAP", "NFT", "MULLVAD", "ETC",
                                           "KEY", "KNOWN", "VAR", "ask")}
        self.addCleanup(lambda: [setattr(LS, k, v) for k, v in old.items()])
        LS.ROUTE, LS.ARP = os.path.join(d, "route"), os.path.join(d, "arp")
        LS.NMAP, LS.NFT, LS.MULLVAD = (os.path.join(d, n) for n in ("nmap", "nft", "mullvad"))
        LS.ETC = os.path.join(d, "etc")
        LS.KEY, LS.KNOWN, LS.VAR = LS.ETC + "/k", LS.ETC + "/known", os.path.join(d, "var")
        for answer in ("2", "1", "1"):
            LS.ask = lambda answer=answer: answer
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(LS.main([]), 0, out.getvalue())
            text = out.getvalue()
            for mac in (GW_MAC, TV_MAC, RND_MAC, TV_MAC.upper()):
                self.assertNotIn(mac, text)
            if answer == "2":
                self.assertIn("this time only: nothing kept", text)
                self.assertFalse(os.path.exists(LS.VAR))
                self.assertFalse(os.path.exists(LS.KNOWN))
        self.assertIn("owner's consent: given", text)
        [netdir] = os.listdir(LS.VAR)
        for p in [LS.KEY, LS.KNOWN] + [os.path.join(LS.VAR, netdir, n)
                                        for n in os.listdir(os.path.join(LS.VAR, netdir))]:
            self.assertEqual(os.stat(p).st_mode & 0o077, 0, p)

    def test_shebang_and_mode(self):
        p = os.path.join(ROOT, "tools", "lan-scan.py")
        with open(p) as f:
            self.assertEqual(f.readline(), "#!/usr/bin/python3 -IB\n")
        self.assertTrue(os.access(p, os.X_OK))


if __name__ == "__main__":
    sys.exit(unittest.main())
