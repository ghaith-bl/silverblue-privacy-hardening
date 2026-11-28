#!/usr/bin/python3 -IB
"""tools/lan-scan.py - which devices are on the network this laptop is on (step 11b2b-1).

  sudo tools/lan-scan.py        find the devices (ARP), report them, compare with the last scan

Part 1 of the LAN device scan (design 2026-11-24, docs/lan-scan.md): discovery only.
nmap's ARP ping (`nmap -sn -PR -n -e <uplink>`) on the uplink's subnet. ARP is not IP:
hostfw and Mullvad's kill switch (both nftables inet tables) are not in its way, so
nothing is opened for it. Port / service scans of the devices (with a short, cgroup-bound
hostfw window and Mullvad's LAN setting) are part 2.

Only on my own network or one whose owner agrees: the first scan of a network asks
(1 = the owner agrees, remember it; 2 = this time only; 0 = stop). Refused when: not root,
hostfw not in enforce, Mullvad not connected, no IPv4 default route, the uplink is a
tunnel or a bridge, the subnet is not RFC 1918 or is larger than a /22, no ARP entry for
the router.

Privacy: no MAC address and no Wi-Fi name is printed or kept outside root-only files.
Network id = HMAC-SHA256(key, router MAC + subnet); device id = HMAC-SHA256(key, MAC).
Key /etc/harden-workstation/lan-scan.key (root 0600, random, made at the first run),
consent list /etc/harden-workstation/lan-scan.known (root 0600, ids only).
nmap's XML (has the MACs) stays in /var/lib/hardening/lan-scan/<id8>/ (root 0700),
the device list per network (ids, addresses, makers, dates) next to it.
"This time only" (2) keeps nothing: the XML is removed after the report, no device list.
The report (screen) has per device: address, maker (from nmap's list) or "random MAC"
(locally administered: phones, laptops with MAC randomization), new / known, and the
devices gone since the last scan. Exit: 0 done, 1 refused / stopped, 2 error.
"""

import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import sys
import time
import xml.etree.ElementTree as ET

NMAP = "/usr/bin/nmap"
NFT = "/usr/sbin/nft"
MULLVAD = "/usr/bin/mullvad"
ROUTE = "/proc/net/route"
ARP = "/proc/net/arp"
ETC = "/etc/harden-workstation"
KEY = ETC + "/lan-scan.key"
KNOWN = ETC + "/lan-scan.known"
VAR = "/var/lib/hardening/lan-scan"
NOT_UPLINK = ("lo", "wg", "tun", "tap", "virbr", "vnet", "veth", "docker", "podman", "cni",
              "br-")
IFNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
ANY_MAC = re.compile(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
HEX64 = re.compile(r"[0-9a-f]{64}")
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MIN_PREFIX = 22
SCAN_TIMEOUT = 600
TEXT_RE = re.compile(r"[^\x20-\x7e]")


def say(*a):
    print(*a, flush=True)


def clean(s, n=40) -> str:
    """Text from a file or a tool, safe for a terminal: printable ASCII, cut."""
    return TEXT_RE.sub("?", str(s))[:n]


# --- the network ------------------------------------------------------------------------

def _ip4(h: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(int(h, 16).to_bytes(4, sys.byteorder))


def uplink(route_text: str):
    """/proc/net/route -> (dev, router, subnet) of the default route with the lowest metric
    (tunnels and bridges never), or None. subnet: the connected route holding the router."""
    rows = []
    for line in route_text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or not IFNAME_RE.fullmatch(f[0]):
            continue
        try:
            rows.append((f[0], _ip4(f[1]), _ip4(f[2]), int(f[3], 16), int(f[6]), _ip4(f[7])))
        except ValueError:
            continue
    best = None
    for dev, dst, gw, flags, metric, mask in rows:
        if int(dst) or int(mask) or flags & 3 != 3 or not int(gw):
            continue
        if not dev.startswith(NOT_UPLINK) and (best is None or metric < best[3]):
            best = (dev, gw, flags, metric)
    if best is None:
        return None
    subnet = None
    for dev, dst, _, flags, _, mask in rows:
        if dev != best[0] or flags & 2 or not flags & 1 or not int(mask):
            continue
        try:
            net = ipaddress.IPv4Network(f"{dst}/{mask}")
        except ValueError:
            continue
        if best[1] in net and (subnet is None or net.prefixlen > subnet.prefixlen):
            subnet = net
    return best[0], str(best[1]), subnet


def arp_mac(arp_text: str, ip: str, dev: str):
    for line in arp_text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[0] == ip and f[5] == dev and int(f[2], 16) & 2:
            mac = f[3].lower()
            if MAC_RE.fullmatch(mac) and mac != "00:00:00:00:00:00":
                return mac
    return None


def refuse(up, hostfw_enforce: bool, vpn_connected: bool, gw_mac) -> str:
    """Why this network must not be scanned now, '' = fine."""
    if not hostfw_enforce:
        return "hostfw is not in enforce mode (sudo hostfw enforce)"
    if not vpn_connected:
        return "Mullvad is not connected (mullvad status)"
    if up is None:
        return "no IPv4 default route (not connected?)"
    dev, _, subnet = up
    if dev.startswith(NOT_UPLINK):
        return f"uplink {dev} is a tunnel or a bridge"
    if subnet is None:
        return "no connected route holds the router's address"
    if not any(subnet.subnet_of(n) for n in RFC1918):
        return f"{subnet} is not a private (RFC 1918) network"
    if subnet.prefixlen < MIN_PREFIX:
        return f"{subnet} is larger than a /{MIN_PREFIX}"
    if gw_mac is None:
        return "no ARP entry for the router yet (try again in a minute)"
    return ""


def net_id(key: bytes, gw_mac: str, subnet) -> str:
    return hmac.new(key, b"lanscan1\0" + gw_mac.encode() + b"\0" + str(subnet).encode(),
                    hashlib.sha256).hexdigest()


def dev_id(key: bytes, mac: str) -> str:
    return hmac.new(key, b"dev1\0" + mac.lower().encode(), hashlib.sha256).hexdigest()


def random_mac(mac: str) -> bool:
    """Locally administered (bit 1 of the first octet): a randomized / made-up MAC."""
    return bool(int(mac[:2], 16) & 0x02)


# --- root files ---------------------------------------------------------------------------

def write_root(path: str, text: str, mode: int = 0o600) -> None:
    d, name = os.path.split(path)
    tmp = os.path.join(d, f".{name}.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(text.encode("utf-8"))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def read_text(path: str, limit: int = 1 << 20):
    """A root-only file of mine: regular, not a link, -> text, None when missing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError(f"{path}: not my own 0600 regular file (mode {st.st_mode & 0o777:o})")
        return f.read(limit).decode("utf-8", "replace")


def load_key(path: str = KEY) -> bytes:
    text = read_text(path)
    if text is None:
        key = os.urandom(32)
        write_root(path, key.hex() + "\n")
        say(f"key: {path} made (root 0600, random)")
        return key
    if not HEX64.fullmatch(text.strip()):
        raise ValueError(f"{path}: not 64 hex digits")
    return bytes.fromhex(text.strip())


def parse_known(text) -> dict:
    out = {}
    for line in (text or "").splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) >= 2 and HEX64.fullmatch(f[0]):
            out[f[0]] = f[1]
    return out


def render_known(known: dict) -> str:
    lines = ["# lan-scan: networks whose owner agreed to a scan (tools/lan-scan.py).",
             "# <network id> <date>: HMAC-SHA256 of router MAC + subnet, no name, no MAC."]
    lines += [f"{n} {d}" for n, d in sorted(known.items(), key=lambda kv: kv[1])]
    return "\n".join(lines) + "\n"


def ask(tty: str = "/dev/tty", out=say) -> str:
    """1 / 2 / 0 from the terminal, asked again up to 3 times; the question ends with a
    newline (a line filter in front of the screen shows whole lines only)."""
    for _ in range(3):
        out("type 1, 2 or 0, then Enter:")
        try:
            with open(tty) as t:
                a = t.readline()
        except OSError:
            return "0"
        if not a:
            return "0"
        a = a.strip()
        if a in ("1", "2", "0"):
            return a
        out(f"'{clean(a, 10)}' is not 1, 2 or 0")
    return "0"


# --- nmap ---------------------------------------------------------------------------------

def discover_argv(dev: str, subnet, xml_path: str) -> list:
    return [NMAP, "-sn", "-PR", "-n", "-e", dev, "--max-retries", "2", "-oX", xml_path,
            str(subnet)]


def run_nmap(argv: list, timeout: int = SCAN_TIMEOUT, every: int = 10) -> int:
    """nmap with its screen output thrown away (it has MACs); a line every `every` s."""
    say("  " + " ".join(argv[:-3]) + " -oX <root-only file> " + argv[-1])
    err_f = tempfile.TemporaryFile()       # not a pipe: a chatty nmap cannot block on it
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=err_f, env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
    t0 = time.monotonic()
    nxt = every
    while p.poll() is None:
        time.sleep(0.5)
        el = time.monotonic() - t0
        if el >= nxt:
            say(f"  ... nmap running {int(el)} s")
            nxt += every
        if el > timeout:
            p.kill()
            say(f"  nmap killed after {timeout} s")
    err_f.seek(0)
    err = err_f.read(1 << 16).decode("utf-8", "replace")
    err_f.close()
    for line in err.splitlines()[:5]:
        say("  nmap: " + clean(ANY_MAC.sub("<mac>", line), 160))
    return p.returncode


def parse_xml(text: str) -> list:
    """nmap -oX -> [{"ip", "mac" or None, "vendor"}] of the hosts that are up."""
    root = ET.fromstring(text)
    out = []
    for h in root.iter("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = None
        vendor = ""
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                try:
                    ip = str(ipaddress.IPv4Address(a.get("addr", "")))
                except ValueError:
                    ip = None
            elif t == "mac":
                m = (a.get("addr") or "").lower()
                if MAC_RE.fullmatch(m):
                    mac, vendor = m, clean(a.get("vendor") or "", 40)
        if ip:
            out.append({"ip": ip, "mac": mac, "vendor": vendor})
    return sorted(out, key=lambda d: ipaddress.IPv4Address(d["ip"]))


def report(hosts: list, key: bytes, gw: str, last: dict, today: str):
    """-> (lines to print, the new device list). last / new: {device id: {first, last, ip,
    maker, up}}; this laptop (no MAC in nmap's list) is shown, never kept. A device seen
    once stays in the list (back later = known, not new); "gone" = up at the last scan,
    not now."""
    lines, seen = [], {}
    for h in hosts:
        if h["mac"] is None:
            lines.append(f"  {h['ip']:<16} this laptop")
            continue
        did = dev_id(key, h["mac"])
        maker = "random MAC" if random_mac(h["mac"]) else (h["vendor"] or "unknown maker")
        old = last.get(did) if isinstance(last.get(did), dict) else None
        seen[did] = {"first": old.get("first", today) if old else today, "last": today,
                     "ip": h["ip"], "maker": maker, "up": True}
        role = "router" if h["ip"] == gw else ""
        state = f"known since {clean(old.get('first', '?'), 10)}" if old else \
            ("NEW" if last else "first scan")
        lines.append(f"  {h['ip']:<16} {role:<7} {maker:<28} {state}")
    keep = dict(seen)
    for d, old in last.items():
        if d in seen or not isinstance(old, dict):
            continue
        if old.get("up", True):
            lines.append(f"  {clean(old.get('ip', '?'), 16):<16} gone    "
                         f"{clean(old.get('maker', '?'), 28):<28} "
                         f"last seen {clean(old.get('last', '?'), 10)}")
        keep[d] = {**old, "up": False}
    return lines, keep


# --- main ---------------------------------------------------------------------------------

def _cmd(argv: list) -> tuple:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                           env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def hostfw_enforce() -> bool:
    rc, out = _cmd([NFT, "list", "chain", "inet", "hostfw", "enforce"])
    return rc == 0 and "reject" in out


def vpn_connected() -> bool:
    rc, out = _cmd([MULLVAD, "status"])
    return rc == 0 and out.lstrip().startswith("Connected")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: sudo tools/lan-scan.py   (no options: discovery of this network)",
              file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("lan-scan: run with sudo (nmap's ARP ping needs root)", file=sys.stderr)
        return 2
    os.umask(0o077)
    for tool in (NMAP, NFT, MULLVAD):
        if not os.path.exists(tool):
            say(f"lan-scan: {tool} missing")
            return 2
    say(f"== lan-scan (discovery)  {datetime.datetime.now().isoformat(timespec='seconds')}")
    with open(ROUTE) as f:
        up = uplink(f.read())
    with open(ARP) as f:
        gw_mac = arp_mac(f.read(), up[1], up[0]) if up else None
    why = refuse(up, hostfw_enforce(), vpn_connected(), gw_mac)
    if why:
        say(f"STOP: {why}")
        return 1
    dev, gw, subnet = up
    os.makedirs(ETC, mode=0o755, exist_ok=True)
    try:
        key = load_key(KEY)
        known = parse_known(read_text(KNOWN))
    except (OSError, ValueError) as e:
        say(f"lan-scan: {e}")
        return 2
    nid = net_id(key, gw_mac, subnet)
    id8 = nid[:8]
    today = datetime.date.today().isoformat()
    say(f"network: id {id8} (router MAC + subnet, no name shown), {subnet} on {dev}, router {gw}")
    keep_files = True
    if nid in known:
        say(f"owner's consent: given {known[nid]}")
    else:
        say("This network is not on the consent list. Scan only your own network, or one")
        say("whose owner agrees (a scan of someone else's network can be against the law).")
        say("  1  yes, the owner agrees: scan, and remember this network")
        say("  2  yes, this time only")
        say("  0  stop, scan nothing")
        a = ask()
        if a == "0":
            say("stopped: nothing scanned")
            return 1
        keep_files = a == "1"
        if a == "1":
            known[nid] = today
            write_root(KNOWN, render_known(known))
            say(f"consent list: {KNOWN} ({len(known)} network(s))")
    if keep_files:
        d = os.path.join(VAR, id8)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(VAR, 0o700)
    else:
        d = tempfile.mkdtemp(prefix="lan-scan-")       # this time only: removed below
    stamp = time.strftime("%Y%m%d-%H%M%S")
    xml_path = os.path.join(d, f"{stamp}-discovery.xml")
    say(f"== discovery: ARP ping of {subnet} (about 5-30 s)")
    try:
        rc = run_nmap(discover_argv(dev, subnet, xml_path))
        if rc != 0:
            say(f"STOP: nmap exit {rc}")
            return 2
        os.chmod(xml_path, 0o600)
        with open(xml_path, encoding="utf-8", errors="replace") as f:
            hosts = parse_xml(f.read())
    except (OSError, ET.ParseError) as e:
        say(f"STOP: nmap's XML: {e}")
        return 2
    finally:
        if not keep_files:
            shutil.rmtree(d, ignore_errors=True)
    state_path = os.path.join(d, "devices.json")
    try:
        last = json.loads(read_text(state_path) or "{}") if keep_files else {}
    except (ValueError, OSError):
        last = {}
    lines, keep = report(hosts, key, gw, last if isinstance(last, dict) else {}, today)
    n_dev = sum(1 for h in hosts if h["mac"])
    say(f"== devices up: {n_dev} besides this laptop (address, role, maker, since)")
    for line in lines:
        say(line)
    new = sum(1 for line in lines if line.endswith("NEW"))
    gone = sum(1 for line in lines if " gone " in line)
    say(f"new since the last scan: {new} | gone: {gone}")
    if not keep_files:
        say("this time only: nothing kept")
        return 0
    write_root(state_path, json.dumps(keep, indent=1, sort_keys=True) + "\n")
    write_root(os.path.join(d, f"{stamp}-report.txt"), "\n".join(lines) + "\n")
    say(f"kept (root only): {d}/  (nmap XML with MACs, device list, report)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
