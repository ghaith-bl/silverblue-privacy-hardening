# Network IDS: Suricata (section `ids`)

Suricata 8 (Fedora's package, layered) watches the network this laptop is on and its VM
bridges. IDS only: it reads copies of packets, never drops one (hostfw and firewalld
decide). sectop shows the alerts (ids box, critical ones in the alert bar) and, from the
DHCP records, the DHCP servers per network (lan box).

## What it sees, what it cannot

- Uplink (Wi-Fi / cable, the IPv4 default route) and the libvirt bridges (`virbr0`,
  `virbr-browse` while up). Never the tunnel `wg0-mullvad`: nothing of what goes through
  the VPN is inspected or logged (privacy; hostfw logs the tunnel side by counters).
- On Wi-Fi (managed mode) the laptop only gets its own traffic plus broadcast /
  multicast (ARP, DHCP, mDNS ...). Not a phone's or a TV's own internet traffic. What it
  can catch from other devices: their scans / probes against this laptop, their
  broadcasts, DHCP answers. Seeing every device's traffic needs the router (OpenWrt) or a
  sensor on a switch mirror port, never ARP tricks (that is the attack itself).
- No promiscuous mode: only what this host sends or receives.

## Rules

- `ids/local.rules` (sid 9200001-9200099, msg `HARDEN ...`, `metadata: harden <kind>`):
  - `scan` / `probe`: TCP SYNs, UDP or pings from the LAN to this laptop (10 / 10 / 5 per
    source and minute; one alert a minute per source)
  - `leak`: DNS, plain HTTP, or TLS not to the Mullvad API (hostfw `local.conf`
    `vpn_api4`) on the uplink from anything but a VM. hostfw drops these before they
    leave (`out_leak`, `out_dns`): an alert = that layer failed. Not covered: QUIC
    (Mullvad's QUIC obfuscation looks the same), raw TCP / UDP (udp2tcp, Shadowsocks
    obfuscation): hostfw counters only
  - `vm_lan`: a VM to the LAN; the browse VM to any other private network (host, lab
    VMs, LAN); `vm_probe`: a VM sending SYNs to the host (not DNS) on 5+ ports a minute
- ET Open (Proofpoint, free), weekly by `harden-ids-update.timer`: categories SCAN
  MALWARE MOBILE_MALWARE EXPLOIT EXPLOIT_KIT DNS COINMINER WORM ATTACK_RESPONSE CNC,
  everything else off (`ids/disable.conf`); a rule ET ships disabled stays disabled.
  suricata-update as user `suricata` (no capabilities, sandboxed), through the tunnel,
  plain User-Agent, `suricata -T` before the new rules replace the old ones, then a rule
  reload (SIGUSR2). `IDS_RULES_UPDATE=no`: local rules only, no download.
- Rogue DHCP and a gateway MAC change: not as rules (a new network's own DHCP server
  would alert at every join, before the network part is rewritten). In sectop's lan box
  (step 11b2a, sectop docs/modules/lan.md): the router's MAC per network from the ARP
  table against the routers accepted there (`sudo ./install.sh --lan-accept` in the
  sectop clone), the router's MAC on a second address, and a DHCP server in eve's DHCP
  records that is not the router (uplink) or not this host (VM bridge). Red alerts.
  Ids only (HMAC with a local key): no MAC or Wi-Fi name in sectop's files or screen.

## Logs (privacy)

- `/var/log/suricata/harden-ids/eve.json` (user suricata, 0640): alerts, app-layer
  anomalies, DHCP (MAC <-> IP of DHCP answers on the network, other devices' too). Off:
  DNS / HTTP / TLS / flow / file logs, stats, payload, packet, HTTP body, app-layer data
  in alerts (no hostnames, URLs, queries), no core dumps. One file a day, 7 kept
  (`/etc/logrotate.d/harden-ids`). Never uploaded: sectop shows counts and signatures.
- Suricata's own messages: the journal (`journalctl -u suricata`).

## Files

| Path | What |
|------|------|
| `/etc/suricata/harden-ids/suricata.yaml` | the config (Fedora's `/etc/suricata/suricata.yaml` unused) |
| `/etc/suricata/harden-ids/net.yaml` | address groups + interfaces of the network now (`harden-ids sync`, then `restorecon -F`: the policy's label whoever wrote it); AIDE: names, mode, owner, label (no content) |
| `/etc/suricata/harden-ids/local.rules`, `update.yaml`, `disable.conf`, `ids.conf`, `reference.config` | rules, suricata-update, kept categories, bridges, Fedora's reference list (root:suricata 0640) |
| `/etc/systemd/system/suricata.service.d/harden-ids.conf` | our config, af-packet, `--user suricata`, sandbox; `ExecCondition`: net.yaml first, nothing to watch = not started |
| `harden-ids-update.service` / `.timer` | ET Open weekly |
| `/usr/local/sbin/harden-ids` | `sync` (net.yaml, restart when it changed), `status` |
| `/etc/NetworkManager/dispatcher.d/91-harden-ids` | sync on uplink up / down / DHCP change |
| `/etc/udev/rules.d/91-harden-ids.rules` + `harden-ids-sync.service` | sync when a libvirt bridge appears |
| `/var/lib/suricata/rules` | ET Open (`suricata.rules`), merged `classification.config` |

## Run

```bash
sudo rpm-ostree install suricata nmap && systemctl reboot
sudo ./harden-workstation.sh ids integrity   # first ET download + start; AIDE: new files
sudo harden-check --accept                   # after a look at the list
sudo harden-ids status                       # interfaces, memory, rules, alerts 24 h
tests/ids-rules.sh                           # local.rules against a made-up capture
sudo systemctl start harden-ids-update.service   # ET Open now
```

Undo: `IDS="off"` + the section (stops and disables suricata and the timer), or
`sudo systemctl disable --now suricata.service harden-ids-update.timer`.
