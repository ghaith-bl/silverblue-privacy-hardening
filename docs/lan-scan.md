# LAN device scan (`tools/lan-scan.py`)

Which devices are on the network this laptop is on, and which are new. Part 1 (step
11b2b-1, 2026-11-27): discovery only. Part 2 (planned): port / service scan of the devices
(tcp top 1000 + udp top 50, version detection) through a short hostfw window bound to the
scan's own cgroup, Mullvad's LAN setting opened for it and closed again (trap, a timer
as a safety net, a boot check).

## Run

    sudo tools/lan-scan.py        # as the admin, from this repo's clone (nmap layered: docs/ids.md)

Only on my own network, or one whose owner agrees. The first scan of a network asks:

    1  yes, the owner agrees: scan, and remember this network
    2  yes, this time only (nothing kept on disk)
    0  stop, scan nothing

## What it does

- Refused when: not root, hostfw not in enforce, Mullvad not connected, no IPv4 default
  route, the uplink is a tunnel / bridge (`wg*`, `tun*`, `virbr*`, ...), the subnet is not
  RFC 1918 (10/8, 172.16/12, 192.168/16) or larger than a /22, no ARP entry for the router.
- `nmap -sn -PR -n -e <uplink> --max-retries 2 <subnet>`: ARP ping. ARP is not IP, so
  hostfw and Mullvad's kill switch (nftables `inet` tables) are not in its way: nothing
  is opened, no packet leaves through the tunnel or outside it. nmap's screen output
  (it has MACs) is thrown away; a progress line every 10 s.
- Report per device: address, `router` / `this laptop`, maker from nmap's MAC list or
  `random MAC` (locally administered bit: phones and laptops with MAC randomization),
  `first scan` / `known since <date>` / `NEW`, then the devices gone since the last scan.
  A device seen once stays known (back later = known, not new).

## Privacy

- No MAC address and no Wi-Fi name is printed, and none is kept outside root-only files.
- Network id = HMAC-SHA256(key, router MAC + subnet) (no Wi-Fi name needed: the router's
  MAC already tells networks apart); device id = HMAC-SHA256(key, MAC).
- `/etc/harden-workstation/lan-scan.key` (root 0600, random, made by the first run),
  `/etc/harden-workstation/lan-scan.known` (root 0600: network ids + date of consent).
- `/var/lib/hardening/lan-scan/<id8>/` (root 0700): nmap's XML (has the MACs: local only,
  never uploaded), `devices.json` (device ids, addresses, makers, dates), the reports.
- "This time only": the XML is removed after the report, no device list is kept.

## Limits

- Wi-Fi with client isolation (hotspots, guest networks): only the router answers.
- A device that does not answer ARP is not seen (rare: ARP is needed to talk on the LAN).
- The maker comes from the MAC's prefix: a randomized MAC has none.
