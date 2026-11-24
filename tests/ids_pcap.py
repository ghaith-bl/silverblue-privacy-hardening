#!/usr/bin/env python3
"""ids_pcap.py - a made-up capture for ids/local.rules (stdlib only, no network, no root).

  python3 -I tests/ids_pcap.py <dir>           write <dir>/capture.pcap, <dir>/net.yaml (the
                                                network below, from ids/harden-ids) and
                                                <dir>/expected.json
  python3 -I tests/ids_pcap.py --check <dir>    compare <dir>/eve.json (suricata -r) with it

Used by tests/ids-rules.sh. Made-up network (documentation ranges, RFC 5737 / 7042):
  LAN 192.0.2.0/24, this laptop .10, gateway .1; outside 198.51.100.0/24; Mullvad API
  203.0.113.20; VM bridges: libvirt's default network and browsevm's (host .1 on both).
Every packet is built here with correct lengths and checksums.
"""
import importlib.machinery
import importlib.util
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LAPTOP, GW, LAN = '192.0.2.10', '192.0.2.1', '192.0.2.0/24'
OUT1, OUT2, OUT3 = '198.51.100.53', '198.51.100.7', '198.51.100.8'
API = '203.0.113.20'
LAB_NET, LAB_GW, LAB_VM, LAB_VM2 = '192.168.122.0/24', '192.168.122.1', '192.168.122.10', '192.168.122.11'
BR_NET, BR_GW, BR_VM = '192.168.123.0/24', '192.168.123.1', '192.168.123.15'
MAC_A, MAC_B = b'\x00\x00\x5e\x00\x53\x01', b'\x00\x00\x5e\x00\x53\x02'


def harden_ids():
    path = os.path.join(HERE, 'ids', 'harden-ids')
    loader = importlib.machinery.SourceFileLoader('harden_ids', path)
    spec = importlib.util.spec_from_loader('harden_ids', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_state():
    return {
        'uplinks': ['wlx0'], 'bridges': ['virbr0', 'virbr-browse'],
        'laptop': [LAPTOP + '/32'], 'lan': [LAN], 'gateways': [GW + '/32'],
        'vm_net': [BR_NET, LAB_NET], 'vm_gw': [LAB_GW + '/32', BR_GW + '/32'],
        'browse_net': [BR_NET], 'vpn_api': [API + '/32'], 'bridges_without_address': [],
    }


# ---------------------------------------------------------------- packets

def csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0x4000, 64,
                      proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return MAC_A + MAC_B + b'\x08\x00' + hdr + payload


def l4sum(src, dst, proto, seg):
    pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, proto, len(seg))
    return csum(pseudo + seg)


def udp(src, sport, dst, dport, data=b''):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    c = l4sum(src, dst, 17, seg) or 0xffff
    return ipv4(src, dst, 17, seg[:6] + struct.pack('!H', c) + seg[8:])


def tcp(src, sport, dst, dport, flags, seq=0, ack=0, data=b''):
    fl = {'S': 0x02, 'SA': 0x12, 'A': 0x10, 'PA': 0x18, 'FA': 0x11}[flags]
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, fl, 64240, 0, 0) + data
    c = l4sum(src, dst, 6, seg)
    return ipv4(src, dst, 6, seg[:16] + struct.pack('!H', c) + seg[18:])


def icmp_echo(src, dst, seq):
    msg = struct.pack('!BBHHH', 8, 0, 0, 0x4242, seq) + b'harden-ids test'
    msg = msg[:2] + struct.pack('!H', csum(msg)) + msg[4:]
    return ipv4(src, dst, 1, msg)


def dns_query(name, ident=0x1234):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)


def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack('!HHHBH', 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    versions = struct.pack('!HHBH', 43, 3, 2, 0x0304)
    groups = struct.pack('!HHHH', 10, 4, 2, 0x001d)
    exts = sni_ext + versions + groups
    body = (b'\x03\x03' + bytes(range(32)) + b'\x00' + struct.pack('!HH', 2, 0x1301) +
            b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs


def tcp_session(cli, cport, srv, sport, request, reply=b''):
    """handshake, client data, server ACK (+ reply), client ACK: what stream reassembly needs"""
    c, s = 1000, 5000
    pk = [tcp(cli, cport, srv, sport, 'S', c),
          tcp(srv, sport, cli, cport, 'SA', s, c + 1),
          tcp(cli, cport, srv, sport, 'A', c + 1, s + 1),
          tcp(cli, cport, srv, sport, 'PA', c + 1, s + 1, request),
          tcp(srv, sport, cli, cport, 'A', s + 1, c + 1 + len(request))]
    if reply:
        pk.append(tcp(srv, sport, cli, cport, 'PA', s + 1, c + 1 + len(request), reply))
        pk.append(tcp(cli, cport, srv, sport, 'A', c + 1 + len(request), s + 1 + len(reply)))
    return pk


def scenario():
    """(packets, expectations): each expectation {sid, src, dst?, min | max}"""
    pk, exp = [], []

    def want(sid, src, dst=None, n=1):
        exp.append({'sid': sid, 'src': src, 'dst': dst, 'min': n})

    def never(sid, src, dst=None):
        exp.append({'sid': sid, 'src': src, 'dst': dst, 'max': 0})

    # scans of this laptop from the LAN; 3 SYNs from another host stay below the threshold
    pk += [tcp('192.0.2.50', 40000 + i, LAPTOP, 1001 + i, 'S', 7) for i in range(12)]
    want(9200001, '192.0.2.50')
    pk += [tcp('192.0.2.60', 41000 + i, LAPTOP, 22, 'S', 7) for i in range(3)]
    never(9200001, '192.0.2.60')
    pk += [udp('192.0.2.51', 42000, LAPTOP, 2001 + i, b'x') for i in range(12)]
    want(9200002, '192.0.2.51')
    pk += [udp('192.0.2.52', 67, LAPTOP, 68, b'dhcp-ish') for _ in range(12)]
    never(9200002, '192.0.2.52')
    pk += [icmp_echo('192.0.2.53', LAPTOP, i) for i in range(6)]
    want(9200003, '192.0.2.53')

    # tunnel leaks from this laptop; the router page and the Mullvad API are not leaks
    pk.append(udp(LAPTOP, 43000, OUT1, 53, dns_query('example.org')))
    want(9200010, LAPTOP, OUT1)
    pk.append(udp(LAB_VM, 43001, LAB_GW, 53, dns_query('example.org', 0x4321)))
    never(9200010, LAB_VM)
    pk += tcp_session(LAPTOP, 43002, GW, 80, b'GET / HTTP/1.1\r\nHost: router\r\n\r\n',
                      b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    never(9200011, LAPTOP, GW)
    pk += tcp_session(LAPTOP, 43003, OUT2, 80, b'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n',
                      b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    want(9200011, LAPTOP, OUT2)
    pk += tcp_session(LAPTOP, 43004, API, 443, client_hello('api.example.net'))
    never(9200012, LAPTOP, API)
    pk += tcp_session(LAPTOP, 43005, OUT3, 443, client_hello('example.org'))
    want(9200012, LAPTOP, OUT3)

    # VMs: lab VM to the LAN, browse VM to the lab VM, a lab VM probing the host
    pk.append(tcp(LAB_VM, 44000, '192.0.2.30', 445, 'S', 9))
    want(9200020, LAB_VM, '192.0.2.30')
    pk.append(tcp(BR_VM, 44001, LAB_VM, 22, 'S', 9))
    want(9200021, BR_VM, LAB_VM)
    pk.append(udp(BR_VM, 44002, BR_GW, 53, dns_query('example.org', 0x5555)))
    never(9200021, BR_VM, BR_GW)
    never(9200010, BR_VM)
    pk += [tcp(LAB_VM2, 45000 + i, LAB_GW, p, 'S', 9)
           for i, p in enumerate((22, 80, 443, 5900, 8080, 9090))]
    want(9200022, LAB_VM2, LAB_GW)
    pk += [tcp(LAB_VM, 45100 + i, LAB_GW, 53, 'S', 9) for i in range(6)]
    never(9200022, LAB_VM)
    return pk, exp


def write_pcap(path, packets, t0=1767225600):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            t = t0 * 1000000 + i * 20000          # 20 ms apart
            f.write(struct.pack('<IIII', t // 1000000, t % 1000000, len(p), len(p)))
            f.write(p)


def build(out):
    packets, exp = scenario()
    write_pcap(os.path.join(out, 'capture.pcap'), packets)
    with open(os.path.join(out, 'net.yaml'), 'w') as f:
        f.write(harden_ids().render(test_state()))
    with open(os.path.join(out, 'expected.json'), 'w') as f:
        json.dump(exp, f, indent=1)
    return len(packets), len(exp)


def check(out):
    with open(os.path.join(out, 'expected.json')) as f:
        exp = json.load(f)
    alerts = []
    try:
        with open(os.path.join(out, 'eve.json')) as f:
            for line in f:
                ev = json.loads(line)
                if ev.get('event_type') == 'alert':
                    alerts.append((ev['alert']['signature_id'], ev.get('src_ip'), ev.get('dest_ip')))
    except FileNotFoundError:
        pass
    bad = 0
    for e in exp:
        n = sum(1 for sid, src, dst in alerts
                if sid == e['sid'] and src == e['src'] and (e['dst'] is None or dst == e['dst']))
        ok = n >= e['min'] if 'min' in e else n <= e['max']
        bad += not ok
        print('%s sid %d  %s -> %s: %d alert(s), want %s' % (
            'PASS' if ok else 'FAIL', e['sid'], e['src'], e['dst'] or 'any', n,
            '>= %d' % e['min'] if 'min' in e else '<= %d' % e['max']))
    sids = {e['sid'] for e in exp}
    for sid, src, dst in alerts:
        if sid not in sids:
            print('NOTE other alert: sid %s %s -> %s' % (sid, src, dst))
    print('%d of %d checks passed' % (len(exp) - bad, len(exp)))
    return 1 if bad else 0


def main(argv):
    if len(argv) == 3 and argv[1] == '--check':
        return check(argv[2])
    if len(argv) == 2 and os.path.isdir(argv[1]):
        n, e = build(argv[1])
        print('ids_pcap: %d packets, %d checks' % (n, e))
        return 0
    print(__doc__.strip())
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
