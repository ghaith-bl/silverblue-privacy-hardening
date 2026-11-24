#!/usr/bin/env bash
#
# tests/ids-rules.sh - ids/local.rules through the installed Suricata with a made-up capture:
# no network, no root, nothing written outside a temp dir. tests/ids_pcap.py writes the
# capture (scans, leaks, VM traffic and look-alikes that must stay quiet), the net.yaml of a
# made-up network (from ids/harden-ids) and what must or must not alert; suricata -r reads it
# with ids/suricata.yaml (a rule that does not load stops it); the alerts are compared.
#
#   tests/ids-rules.sh          exit 0 = as expected, 1 = a difference, 2 = cannot run here
#
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v suricata >/dev/null || { echo "ids-rules: no suricata on this machine: SKIP"; exit 2; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
python3 -I "$HERE/tests/ids_pcap.py" "$W" || exit 2
cp "$HERE/ids/suricata.yaml" "$W/suricata.yaml"
# pcap mode: one thread, no checksum checks (made-up packets), no cache, no rule references
if ! suricata -r "$W/capture.pcap" -c "$W/suricata.yaml" -S "$HERE/ids/local.rules" -l "$W" \
     -k none --runmode single --init-errors-fatal \
     --set detect.sgh-mpm-caching=no --set classification-file=/dev/null \
     --set reference-config-file=/dev/null > "$W/suricata.out" 2>&1; then
  echo "ids-rules: suricata -r failed:"
  tail -n 20 "$W/suricata.out"
  exit 1
fi
grep -E 'rules successfully loaded|rule files processed' "$W/suricata.out" | head -n 2
python3 -I "$HERE/tests/ids_pcap.py" --check "$W"
