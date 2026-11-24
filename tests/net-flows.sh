#!/usr/bin/env bash
#
# net-flows.sh - attack this laptop from a lab VM and check every result against the flow
# table below: what a machine next to the laptop can reach, on IPv4 and IPv6, TCP and UDP,
# with the usual firewall-bypass tricks, and what hostfw counts while it happens.
# Own targets only: this laptop's own addresses, plus two ports on the LAN gateway that the
# VM must NOT reach (the probe never gets there while hostfw / Mullvad do their job).
#
#   tests/net-flows.sh                     full run (all 65535 TCP ports per address), ~10-15 min
#   tests/net-flows.sh --quick             top 1000 TCP ports per address, ~4 min
#   tests/net-flows.sh --no-internet       skip the "VM via the tunnel" check (am.i.mullvad.net)
#   tests/net-flows.sh --evaluate DIR      check saved results again, no scan
#   VM_HOST=vmub VM_USER=null              ssh alias of the lab VM, local user that holds its key
#
# Run as the admin (sudo for nft / ss / the VM user's ssh), on the text console: the VM's
# sudo asks its password once (nmap needs raw sockets there). As VM_USER itself it runs too,
# without the counter / listener parts (no sudo): those checks say SKIP.
# Needs in the VM: nmap (sudo apt install nmap), curl for the tunnel check.
# Changes nothing on this laptop. In the VM: one temp dir, removed at the end.
# Results: ~/net-flows/<date-time>/ (0700): meta, nmap -oG files, counters, report.txt.
#
# Flow table (src = lab VM on virbr0; BR = laptop on virbr0, UP = laptop on the uplink,
# VPN = laptop on the tunnel, GW = LAN gateway):
#   VM -> BR   tcp all (+ source port 53, fragmented)  open: 53 only (dnsmasq)
#   VM -> BR   udp top 100 + every laptop UDP listener open: 53 (67 may answer)
#   VM -> BR   ACK scan top 1000                        no port unfiltered but 53 (stateful filter)
#   VM -> UP   tcp all, udp top 100 + listeners         none open
#   VM -> VPN  tcp all, udp top 100 + listeners         none open
#   VM -> GW   tcp 53 80 443, ping                      not reached (filtered), fwd_vm_lan grows
#   VM v6      ping ff02::1 on its link                 only the VM answers (no laptop v6 there)
#   VM -> laptop link-local v6 (bridge, vnet*)          nothing open or closed (no v6 path)
#   VM -> internet via the tunnel                       connected to Mullvad, fwd_vm_new grows
#   counters out_leak out_lan out_dns out_split in_lan in_vpn fwd_in   unchanged
#   hostfw mode                                         enforce
#
# The VM is not trusted: its results are read as plain text with fixed patterns and size
# caps, never run or sourced; ssh never accepts a new host key and forwards nothing.
# Exit: 0 every check PASS, 1 a check FAIL, 2 usage / could not run.
#
set -uo pipefail
umask 077

VM_HOST=${VM_HOST:-vmub}
VM_USER=${VM_USER:-null}
BR_IF=${BR_IF:-virbr0}
VPN_IF=${VPN_IF:-wg0-mullvad}
GW_PORTS=53,80,443
MAX_FILE=2000000

die()  { printf 'net-flows: %s\n' "$*" >&2; exit 2; }
step() { printf '\n== %s (%s)\n' "$*" "$(date +%T)"; }
# link-local / EUI-64 interface ids carry the MAC: never printed
mask6() { sed -E 's/fe80::[0-9a-fA-F:]+/fe80::<id>/g'; }

is_v4()   { [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$ ]]; }
is_ll6()  { [[ $1 =~ ^fe80::[0-9a-f:]{1,40}$ ]]; }
is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
v4int()   { local IFS=.; local -a o; read -r -a o <<< "$1"; echo $(( (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3] )); }

# ---------------------------------------------------------------- remote part
# Runs inside the VM as root (sudo bash scan.sh ...). Arguments are checked by the
# caller (addresses, ports, flags only). Writes <name>.gnmap and small text files to $1.
remote_scan() {
  set -uo pipefail
  local d=$1 hbr=$2 hup=$3 hvpn=$4 gw=$5 gwports=$6 quick=$7 inet=$8 udpx=$9
  shift 9
  local -a ll6=("$@") tcpports=()
  local u=${SUDO_USER:-} ifc n t
  [[ $EUID -eq 0 ]] || { echo "remote: needs root (sudo)"; return 1; }
  cd "$d" || return 1
  command -v nmap >/dev/null || { echo "remote: no nmap in the VM (sudo apt install nmap)"; return 1; }
  nmap --version | head -n 1
  ifc=$(ip -o route get "$hbr" | sed -nE 's/.* dev ([^ ]+).*/\1/p')
  [[ -n $ifc ]] || { echo "remote: no route to $hbr"; return 1; }
  echo "VM side: interface $ifc"
  if [[ $quick == 1 ]]; then tcpports=(--top-ports 1000); else tcpports=(-p-); fi

  ns() {   # name, nmap args... ; progress lines only on screen, results in name.gnmap
    local name=$1
    shift
    printf -- '-- %s (%s)\n' "$name" "$(date +%T)"
    nmap -n -Pn --reason --stats-every 30s -oG "$d/$name.gnmap" "$@" 2>&1 |
      grep --line-buffered -E '^Stats:|Timing: About|^Nmap done|^WARNING|^Failed|^QUITTING' |
      sed -E 's/fe80::[0-9a-fA-F:]+/fe80::<id>/g'
  }

  for n in br up vpn; do
    case $n in br) t=$hbr ;; up) t=$hup ;; vpn) t=$hvpn ;; esac
    [[ -n $t && $t != - ]] || continue
    ns "tcp-$n"     -sS "${tcpports[@]}" --max-retries 2 --min-rate 1000 "$t"
    ns "sport53-$n" -sS -g 53 --top-ports 1000 --max-retries 2 "$t"
    ns "udp-$n"     -sU --top-ports 100 --max-retries 1 --defeat-icmp-ratelimit "$t"
    ns "udpx-$n"    -sU -p "$udpx" --max-retries 3 "$t"
  done
  ns ack-br  -sA --top-ports 1000 --max-retries 2 "$hbr"
  ns frag-br -sS -f --top-ports 1000 --max-retries 2 "$hbr"

  ns gw -sS -p "$gwports" --max-retries 1 "$gw"
  if ping -c 2 -W 2 "$gw" >/dev/null 2>&1; then echo "rc=0" > gw-ping.txt; else echo "rc=1" > gw-ping.txt; fi

  printf -- '-- v6 (%s)\n' "$(date +%T)"
  ip -6 -o addr show dev "$ifc" scope link | sed -nE 's/.* inet6 (fe80::[0-9a-f:]+)\/.*/\1/p' > v6-self.txt
  ping -6 -n -c 3 -w 6 "ff02::1%$ifc" 2>/dev/null | sed -nE 's/.* from (fe80::[0-9a-f:]+)(%[^:]*)?: .*/\1/p' |
    sort -u > v6-responders.txt
  echo "v6 responders: $(wc -l < v6-responders.txt) (the VM's own: $(wc -l < v6-self.txt))"
  local i=0 a
  for a in "${ll6[@]}"; do
    i=$((i + 1))
    ns "tcp6-$i" -6 -sS --top-ports 1000 --max-retries 2 "$a%$ifc"
  done

  if [[ $inet == 1 ]]; then
    printf -- '-- internet via the tunnel (%s)\n' "$(date +%T)"
    if command -v curl >/dev/null; then
      runuser -u "${u:-nobody}" -- curl -sS -m 20 https://am.i.mullvad.net/connected > inet.txt 2>&1 || true
    else
      echo "no curl in the VM" > inet.txt
    fi
  fi
  echo ok > remote.done
  [[ -n $u ]] && chown -R "$u" "$d"
  return 0
}

# ---------------------------------------------------------------- evaluation
FAILS=0
PASSES=0
SKIPS=0
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-24s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1));   printf 'FAIL  %-24s %s\n' "$1" "$2"; }
skip() { SKIPS=$((SKIPS + 1));   printf 'SKIP  %-24s %s\n' "$1" "$2"; }

# "port/proto state" for every port nmap listed (not the ignored ones); fixed fields only
ports_of() {
  head -c "$MAX_FILE" "$1" | awk -F'\t' '
    /^Host: / { for (i = 1; i <= NF; i++) if ($i ~ /^Ports: /) {
        n = split(substr($i, 8), a, /, /)
        for (j = 1; j <= n; j++) { split(a[j], f, "/")
          if (f[1] ~ /^[0-9]+$/ && f[2] ~ /^[a-z|]+$/ && f[3] ~ /^(tcp|udp)$/) print f[1] "/" f[3], f[2] } } }'
}

scan_done() { head -c "$MAX_FILE" "$1" 2>/dev/null | grep -qE '^# Nmap done at .* -- 1 IP address \(1 host up\)'; }

# check_scan <file stem> <label> <bad state regex> <must be open, space list> <may be open>
check_scan() {
  local f=$W/$1.gnmap label=$2 bad=$3 must=" $4 " may=" $5 " p st hit="" miss="" other note
  if [[ ! -f $f ]] || ! scan_done "$f"; then fail "$label" "scan missing or not finished ($1.gnmap)"; return; fi
  while read -r p st; do
    [[ -n $p ]] || continue
    if [[ $st =~ $bad && $must != *" $p "* && $may != *" $p "* ]]; then hit+=" $p:$st"; fi
  done < <(ports_of "$f")
  for p in $4; do
    st=$(ports_of "$f" | awk -v p="$p" '$1 == p { print $2 }')
    [[ $st == open ]] || miss+=" $p:${st:-not-listed}"
  done
  other=$(ports_of "$f" | awk '$2 ~ /open\|filtered|closed\|filtered/' | wc -l)
  note=""
  (( other > 0 )) && note=" ($other with no answer)"
  if [[ -n $hit || -n $miss ]]; then
    fail "$label" "${hit:+unexpected:$hit}${miss:+ must be open:$miss}"
  elif [[ -n ${4// /} ]]; then
    pass "$label" "only ${4// /, } open, as expected$note"
  else
    pass "$label" "no port $(tr -d '^$()' <<< "$bad" | tr '|' '/'), as expected$note"
  fi
}

counter() { awk -v n="$2" '$1 == n { print $2 }' "$W/counters-$1.txt" 2>/dev/null; }

meta() { sed -nE "s/^$1=([A-Za-z0-9 .:,_-]*)$/\1/p" "$W/meta" | head -n 1; }

evaluate() {
  local hbr hup hvpn quick inet mode vmsrc h6 i b a d n s self
  [[ -f $W/meta ]] || die "no meta file in $W"
  hbr=$(meta hbr); hup=$(meta hup); hvpn=$(meta hvpn); quick=$(meta quick); inet=$(meta inet)
  mode=$(meta mode); vmsrc=$(meta vmsrc); h6=$(meta h6)
  step "results ($W)"

  case $mode in
    enforce) pass "hostfw mode" "enforce" ;;
    unknown) skip "hostfw mode" "not read (no sudo)" ;;
    *)       fail "hostfw mode" "${mode:-?} (denies are only logged, not blocked)" ;;
  esac
  if [[ $vmsrc == ok ]]; then pass "scan source" "VM inside the $BR_IF network (laptop there: $hbr)"
  else fail "scan source" "VM is not on the $BR_IF network (${vmsrc:-?})"; fi
  if [[ ! -f $W/remote.done ]]; then fail "VM run" "did not finish (no remote.done)"; fi

  check_scan tcp-br     "BR tcp"            '^open$'       "53/tcp" ""
  check_scan sport53-br "BR tcp sport 53"   '^open$'       "53/tcp" ""
  check_scan frag-br    "BR tcp fragmented" '^open$'       "53/tcp" ""
  # 53/tcp may answer: conntrack picks up a lone ACK as new (nf_conntrack_tcp_loose=1), dns allows it
  check_scan ack-br     "BR ack"            '^unfiltered$' "" "53/tcp"
  check_scan udp-br     "BR udp top 100"    '^open$'       "53/udp" "67/udp"
  check_scan udpx-br    "BR udp listeners"  '^open$'       "53/udp" "67/udp"
  for n in up vpn; do
    a=$hup; [[ $n == vpn ]] && a=$hvpn
    if [[ -z $a || $a == - ]]; then fail "${n^^} address" "none (interface down?)"; continue; fi
    check_scan "tcp-$n"     "${n^^} tcp"           '^open$' "" ""
    check_scan "sport53-$n" "${n^^} tcp sport 53"  '^open$' "" ""
    check_scan "udp-$n"     "${n^^} udp top 100"   '^open$' "" ""
    check_scan "udpx-$n"    "${n^^} udp listeners" '^open$' "" ""
  done

  check_scan gw "GW tcp $GW_PORTS" '^(open|closed|unfiltered)$' "" ""
  case $(cat "$W/gw-ping.txt" 2>/dev/null) in
    rc=1) pass "GW ping" "no answer (not reached)" ;;
    rc=0) fail "GW ping" "the gateway answered: the VM reaches the LAN" ;;
    *)    fail "GW ping" "no result" ;;
  esac

  # v6: the VM may only hear itself on its link
  if [[ -f $W/v6-responders.txt && -f $W/v6-self.txt ]]; then
    b=$(grep -vxF -f "$W/v6-self.txt" "$W/v6-responders.txt" | grep -cE '^fe80::')
    self=$(grep -cE '^fe80::' "$W/v6-self.txt")
    if (( b == 0 )); then pass "v6 neighbours" "only the VM itself answers ff02::1 ($self own address)"
    else fail "v6 neighbours" "$b other address(es) answer on the VM's link"; fi
  else
    fail "v6 neighbours" "no result"
  fi
  i=0
  for a in $h6; do
    i=$((i + 1))
    check_scan "tcp6-$i" "laptop v6 #$i" '^(open|closed)$' "" ""
  done
  (( i > 0 )) || pass "laptop v6 targets" "the laptop has no link-local address on $BR_IF or its ports"

  if [[ $inet == 1 ]]; then
    if grep -qE '^You are connected to Mullvad' "$W/inet.txt" 2>/dev/null; then
      s=$(sed -nE 's/^You are connected to Mullvad \(server ([A-Za-z0-9-]{1,40})\).*/\1/p' "$W/inet.txt" | head -n 1)
      pass "VM via tunnel" "connected to Mullvad${s:+ (server $s)}"
    else
      fail "VM via tunnel" "$(head -c 200 "$W/inet.txt" 2>/dev/null | head -n 1 | tr -cd '[:print:]')"
    fi
  else
    skip "VM via tunnel" "--no-internet"
  fi

  if [[ -f $W/counters-before.txt && -f $W/counters-after.txt ]]; then
    for n in fwd_vm_lan fwd_vm_new out_leak out_lan out_dns out_split in_lan in_vpn fwd_in; do
      b=$(counter before "$n"); a=$(counter after "$n")
      if [[ ! $b =~ ^[0-9]+$ || ! $a =~ ^[0-9]+$ ]]; then fail "counter $n" "missing"; continue; fi
      d=$((a - b))
      case $n in
        fwd_vm_lan) if (( d > 0 )); then pass "counter $n" "+$d (gateway probes counted + blocked)"
                    else fail "counter $n" "+0: the gateway probes were not counted"; fi ;;
        fwd_vm_new) if [[ $inet != 1 ]]; then skip "counter $n" "+$d (--no-internet)"
                    elif (( d > 0 )); then pass "counter $n" "+$d (VM flows via the tunnel)"
                    else fail "counter $n" "+0: VM internet flows not counted"; fi ;;
        *)          if (( d == 0 )); then pass "counter $n" "unchanged ($a)"
                    else fail "counter $n" "+$d during the test (journal: HFW lines)"; fi ;;
      esac
    done
  else
    skip "counters" "not read (run as the admin for them)"
  fi

  printf '\n%s PASS, %s FAIL, %s SKIP  (%s, %s)\n' "$PASSES" "$FAILS" "$SKIPS" \
    "$([[ $quick == 1 ]] && echo 'top 1000 tcp' || echo 'all tcp ports')" "$W"
  (( FAILS == 0 ))
}

# ---------------------------------------------------------------- host part
QUICK=0
INET=1
W=""
while (( $# )); do
  case $1 in
    --quick)       QUICK=1 ;;
    --no-internet) INET=0 ;;
    --evaluate)    shift; [[ -n ${1:-} && -d $1 ]] || die "--evaluate needs a results dir"; W=$(cd "$1" && pwd) ;;
    -h|--help)     sed -n '3,46p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             die "unknown option: $1 (--help)" ;;
  esac
  shift
done

if [[ -n $W ]]; then
  evaluate | mask6
  exit "${PIPESTATUS[0]}"
fi

[[ $EUID -ne 0 ]] || die "run as the admin (sudo per line), not as root"
[[ $VM_HOST =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "VM_HOST: bad name"
[[ $VM_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "VM_USER: bad name"
for c in ip ssh awk ss; do command -v "$c" >/dev/null || die "no $c"; done

ME=$(id -un)
ROOT=1
if [[ $ME == "$VM_USER" ]]; then ROOT=0; fi
as_vm() { if [[ $ME == "$VM_USER" ]]; then "$@"; else sudo -u "$VM_USER" -H -- "$@"; fi; }

W=$HOME/net-flows/$(date +%Y%m%d-%H%M%S)
mkdir -p "$W" || die "cannot create $W"
chmod 700 "$HOME/net-flows" "$W"
exec > >(tee "$W/run.txt" | mask6) 2>&1
printf '== net-flows  %s  (%s)\n' "$(date -Is)" "$([[ $QUICK == 1 ]] && echo quick || echo full)"

step "laptop side: addresses, listeners, hostfw"
if (( ROOT )); then sudo -v || die "sudo failed"; fi
HBR=$(ip -4 -o addr show dev "$BR_IF" scope global 2>/dev/null | awk '{print $4; exit}')
[[ -n $HBR ]] || die "$BR_IF has no IPv4 address (libvirt network default not started?)"
BR_PREFIX=${HBR#*/}; HBR=${HBR%/*}
is_v4 "$HBR" && [[ $BR_PREFIX =~ ^[0-9]+$ ]] && (( BR_PREFIX >= 8 && BR_PREFIX <= 30 )) || die "$BR_IF address: $HBR/$BR_PREFIX"
read -r UP_IF GW < <(ip -4 route show default | awk '{for (i = 1; i < NF; i++) { if ($i == "dev") d = $(i+1); if ($i == "via") g = $(i+1) } print d, g; exit}')
HUP=$(ip -4 -o addr show dev "${UP_IF:-none}" scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
HVPN=$(ip -4 -o addr show dev "$VPN_IF" 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
for v in GW HUP HVPN; do
  if [[ -n ${!v} ]] && ! is_v4 "${!v}"; then die "$v: not an IPv4 address"; fi
done
[[ -n $GW ]] || die "no default route (no network?)"
echo "BR  $BR_IF $HBR/$BR_PREFIX"
echo "UP  ${UP_IF:-?} ${HUP:--}   gateway $GW"
echo "VPN $VPN_IF ${HVPN:--}"
# laptop link-local v6 on the bridge and its ports: targets for the v6 part
H6=()
mapfile -t ports < <(ip -o link show master "$BR_IF" 2>/dev/null | awk -F': ' '{sub(/@.*/, "", $2); print $2}')
for i in "$BR_IF" "${ports[@]}"; do
  while read -r a; do is_ll6 "$a" && H6+=("$a"); done < <(ip -6 -o addr show dev "$i" scope link 2>/dev/null |
    sed -nE 's/.* inet6 (fe80::[0-9a-f:]+)\/.*/\1/p')
done
echo "laptop v6 link-local on $BR_IF and its ports: ${#H6[@]}"

UDPX="53,67"
MODE=unknown
# every UDP socket of the laptop not bound to loopback: the VM must reach none but dnsmasq
while read -r p; do is_port "$p" && [[ ",$UDPX," != *",$p,"* ]] && UDPX+=",$p"; done < <(
  ss -H -uln | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|::1)' | sed -nE 's/.*:([0-9]+)$/\1/p' | sort -un)
if (( ROOT )); then
  if sudo nft list chain inet hostfw enforce 2>/dev/null | grep -qE '^[[:space:]]+reject'; then MODE=enforce
  elif sudo nft list table inet hostfw >/dev/null 2>&1; then MODE=observe
  else MODE=missing; fi
fi
echo "udp ports probed by name: $UDPX"
echo "hostfw mode: $MODE"

counters() {   # $1 before | after
  (( ROOT )) || return 0
  sudo nft list counters table inet hostfw 2>/dev/null |
    awk '/^[[:space:]]*counter /{n = $2} /packets/{print n, $2, $4}' > "$W/counters-$1.txt"
}

SSHO=(-o BatchMode=no -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ForwardAgent=no
      -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -o LogLevel=ERROR)
CM=$(as_vm mktemp -d /tmp/net-flows-cm.XXXXXXXXXX) || die "cannot make the ssh control dir"
[[ $CM =~ ^/tmp/net-flows-cm\.[A-Za-z0-9]{10}$ ]] || die "control dir: $CM"
SSHO+=(-o ControlMaster=auto -o "ControlPath=$CM/c" -o ControlPersist=120)
vm()  { as_vm ssh -n "${SSHO[@]}" "$VM_HOST" "$@"; }      # stdin: /dev/null (keys stay on the console)
vmin() { as_vm ssh "${SSHO[@]}" "$VM_HOST" "$@"; }        # stdin: the upload
vmt() { as_vm ssh -t "${SSHO[@]}" "$VM_HOST" "$@"; }
RD=""
cleanup() {
  [[ -n ${CM:-} ]] || return 0
  if [[ -n $RD ]]; then vm "rm -rf -- '$RD'" >/dev/null 2>&1 || echo "note: remove $RD in the VM by hand"; fi
  as_vm ssh "${SSHO[@]}" -O exit "$VM_HOST" >/dev/null 2>&1 || true
  as_vm rm -rf -- "$CM" 2>/dev/null || true
  RD=""; CM=""
}
trap cleanup EXIT
trap 'echo; echo "interrupted"; exit 2' INT TERM

step "lab VM ($VM_HOST as $VM_USER)"
echo "(the key of $VM_USER may ask its passphrase once)"
vm true || die "ssh $VM_HOST as $VM_USER failed (VM running? host key known?)"
VMSRC=$(vm "ip -o route get $HBR" | sed -nE 's/.* src ([0-9.]+).*/\1/p' | head -n 1)
vmsrc=bad
if is_v4 "${VMSRC:-x}"; then
  m=$(( (0xffffffff << (32 - BR_PREFIX)) & 0xffffffff ))
  (( ($(v4int "$VMSRC") & m) == ($(v4int "$HBR") & m) )) && [[ $VMSRC != "$HBR" ]] && vmsrc=ok
fi
echo "VM source address: ${VMSRC:-?} ($vmsrc)"
[[ $vmsrc == ok ]] || die "the VM does not sit on $BR_IF: refused (the scan must come from the lab network)"
vm "command -v nmap" >/dev/null || die "no nmap in the VM: ssh $VM_HOST, then: sudo apt install nmap"

{
  echo "hbr=$HBR"; echo "hup=${HUP:--}"; echo "hvpn=${HVPN:--}"; echo "gw=$GW"
  echo "quick=$QUICK"; echo "inet=$INET"; echo "mode=$MODE"; echo "vmsrc=$vmsrc"
  echo "udpx=$UDPX"; echo "h6=${H6[*]}"
} > "$W/meta"

step "counters before"
counters before
(( ROOT )) && echo "$(wc -l < "$W/counters-before.txt") counters read" || echo "skipped (not the admin)"

step "scan from the VM (its sudo asks once; progress every 30 s)"
RD=$(vm 'mktemp -d') || die "no temp dir in the VM"
[[ $RD =~ ^/tmp/tmp\.[A-Za-z0-9]{10}$ ]] || { RD=""; die "VM temp dir looks wrong"; }
{ declare -f remote_scan; printf '%s\n' 'remote_scan "$@"'; } |
  vmin "cat > '$RD/scan.sh'" || die "upload to the VM failed"
args="$RD $HBR ${HUP:--} ${HVPN:--} $GW $GW_PORTS $QUICK $INET $UDPX ${H6[*]}"
[[ $args =~ ^[A-Za-z0-9/.:,\ _-]+$ ]] || die "arguments: unexpected characters"
# prompt ends with a newline: a line-based output filter (admin-run privacy filter) still shows it
vmt "sudo -p '[VM sudo] password for %u (then Enter):
' bash '$RD/scan.sh' $args" || echo "VM part ended with an error (results below say what is missing)"

step "results from the VM"
names=(remote.done gw-ping.txt v6-self.txt v6-responders.txt inet.txt)
for f in tcp sport53 udp udpx; do for n in br up vpn; do names+=("$f-$n.gnmap"); done; done
names+=(ack-br.gnmap frag-br.gnmap gw.gnmap)
for ((i = 1; i <= ${#H6[@]}; i++)); do names+=("tcp6-$i.gnmap"); done
got=0
for f in "${names[@]}"; do
  if vm "test -f '$RD/$f' && cat -- '$RD/$f'" 2>/dev/null | head -c "$MAX_FILE" > "$W/$f.part" && [[ -s $W/$f.part ]]; then
    mv "$W/$f.part" "$W/$f"; got=$((got + 1))
  else
    rm -f "$W/$f.part"
  fi
done
echo "$got files"

step "counters after"
counters after
(( ROOT )) && echo "done" || echo "skipped (not the admin)"

evaluate | tee "$W/report.txt"
rc=${PIPESTATUS[0]}
echo "kept: $W (report.txt, run.txt, *.gnmap)"
cleanup
trap - EXIT
# let the output filter finish before the caller prints more
exec >&- 2>&-
wait
exit "$rc"
