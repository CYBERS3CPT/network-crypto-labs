#!/usr/bin/env bash
# lab-check.sh — is this VM ready for Session 2, and which interface is which?
#
# Read-only. It runs nothing that changes state, sends nothing to anyone, and
# refuses to guess which interface is your lab segment: it shows you the
# evidence and lets you decide. "The traffic leaves through eth0" is an
# assumption until `ip route get` says so.
#
#   ./lab-check.sh                    # tools, interfaces, routes
#   ./lab-check.sh 192.168.56.20      # ...and the route decision for your target VM

set -u

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

TARGET="${1:-}"
missing=0

if [[ -t 1 ]]; then
  G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'
else
  G=""; Y=""; R=""; B=""; N=""
fi

echo "${B}Tools${N}"
# tool : package that provides it on Debian/Ubuntu : which exercise needs it
while IFS=: read -r tool pkg used; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "  %s✓%s %-11s %s\n" "$G" "$N" "$tool" "$used"
  else
    printf "  %s✗%s %-11s %s   → sudo apt install -y %s\n" "$R" "$N" "$tool" "$used" "$pkg"
    missing=1
  fi
done <<'TOOLS'
ip:iproute2:everything
ss:iproute2:ex 5
tcpdump:tcpdump:ex 1, 3, 4, 8, 9, 10
tshark:tshark:ex 8, 10
nc:netcat-openbsd:ex 4, 6, 10
dig:bind9-dnsutils:ex 6, 7, 10
traceroute:traceroute:ex 3
nmap:nmap:ex 9
conntrack:conntrack:ex 6
script:bsdutils:the log. Non-negotiable
TOOLS

if command -v dhclient >/dev/null 2>&1; then
  printf "  %s✓%s %-11s %s\n" "$G" "$N" "dhclient" "ex 8"
elif command -v networkctl >/dev/null 2>&1; then
  printf "  %s~%s %-11s %s\n" "$Y" "$N" "dhclient" "not here; ex 8 uses 'sudo networkctl renew <iface>' instead"
elif command -v nmcli >/dev/null 2>&1; then
  printf "  %s~%s %-11s %s\n" "$Y" "$N" "dhclient" "not here; ex 8 uses 'sudo nmcli device reapply <iface>' instead"
else
  printf "  %s✗%s %-11s %s\n" "$R" "$N" "dhclient" "ex 8   → sudo apt install -y isc-dhcp-client"
  missing=1
fi

echo
echo "${B}Interfaces${N} (name, state, addresses — you decide which is the lab segment)"
ip -br a | sed 's/^/  /'

echo
echo "${B}Routes${N}"
ip route | sed 's/^/  /'

echo
echo "${B}Route decisions${N}"
printf "  internet  (1.1.1.1):   "; ip route get 1.1.1.1 2>/dev/null | head -1 | sed 's/ uid .*//' || echo "no route. NAT interface down?"
if [[ -n "$TARGET" ]]; then
  printf "  target    (%s): " "$TARGET"; ip route get "$TARGET" 2>/dev/null | head -1 | sed 's/ uid .*//' || echo "no route. Wrong address, or the host-only adapter is not attached."
else
  echo "  target:   not given. Re-run with your target VM's address to see which interface it leaves by."
fi

echo
echo "${B}Housekeeping${N}"
if pgrep -x script >/dev/null 2>&1; then
  printf "  %s✓%s a script(1) session is running. The log is being kept.\n" "$G" "$N"
else
  printf "  %s~%s no script(1) session. Start one before the first exercise: script -a ~/s2/session2.log\n" "$Y" "$N"
fi
if command -v iptables >/dev/null 2>&1 && sudo -n iptables -S INPUT 2>/dev/null | grep -q -- '--dport 8080 -j DROP'; then
  printf "  %s~%s the exercise 4 DROP rule for port 8080 is still loaded. Exercise 9 will report it as filtered, which is correct and confusing.\n" "$Y" "$N"
fi

echo
if [[ $missing -eq 0 ]]; then
  echo "${G}Ready.${N} Two terminals. Capture first."
else
  echo "${Y}Install the missing tools first.${N} Nothing above will be graded on how quickly you found out it was missing."
  exit 1
fi
