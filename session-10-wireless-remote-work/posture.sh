#!/usr/bin/env bash
# posture.sh — the questions a "device posture" check asks before letting a
# laptop into the company, asked of your own Kali. Read-only: it changes nothing.
#
#   ./posture.sh            the report and the verdict
#   ./posture.sh --json     the same, as the JSON a VPN gateway or ZTNA broker would receive
#
# Real products (Intune compliance, Jamf, CrowdStrike ZTA, Cisco Duo, Tailscale
# posture…) ask the same kind of questions with better tooling. The decision
# logic at the bottom is the part worth arguing about.
set -uo pipefail

case ${1:-} in -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; esac
json=false; [[ ${1:-} == --json ]] && json=true
declare -a NAMES RESULTS WHY

check() {  # check <name> <PASS|FAIL|WARN> <why>
  NAMES+=("$1"); RESULTS+=("$2"); WHY+=("$3")
}

# 1. Disk encryption: is there a dm-crypt/LUKS device under the root filesystem?
if lsblk -no TYPE 2>/dev/null | grep -qx crypt; then
  check "disk-encryption" PASS "a LUKS/dm-crypt volume is present"
else
  check "disk-encryption" FAIL "no encrypted volume: a stolen laptop is a readable disk"
fi

# 2. Host firewall: any nftables/iptables rules, or ufw active?
rules=$( (sudo -n nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null) | grep -c 'hook input' || true)
if command -v ufw >/dev/null && sudo -n ufw status 2>/dev/null | grep -q 'Status: active'; then
  check "host-firewall" PASS "ufw is active"
elif [[ ${rules:-0} -gt 0 ]]; then
  check "host-firewall" PASS "an nftables input hook exists"
else
  check "host-firewall" FAIL "no input filtering: anyone on the café Wi-Fi can knock on every port"
fi

# 3. Updates: how long since the package lists were refreshed, and how many upgrades wait?
lists=/var/lib/apt/lists
if [[ -d $lists ]]; then
  age=$(( ( $(date +%s) - $(stat -c %Y "$lists" 2>/dev/null || echo 0) ) / 86400 ))
  pending=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
  if (( age > 14 )); then
    check "updates" FAIL "package lists are $age days old — the laptop does not even know what it is missing"
  elif (( pending > 50 )); then
    check "updates" WARN "$pending upgrades waiting (lists refreshed $age days ago)"
  else
    check "updates" PASS "$pending upgrades waiting, lists refreshed $age days ago"
  fi
else
  check "updates" WARN "not a Debian-family system; check updates by hand"
fi

# 4. Remote login: an SSH server listening on all interfaces is an open door on public Wi-Fi.
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*|\[::\]):22$'; then
  check "ssh-exposed" WARN "sshd listens on every interface, including the café's"
else
  check "ssh-exposed" PASS "no SSH server listening on all interfaces"
fi

# 5. Screen lock / user: are we running the session as root?
if [[ ${SUDO_USER:-$USER} == root ]]; then
  check "daily-user" FAIL "the daily user is root"
else
  check "daily-user" PASS "daily user is '${SUDO_USER:-$USER}', not root"
fi

# ---------------------------------------------------------------- the decision
fails=0; warns=0
for r in "${RESULTS[@]}"; do [[ $r == FAIL ]] && ((fails++)); [[ $r == WARN ]] && ((warns++)); done
if (( fails == 0 )); then
  verdict="FULL";    meaning="tunnel to the intranet"
elif [[ ${RESULTS[0]} == FAIL ]] && (( fails >= 2 )); then
  verdict="DENY";    meaning="no company access from this device"
else
  verdict="LIMITED"; meaning="email and the update server only, until fixed"
fi

if $json; then
  printf '{\n  "device": "%s",\n  "checks": {\n' "$(hostname)"
  for i in "${!NAMES[@]}"; do
    sep=,; (( i == ${#NAMES[@]} - 1 )) && sep=
    printf '    "%s": {"result": "%s", "why": "%s"}%s\n' "${NAMES[$i]}" "${RESULTS[$i]}" "${WHY[$i]}" "$sep"
  done
  printf '  },\n  "verdict": "%s"\n}\n' "$verdict"
else
  echo "Device posture — $(hostname)"
  echo
  for i in "${!NAMES[@]}"; do printf '  %-4s  %-16s %s\n' "${RESULTS[$i]}" "${NAMES[$i]}" "${WHY[$i]}"; done
  echo
  echo "  $fails failed, $warns warnings  →  verdict: $verdict ($meaning)"
  echo
  echo "  The rule used: no failures = FULL; disk not encrypted plus any other failure = DENY;"
  echo "  anything else = LIMITED. Exercise 12 asks you whether that rule is any good."
fi
