#!/usr/bin/env bash
# s10-lab.sh — working from a café, inside your Kali: a laptop, the café's
# Wi-Fi router, a news website, and the office with its VPN gateway and intranet.
#
#   sudo ./s10-lab.sh up             build it (namespaces, cables, fake services, office VPN)
#   sudo ./s10-lab.sh status         the map, the office public key, and who is enrolled
#   sudo ./s10-lab.sh enrol <pubkey> IT adds your laptop's public key to the VPN gateway
#   sudo ./s10-lab.sh revoke         IT removes every laptop from the VPN (lost laptop!)
#   sudo ./s10-lab.sh down           demolish everything (your Kali goes back to normal)
#   on <host> <command>              run a command "inside" a host: laptop, cafe, site, office, intranet
#
# Nothing here touches your real network or a real radio. The café "Wi-Fi" is a
# veth cable called wlan0 — what matters tonight is that the café's router sees
# every packet the laptop sends, which is exactly true of real public Wi-Fi.
set -euo pipefail

RUN=/run/s10-lab
HOSTS="laptop cafe site office intranet"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

need_root() {
  [[ $EUID -eq 0 ]] || { echo "Run me with sudo. Namespaces are a root thing." >&2; exit 1; }
}

need_tools() {
  local missing=()
  for t in wg nft tcpdump curl python3; do command -v "$t" >/dev/null || missing+=("$t"); done
  if ((${#missing[@]})); then
    echo "Missing: ${missing[*]}.  On Kali:  sudo apt install -y wireguard-tools nftables tcpdump curl" >&2
    exit 1
  fi
  if ! ip link add s10probe type wireguard 2>/dev/null; then
    echo "This kernel has no WireGuard module. On Kali it is built in; try: sudo modprobe wireguard" >&2
    exit 1
  fi
  ip link del s10probe
}

# A cable between two namespaces: cable <nsA> <ifA> <addrA> <nsB> <ifB> <addrB>
cable() {
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  ip -n "$1" addr add "$3" dev "$2"; ip -n "$1" link set "$2" up
  ip -n "$4" addr add "$6" dev "$5"; ip -n "$4" link set "$5" up
  ip netns exec "$1" ethtool -K "$2" tx off rx off gro off gso off tso off >/dev/null 2>&1 || true
  ip netns exec "$4" ethtool -K "$5" tx off rx off gro off gso off tso off >/dev/null 2>&1 || true
}

write_websvc() {
  cat > "$RUN/websvc.py" <<'PY'
# Tiny plain-HTTP sites. Enough to be read on the wire; nothing to be useful.
import http.server, sys, urllib.parse
port, title, body = int(sys.argv[1]), sys.argv[2], sys.argv[3]

class H(http.server.BaseHTTPRequestHandler):
    server_version, sys_version = "lab-httpd", ""
    def reply(self, text):
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self.reply(f"{title}\n{body}\nYou are {self.client_address[0]}, as far as this server can tell.\n")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(n).decode(errors="replace"))
        who = form.get("user", ["?"])[0]
        self.reply(f"{title}\nWelcome back, {who}. (This site checks nothing. It is a lab.)\n")
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
PY
}

web() {  # web <ns> <title> <body>
  ip netns exec "$1" python3 "$RUN/websvc.py" 80 "$2" "$3" >/dev/null 2>&1 &
  echo $! > "$RUN/$1.pid"
}

cmd_up() {
  need_root; need_tools
  if ip netns list | grep -qw office; then
    echo "The lab already exists. 'sudo ./s10-lab.sh down' first if you want a fresh one."; exit 0
  fi
  mkdir -p "$RUN"; chmod 700 "$RUN"
  write_websvc

  for h in $HOSTS; do ip netns add "$h"; ip -n "$h" link set lo up; done

  #     ns      iface  address           ns       iface  address
  cable laptop  wlan0  192.168.50.10/24  cafe     wlan0  192.168.50.1/24    # café Wi-Fi
  cable cafe    wan0   198.51.100.1/24   office   wan0   198.51.100.10/24   # the internet, part 1
  cable cafe    wan1   203.0.113.1/24    site     eth0   203.0.113.80/24    # the internet, part 2
  cable office  lan0   10.20.0.1/24      intranet eth0   10.20.0.20/24      # office LAN

  ip -n laptop   route add default via 192.168.50.1
  ip -n site     route add default via 203.0.113.1
  ip -n office   route add default via 198.51.100.1
  ip -n intranet route add default via 10.20.0.1
  ip netns exec cafe   sysctl -qw net.ipv4.ip_forward=1
  ip netns exec office sysctl -qw net.ipv4.ip_forward=1

  # The office VPN gateway. Its private key never leaves $RUN (root only).
  (umask 077; wg genkey > "$RUN/office.key")
  wg pubkey < "$RUN/office.key" > "$RUN/office.pub"
  ip -n office link add wg0 type wireguard
  ip netns exec office wg set wg0 listen-port 51820 private-key "$RUN/office.key"
  ip -n office addr add 10.99.0.1/24 dev wg0
  ip -n office link set wg0 up

  # Office firewall: the intranet is reachable only through the tunnel.
  # Traffic leaving the tunnel for the internet is NATed (for the full-tunnel exercise).
  ip netns exec office nft -f - <<'NFT'
table inet office {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" accept
    iifname "lan0" oifname "wan0" accept
  }
}
table ip nat {
  chain post {
    type nat hook postrouting priority 100;
    iifname "wg0" oifname "wan0" masquerade
  }
}
NFT

  web site     "worldnews.example - plain HTTP, like too much of the web still is" "Today: nothing happened."
  web office   "office.example - public page of the company" "Staff login is a POST to /login."
  web intranet "intranet - HR portal (office LAN only)" "payroll-2025.csv, holidays.xlsx, the usual."

  install -m 755 /dev/stdin /usr/local/bin/on <<'SH'
#!/usr/bin/env bash
# on <host> <command...> — run a command inside one of the lab hosts.
if [[ $# -lt 2 ]]; then
  echo "usage: on <laptop|cafe|site|office|intranet> <command...>    e.g.  on laptop curl http://203.0.113.80"; exit 1
fi
h=$1; shift
exec sudo ip netns exec "$h" "$@"
SH
  sleep 1
  echo "The lab is up. You are the laptop, sitting in a café."
  echo
  cmd_status
}

cmd_status() {
  ip netns list | grep -qw office || { echo "No lab yet. Run: sudo ./s10-lab.sh up"; exit 1; }
  cat <<'MAP'
  [laptop] 192.168.50.10 --wlan0-- [cafe] 192.168.50.1      (the café router sees everything here)
                                     |  \
                    198.51.100.0/24 wan0  wan1 203.0.113.0/24
                                     |      \
     VPN gateway, UDP 51820 → [office] .10  [site] .80   worldnews.example (plain HTTP)
                                     | lan0 10.20.0.1
                              [intranet] 10.20.0.20       HR portal, office LAN only

  Tunnel addresses: office 10.99.0.1, laptop 10.99.0.2
MAP
  echo
  echo "  Office public key:  $(cat "$RUN/office.pub")"
  echo "  Office endpoint:    198.51.100.10:51820"
  local peers
  peers=$(ip netns exec office wg show wg0 peers 2>/dev/null || true)
  if [[ -n $peers ]]; then
    echo "  Enrolled laptops:   $peers"
    ip netns exec office wg show wg0 latest-handshakes | while read -r k ts; do
      [[ $ts == 0 ]] && echo "                      (no handshake yet)" || echo "                      last handshake $(( $(date +%s) - ts )) s ago"
    done
  else
    echo "  Enrolled laptops:   none — run 'sudo ./s10-lab.sh enrol <your laptop public key>'"
  fi
  if ip -n laptop link show wg0 >/dev/null 2>&1; then
    echo "  Laptop routes:"; ip -n laptop route | sed 's/^/                      /'
  fi
}

cmd_enrol() {
  need_root
  local key=${1:-}
  if [[ ! $key =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "That does not look like a WireGuard public key (44 characters, ending in '=')." >&2
    echo "On the laptop:  on laptop wg show wg0 public-key" >&2; exit 1
  fi
  ip netns exec office wg set wg0 peer "$key" allowed-ips 10.99.0.2/32
  echo "Enrolled. The office will accept tunnel traffic from 10.99.0.2 signed by that key, and nothing else."
}

cmd_revoke() {
  need_root
  for p in $(ip netns exec office wg show wg0 peers); do ip netns exec office wg set wg0 peer "$p" remove; done
  echo "Every laptop removed from the gateway. Their keys are now just random bytes."
}

cmd_down() {
  need_root
  for h in site office intranet; do
    [[ -f $RUN/$h.pid ]] && kill "$(cat "$RUN/$h.pid")" 2>/dev/null || true
  done
  for h in $HOSTS; do
    ip netns pids "$h" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$h" 2>/dev/null || true
  done
  rm -rf "$RUN" /usr/local/bin/on
  echo "Lab demolished. Your Kali is back to normal."
}

case "${1:-}" in
  up) cmd_up ;; status) cmd_status ;; down) cmd_down ;;
  enrol|enroll) cmd_enrol "${2:-}" ;; revoke) cmd_revoke ;;
  -h|--help|help|"") usage ;;
  *) echo "unknown command: $1"; usage; exit 1 ;;
esac
