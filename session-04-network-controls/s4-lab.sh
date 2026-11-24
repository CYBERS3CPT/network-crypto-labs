#!/usr/bin/env bash
# s4-lab.sh — a tiny company inside your Kali: four zones, one firewall.
#
#   sudo ./s4-lab.sh up        build the company (namespaces, cables, fake services)
#   sudo ./s4-lab.sh matrix    test 15 flows and compare them with the policy
#   sudo ./s4-lab.sh status    who is where, and what the firewall currently says
#   sudo ./s4-lab.sh down      demolish everything (your Kali goes back to normal)
#   on <host> <command>        run a command "inside" a host: internet, fw, web, pc, db
#
# Nothing here touches your real network. Every "host" is a Linux network
# namespace on your own Kali: its own interfaces, its own routes, its own
# firewall. The cables are veth pairs. The company is fictional; the packets
# are not.
set -euo pipefail

RUN=/run/s4-lab
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#        host      zone      fw iface  fw address      host address    host MAC
ZONES=( "internet  INTERNET  fw-out    203.0.113.1     203.0.113.66    02:00:00:00:66:66"
        "web       DMZ       fw-dmz    10.10.10.1      10.10.10.10     02:00:00:00:10:10"
        "pc        LAN       fw-lan    10.10.20.1      10.10.20.20     02:00:00:00:20:20"
        "db        DATA      fw-data   10.10.30.1      10.10.30.30     02:00:00:00:30:30" )

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

need_root() {
  [[ $EUID -eq 0 ]] || { echo "Run me with sudo. Namespaces are a root thing." >&2; exit 1; }
}

ip_of() {
  case "$1" in
    internet) echo 203.0.113.66 ;; web) echo 10.10.10.10 ;;
    pc) echo 10.10.20.20 ;;       db)  echo 10.10.30.30 ;;
    *) echo "unknown host: $1" >&2; return 1 ;;
  esac
}

write_fakesvc() {
  cat > "$RUN/fakesvc.py" <<'PY'
# Fake services: enough protocol to be recognised, not enough to be useful.
import socketserver, sys, threading, http.server, datetime

name, log = sys.argv[1], open(sys.argv[2], "a", buffering=1)

def note(msg):
    log.write(f"{datetime.datetime.now():%H:%M:%S} {name} {msg}\n")

def http_handler(body):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "lab-httpd"
        sys_version = ""
        def do_GET(self):
            note(f"HTTP GET {self.path} from {self.client_address[0]}")
            data = (body + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *a):
            pass
    return H

def banner_handler(banner):
    class B(socketserver.BaseRequestHandler):
        def handle(self):
            note(f"TCP connection from {self.client_address[0]}")
            self.request.sendall((banner + "\r\n").encode())
    return B

class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

for spec in sys.argv[3:]:
    port, kind, text = spec.split("|", 2)
    handler = http_handler(text) if kind == "http" else banner_handler(text)
    srv = TS(("0.0.0.0", int(port)), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
note("services up")
threading.Event().wait()
PY
}

start_svc() {  # start_svc <host> "<port|kind|text>"...
  local host=$1; shift
  ip netns exec "$host" setsid python3 "$RUN/fakesvc.py" "$host" "$RUN/$host.log" "$@" \
    >/dev/null 2>&1 < /dev/null &
  echo $! > "$RUN/$host.pid"
}

cmd_up() {
  need_root
  if ip netns list | grep -qw fw; then
    echo "The company already exists. 'sudo ./s4-lab.sh down' first if you want a fresh one."; exit 0
  fi
  mkdir -p "$RUN"
  write_fakesvc

  ip netns add fw
  ip -n fw link set lo up
  ip netns exec fw sysctl -qw net.ipv4.ip_forward=1
  # Let the firewall namespace write its log lines to the kernel log (dmesg).
  sysctl -qw net.netfilter.nf_log_all_netns=1 2>/dev/null || true

  for z in "${ZONES[@]}"; do
    read -r host zone fwif fwip hostip mac <<<"$z"
    ip netns add "$host"
    ip -n "$host" link set lo up
    ip link add "$fwif" netns fw type veth peer name eth0 netns "$host"
    ip -n "$host" link set eth0 address "$mac"
    ip -n fw addr add "$fwip/24" dev "$fwif"
    ip -n "$host" addr add "$hostip/24" dev eth0
    ip -n fw link set "$fwif" up
    ip -n "$host" link set eth0 up
    ip -n "$host" route add default via "$fwip"
    # veth "offloads" leave checksums unfinished; an IDS then ignores the packets.
    ip netns exec fw ethtool -K "$fwif" tx off rx off gro off gso off tso off >/dev/null 2>&1 || true
    ip netns exec "$host" ethtool -K eth0 tx off rx off gro off gso off tso off >/dev/null 2>&1 || true
  done

  start_svc web "80|http|ACME Shop - public website (DMZ zone). Welcome, customer." \
                "22|banner|SSH-2.0-OpenSSH_9.6 web-admin"
  start_svc db  "3306|banner|MariaDB 10.11 - customer database (DATA zone). If you read this from the internet, the firewall has failed." \
                "22|banner|SSH-2.0-OpenSSH_9.6 db-admin"
  start_svc pc  "445|banner|SMB - Finance share on PC-0042 (LAN zone). Salaries.xlsx is in here."
  start_svc internet "80|http|evil.example - the attacker's server. If a server just reached this, you have no egress policy."

  install -m 755 /dev/stdin /usr/local/bin/on <<'SH'
#!/usr/bin/env bash
# on <host> <command...> — run a command inside one of the lab hosts.
if [[ $# -lt 2 ]]; then
  echo "usage: on <internet|fw|web|pc|db> <command...>    e.g.  on internet curl http://10.10.10.10"; exit 1
fi
h=$1; shift
exec sudo ip netns exec "$h" "$@"
SH
  sleep 1
  echo "The company is up. Four zones, one firewall, and no rules yet."
  echo
  cmd_status
}

cmd_down() {
  need_root
  for h in internet web pc db; do
    [[ -f $RUN/$h.pid ]] && kill "$(cat "$RUN/$h.pid")" 2>/dev/null || true
  done
  for ns in internet web pc db fw; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  rm -rf "$RUN" /usr/local/bin/on
  echo "Company demolished. Your Kali is back to normal."
}

cmd_status() {
  ip netns list | grep -qw fw || { echo "No company yet. Run: sudo ./s4-lab.sh up"; exit 1; }
  cat <<'MAP'
                    INTERNET 203.0.113.0/24
                    [internet] .66    listens: 80 (evil.example)
                         |
                      fw-out .1
  DMZ 10.10.10.0/24   +--------+   LAN 10.10.20.0/24
  [web] .10 ---fw-dmz-|   fw   |-fw-lan--- [pc] .20
  listens: 80, 22  .1 +--------+ .1        listens: 445
                      fw-data .1
                         |
                    [db] .30          listens: 3306, 22
                    DATA 10.10.30.0/24
MAP
  echo
  local n; n=$(ip netns exec fw nft list ruleset 2>/dev/null | grep -c . || true)
  if [[ ${n:-0} -eq 0 ]]; then
    echo "Firewall rules: none. Everything can reach everything. (That is the problem.)"
  else
    echo "Firewall rules loaded. See them with:  on fw nft list ruleset"
  fi
}

# from  to        port  service              policy
FLOWS=( "internet web  80   web-site            ALLOW"
        "internet web  22   ssh-admin           DENY"
        "internet db   3306 database            DENY"
        "internet pc   445  file-share          DENY"
        "pc       web  80   web-site            ALLOW"
        "pc       web  22   ssh-admin           ALLOW"
        "pc       db   22   ssh-admin           ALLOW"
        "pc       db   3306 database            DENY"
        "pc       internet 80 browsing          ALLOW"
        "web      db   3306 database            ALLOW"
        "web      db   22   ssh-admin           DENY"
        "web      pc   445  file-share          DENY"
        "web      internet 80 egress            DENY"
        "db       internet 80 egress            DENY"
        "db       pc   445  file-share          DENY" )

cmd_matrix() {
  need_root
  ip netns list | grep -qw fw || { echo "No company yet. Run: sudo ./s4-lab.sh up"; exit 1; }
  local ok=0 total=0
  printf "\n  %-3s %-9s %-9s %-6s %-11s %-8s %-9s %s\n" "#" FROM TO PORT SERVICE POLICY OBSERVED RESULT
  printf "  %s\n" "----------------------------------------------------------------------------"
  for f in "${FLOWS[@]}"; do
    read -r src dst port svc policy <<<"$f"
    total=$((total+1))
    if ip netns exec "$src" timeout 2 bash -c "exec 3<>/dev/tcp/$(ip_of "$dst")/$port" 2>/dev/null; then
      obs=OPEN; want=ALLOW
    else
      obs=BLOCKED; want=DENY
    fi
    if [[ $want == "$policy" ]]; then res="ok"; ok=$((ok+1)); else res="MISMATCH"; fi
    printf "  %-3s %-9s %-9s %-6s %-11s %-8s %-9s %s\n" "$total" "$src" "$dst" "$port" "$svc" "$policy" "$obs" "$res"
  done
  echo
  echo "  $ok of $total flows match the policy."
  if [[ $ok -eq $total ]]; then
    echo "  The firewall does what the policy says. Now go and prove it from somewhere else."
  else
    echo "  Every MISMATCH is either a missing rule, a rule too wide, or a policy nobody agreed on."
  fi
  echo
}

case "${1:-}" in
  up) cmd_up ;; down) cmd_down ;; status) cmd_status ;; matrix) cmd_matrix ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown command: $1"; usage; exit 1 ;;
esac
