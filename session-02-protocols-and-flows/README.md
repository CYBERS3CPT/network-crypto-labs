# Session 2 — Network protocols, flows and attack surface

Ethernet, IP, routing, TCP, UDP, connection tracking, DNS, DHCP, and what
"exposed" actually means. Ten exercises, about an hour of hands-on, and a flow
table at the end that Practical 1 starts from.

The whole session in one sentence: a packet carries four different answers to
"who are you?", none of them is authenticated, and there is a different tool
for reading each one.

| Header | Identifies | Valid for | Rewritten by |
|---|---|---|---|
| Ethernet | a MAC address | one link | every router |
| IP | a host, allegedly | end to end | NAT, proxies |
| TCP / UDP | a service and a conversation | end to end | NAT, for the ports |
| Payload | whatever the application claims | end to end | nobody. Or everybody, if it is cleartext |

---

## Before you start

**Scope.** Your two VMs, the host-only segment between them, and the public
endpoints named below (`1.1.1.1`, `8.8.8.8`, `nova.pt`, `example.com`). Nothing
else. Not the gateway, not the host, not your neighbour, not the campus. The
scan in exercise 9 goes to *your* target VM, and only there.

**Two terminals.** One captures, one generates. Capture first, generate second,
stop the capture third. Terminal 1 in this README is always the capture.

**One log.**

```bash
mkdir -p ~/s2 && cd ~/s2
script -a ~/s2/session2.log
date -Is
```

**Interface names.** The slides say `eth0` (NAT, towards the internet) and
`eth1` (host-only, the lab segment, `192.168.56.0/24`). Your VM may call them
`ens33` and `ens37`, or `enp0s3` and `enp0s8`, depending on who built it and
in what mood. Run `./lab-check.sh` once and write down which is which. Every
command below uses `eth0`/`eth1`; substitute accordingly, and substitute
`<target>` with your target VM's address on the lab segment.

```bash
./lab-check.sh            # tools present? interfaces? which one is the lab?
```

---

## Block 1 — The stack in practice

### Exercise 1 — Watch ARP happen (5 min)

**Why.** A MAC address is a link-local name: two hops away, nobody has ever
heard of it. ARP maps IP to MAC by shouting at the whole segment and believing
the first thing that shouts back. There is no authentication. None. Any host on
your VLAN can claim to be the router, and your kernel will thank it politely and
update its table.

```bash
ip -br link                              # your MAC addresses
sudo ip neigh flush all                  # forget every neighbour
ip neigh                                 # empty, or nearly
sudo tcpdump -i eth1 -n arp &            # terminal 1
ping -c 2 <target>                       # terminal 2
ip neigh                                 # look again
```

**What you should see.** In terminal 1, a `Request who-has <target> tell
<you>` followed by a `Reply <target> is-at <mac>`. In the last `ip neigh`, a
new entry for `<target>` in state `REACHABLE`.

If the request appears and no reply does, the target VM is off, on the wrong
segment, or you are capturing on the wrong interface. In that order of
likelihood.

**Log.** The request/reply pair and the resulting neighbour entry.

**Answer in one line.** Who *could* have answered that request instead of the
target? (Hint: how many hosts heard it?)

### Exercise 2 — Make the kernel explain itself (5 min)

**Why.** The prefix defines "inside". A host with the wrong mask disagrees with
its neighbours about what is local, and traffic it believes is local never goes
to the gateway, and therefore never goes past your firewall. Subnetting is a
security control that happens to involve arithmetic, not the other way round.

| Notation | Hosts | Typical use |
|---|---|---|
| `10.0.0.0/8` | 16.7 M | enterprise core, badly subnetted |
| `192.168.56.0/24` | 254 | your host-only lab segment |
| `10.20.30.0/28` | 14 | a segment sized for its purpose |
| `0.0.0.0/0` | everything | the default route, and the default firewall mistake |

```bash
ip -br a                                 # addresses, with prefixes
ip route                                 # the whole table
ip route get <target>                    # the decision for the lab segment
ip route get 1.1.1.1                     # the decision for the internet
ip route get 127.0.0.1                   # and for yourself
```

**What you should see.** Three different answers. The lab target goes out
`eth1` with your `192.168.56.x` source and *no* `via` (it is on-link). The
internet goes out `eth0` via your NAT gateway. Loopback goes out `lo` from
`127.0.0.1`.

**Log and explain.** For each of the three: which interface, which source
address, which gateway if any, and *why* they differ. "The traffic leaves
through eth0" is an assumption. `ip route get` turns it into evidence.

### Exercise 3 — Two traceroutes, two paths (6 min)

**Why.** Routing is hop by hop: every router decides on its own, using only its
own table, and nobody sees the whole path. The return path need not match the
outbound one. TTL is a hop counter, not a control; it is the only reason a
routing loop ever stops, and the only reason traceroute works at all.

```bash
ping -c 3 -t 1 1.1.1.1                   # TTL 1: who complains, and how?
traceroute 1.1.1.1                       # UDP probes, high ports, by default
sudo traceroute -I 1.1.1.1               # ICMP echo probes
sudo tcpdump -i eth0 -n icmp             # terminal 1: watch the complaints arrive
```

(`-t` sets the TTL on Linux `ping`. On macOS it sets a timeout and `-m` sets
the TTL. You are in the VM. Stay in the VM.)

**What you should see.** The TTL-1 ping gets `Time to live exceeded` from your
first hop, which is the router telling you it threw your packet away and is
sorry. The two traceroutes agree on some hops and disagree on others: some
routers answer ICMP probes but drop UDP to odd ports, some rate-limit ICMP
errors, some answer nothing to anybody. Those are the `* * *` lines.

**Compare.** Where do the two traceroutes disagree? Which hops answer one probe
type and not the other?

**Then answer, honestly.** Three stars in a row. What can you actually
conclude? The correct answer is shorter than you would like. Stars are not
failures. They are policy, and policy is what you are learning to read.

---

## Block 2 — Transport, state and flows

### Exercise 4 — Three outcomes, three fingerprints (7 min)

**Why.** TCP opens with three packets and then promises to keep state. From an
attacker's point of view the interesting part ends at packet two: the SYN-ACK
says "a service exists and is listening", and nothing after that says anything
more. That is why a SYN scan stops there, and why it is cheap and quiet.

| Packet | Flags | What an attacker learns |
|---|---|---|
| 1 | SYN | nothing yet |
| 2 | SYN, ACK | the service exists and is listening |
| 3 | ACK | nothing more; the scan already ended at 2 |
| — | RST | the port is closed but the host is alive |

```bash
sudo tcpdump -i eth1 -n "tcp and host <target>" &      # terminal 1

nc -vz <target> 22                                       # open
nc -vz <target> 9999                                     # closed
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP       # on the TARGET VM
nc -vz <target> 8080                                     # filtered
```

**What you should see, and what it means.**

| You observe | You may conclude |
|---|---|
| SYN, SYN-ACK, ACK | service listening and reachable *from here* |
| SYN, RST | host alive, nothing listening on that port |
| SYN, SYN, SYN… then `nc` gives up | something dropped it. You do not know what, or where |

Note the retransmissions in the third case: the kernel tries again with
increasing gaps, because as far as it knows the packet was merely lost.
Silence and refusal look different on TCP. Remember that for the next exercise,
where they do not.

**Undo when done, on the target:**

```bash
sudo iptables -D INPUT -p tcp --dport 8080 -j DROP
```

Leaving it in place will make exercise 9 confusing and your future self
irritated.

### Exercise 5 — What is your machine offering? (5 min)

**Why.** UDP has no handshake, so there is no moment where both sides agree a
conversation started; no RST, so a closed port may answer with an ICMP error or
with nothing; and a trivially spoofable source, so the reply goes wherever the
header says. Firewalls invent UDP "state" with a timer, which is how DNS
survives NAT. Amplification attacks are the other consequence: a small forged
request, a large reply, someone else's address.

But before worrying about who can reach you, find out what you are offering.

```bash
ss -tlnp                                 # TCP listening, with the process
ss -ulnp                                 # UDP listening
ss -tan state established                # live conversations
ss -s                                    # summary by state
```

**Read the address column.** `127.0.0.1` means only this host can talk to it.
`0.0.0.0` or `[::]` means anyone who can route here. The difference between
those two is the difference between a service and an exposure.

**Find and log.** One service you did not know was running. Name it, and the
process behind it. Everyone has one. It is usually something with `systemd-` in
front of it, or a printer daemon on a machine that has never met a printer.

A listening socket is an *offer*. Whether anyone can accept it is a different
question, and exercise 9 asks it.

### Exercise 6 — Read the firewall's memory (6 min)

**Why.** A flow is a row in a table, keyed on the 5-tuple: source IP, source
port, destination IP, destination port, protocol. Everything you will ever
build keys on it: firewall rules, NAT translations, load-balancer sessions,
NetFlow records, SIEM correlation. And its limit is fixed: the tuple says who
talked to whom, for how long, and how much. It says nothing about what was said.

Connection tracking is that table, live, in your kernel.

```bash
sudo apt install -y conntrack            # if missing
sudo conntrack -E &                      # terminal 1: events as they happen

nc <target> 22                           # terminal 2: open it, leave it open
dig @1.1.1.1 example.com                 # a UDP flow, for contrast
sudo conntrack -L | head                 # the live table

cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout
```

**What you should see.** In terminal 1, the SSH entry appear as `[NEW]`, then
`[UPDATE]` to `ESTABLISHED`. The DNS entry appear as `[NEW]` with `udp` and
then, some seconds later, `[DESTROY]`, because the timer ran out and nobody
said otherwise. That is what UDP "state" is: a guess with an expiry date.

**Log the two timeouts.** Typically `432000` seconds for established TCP (five
days) and `30` for UDP. Those two numbers explain most "my session dropped"
tickets you will ever receive, because somewhere between the client and the
server there is a middlebox with a much smaller number.

(If `nf_conntrack` was not loaded, the first `conntrack -L` loads it, and the
table only fills from that moment. Run the `nc` and `dig` again if the table
looks empty.)

---

## Break

Ten minutes. Your log should have six entries. If it has none, you cannot
build the flow table in block 4. Find a neighbour now, while there is still
time to copy their commands and not their answers.

---

## Block 3 — Name and address services

### Exercise 7 — Follow a name to its source (6 min)

**Why.** DNS decides where your traffic goes, in five steps, and every step is a
chance to lie to you:

| # | Step | Who could alter the answer |
|---|---|---|
| 1 | The application asks the stub resolver | anything with write access to `/etc/hosts` |
| 2 | The stub asks the configured resolver | whoever wrote `resolv.conf`, which is usually DHCP |
| 3 | The resolver checks its cache | a poisoned cache lies to everyone behind it until the TTL expires |
| 4 | Recursion: root, TLD, authoritative | anyone on the path, if the query is cleartext UDP |
| 5 | The answer returns and is cached | the zone owner, and whoever compromised their registrar |

Without DNSSEC nothing in that chain is signed. You are trusting a sequence of
strangers to tell you where your bank is, and they have been quite reliable so
far, which is not the same as trustworthy.

```bash
cat /etc/resolv.conf                     # who are you asking, and who decided that?
dig nova.pt +trace                       # root → TLD → authoritative, step by step
dig nova.pt NS +short                    # who is authoritative
dig @1.1.1.1 nova.pt | grep -E "ANSWER|IN.A"
dig @8.8.8.8 nova.pt | grep -E "ANSWER|IN.A"     # same answer? same TTL?
dig nova.pt ; dig nova.pt                # twice. Watch the TTL fall.
```

**What you should see.** `+trace` walks down from the root servers through
`.pt` to the authoritative servers for `nova.pt`. The two public resolvers give
the same address but, almost certainly, different TTLs, because they cached the
answer at different moments. Your own two runs show the TTL dropping by however
many seconds passed between them.

(If `resolv.conf` says `127.0.0.53`, that is `systemd-resolved` in front of the
real one. `resolvectl status` tells you who it is actually asking.)

**Log.** The authoritative servers, and the TTL difference between the two runs.

**Answer.** A falling TTL proves that someone behind that resolver asked
recently. What could an attacker learn from that? Think about what "someone
asked for `vpn.yourcompany.com` in the last 40 seconds" tells a person who is
watching.

Two notes for later. DNS is allowed out of every network, so everything uses
it: exfiltration hides in long random subdomains, command-and-control hides in
TXT records. And DNS over HTTPS protects the user from the network while
removing the network's visibility. Both are true at once. If you log one
protocol in your whole estate, log DNS.

### Exercise 8 — Capture your own lease (6 min)

**Why.** DHCP hands your machine its address, its default gateway, its DNS
resolver, sometimes its static routes, its NTP server and its boot file. It does
this over four broadcast packets (DISCOVER, OFFER, REQUEST, ACK), and your
machine accepts the first offer that arrives. No credentials are involved at
any point. A rogue DHCP server is a full man-in-the-middle with no exploit and
no vulnerability: just a faster answer.

```bash
sudo tcpdump -i eth0 -n -v "port 67 or port 68" -w dhcp.pcap &     # terminal 1
sudo dhclient -r eth0 && sudo dhclient eth0                         # terminal 2
sudo pkill tcpdump
tshark -r dhcp.pcap -V | grep -E "Message type|Router|Domain Name Server|Lease"
```

**Two warnings, both learned the hard way by someone.**

- `dhclient -r` *releases* the lease, which drops the address. If you are
  connected to the VM over SSH **through `eth0`**, that is the end of your
  session. Use the console, or a second interface, or accept that you will be
  reconnecting.
- Not every VM has `dhclient`. Ubuntu with `systemd-networkd` wants
  `sudo networkctl renew eth0`; with NetworkManager it is
  `sudo nmcli device reapply eth0` or `nmcli con up <name>`. The capture is the
  same either way.

**What you should see.** Four `Message type` lines (Discover, Offer, Request,
ACK) and, in the ACK, every parameter the server handed you.

**Log.** That list of parameters, from the ACK. It is exactly the list an
attacker gets to choose for you on a network without DHCP snooping, and the
mitigations (DHCP snooping, port security, 802.1X) are all Layer 2 controls,
which is a later session.

Nobody runs a rogue DHCP server today. That experiment is Practical 3, in the
isolated segment, with written instructions, because "I was only testing"
does not survive a room full of people who suddenly cannot reach the internet.

---

## Block 4 — Exposure and visibility

### Exercise 9 — Scan your own target VM (6 min)

**Why.** "Listening" is not "reachable". They are answered by different
things, from different places, with different evidence:

| Question | Answered by | Evidence |
|---|---|---|
| Is something listening? | the host itself | `ss -tlnp` (exercise 5) |
| Can I reach it from here? | the path between us | `nc -vz` / `nmap`, *from a stated location* |
| Who else can reach it? | routing, plus every policy on the way | rules, NAT tables, ACLs, read rather than guessed |
| Should it be reachable? | a human decision | written, dated, owned; or it does not exist |

Exposure is a property of a *path*, not of a host. Every claim about it must say
"from where".

**Scope, once more.** Your own target VM on the lab segment. Not the gateway,
not the host, not your neighbour, not the campus.

```bash
sudo nmap -sS -p- --open <target>              # which TCP ports answer, all 65535
sudo nmap -sV -p <open-ports> <target>         # what claims to be there
sudo nmap -sU --top-ports 20 <target>          # UDP: slow, and ambiguous
sudo tcpdump -i eth1 -n -c 40 tcp              # terminal 1: what a scan looks like on the wire
```

**What you should see.** A short list of open TCP ports (22, and whatever the
target's image ships with), a version guess for each, and a UDP result full of
`open|filtered`, which is nmap's way of saying "no answer, and on UDP that means
nothing". The tcpdump shows a wall of SYNs to sequential ports with the
occasional SYN-ACK: this is what the target's owner sees, and what an IDS
signature looks for.

If port 8080 shows as `filtered`, you forgot the undo in exercise 4.

**Log.** Open ports, claimed versions, and the command that produced each
line.

**Then state the limits.** What does this scan *not* tell you? Patch level.
Whether authentication is required. Whether anyone is watching. The version
string is a claim by the service, and services can be configured to claim
anything. Write the list.

Six findings you will meet in every real environment, none of which has a
CVE, all of which are decisions somebody made:

| Finding | What it usually looks like |
|---|---|
| any/any rules | added "temporarily", never reviewed. The evidence is the rule itself, with its comment and its date |
| management planes on the user VLAN | SSH, RDP, iDRAC and switch web UIs reachable from any desk |
| cleartext protocols still enabled | Telnet, FTP, SNMPv1/v2c, HTTP admin pages. "For the old printer" |
| IPv6 enabled, unfiltered | dual-stack host, IPv4-only rules. The traffic does not break the policy, it walks around it |
| flat addressing | one broadcast domain for the servers, the laptops and the badge reader |
| no egress policy | inbound guarded, outbound wide open. Every C2 channel is grateful |

### Exercise 10 — Build your first flow table (10 min, finish tonight)

**Why.** Where you capture decides what you can know:

| Capture point | You see | You are blind to |
|---|---|---|
| on the host | its own traffic, post-decryption, with process names | everything happening on other hosts |
| on the segment | broadcast, ARP, DHCP, lateral movement between neighbours | anything that left the segment, and all payload if encrypted |
| at the gateway | every flow entering or leaving; the egress story | all lateral traffic, which is where intrusions actually spread |
| SPAN / mirror port | in principle everything crossing the switch | whatever it dropped under load, silently |

A finding with no capture point is unfalsifiable. Name the interface, the
filter and the clock, every time.

```bash
sudo tcpdump -i eth1 -w s2_flows.pcap &        # terminal 1: capture first
ping -c 3 <target> ; nc -vz <target> 22 ; nc -vz <target> 9999 ; dig nova.pt
sudo pkill tcpdump

tshark -r s2_flows.pcap -q -z conv,tcp         # TCP conversations
tshark -r s2_flows.pcap -q -z conv,udp         # UDP conversations
```

(The `dig` goes out `eth0`, not `eth1`, unless your resolver happens to live
on the lab segment. Whether it shows up in this capture is the first thing the
capture point cannot tell you about. Notice that, and write it down.)

**The table.** One row per flow, in your log:

| 5-tuple | packets / bytes | outcome | expected / observed | capture point |
|---|---|---|---|---|

`flow-table.py` fills the first three columns from the pcap and leaves the
other two blank, on purpose:

```bash
./flow-table.py ../examples/s2_sample.pcap                       # what it looks like when it works
./flow-table.py s2_flows.pcap --capture-point "eth1, no filter"  # now yours
```

**Then three sentences.** One flow you expected and saw. One you did not
expect. One thing this capture point cannot tell you.

**Keep `s2_flows.pcap`.** Practical 1 starts from it, and "I deleted it" is not
a capture point.

---

## What today was actually about

- Four headers, four unauthenticated identities, and a different tool to read
  each one.
- State is a table, not a property of the wire. Tables disagree, expire, and
  fill up.
- Your first three trust boundaries: the broadcast domain, the prefix, and the
  capture point.

## Before Session 3

1. Finish the flow table and the three sentences.
2. Bring `s2_flows.pcap`.
3. Kurose & Ross, chapter 3 (transport). Skim chapter 4 (network layer).
4. Post one capture you could not interpret on the forum. Everybody has one.
   The people who say they do not have one have not looked.

## Scripts in this folder

| Script | What it does |
|---|---|
| `lab-check.sh` | checks that `tcpdump`, `tshark`, `nc`, `dig`, `nmap`, `traceroute`, `conntrack` and `ss` are installed, lists your interfaces with addresses, and shows the route decisions for the lab target and the internet so you can name your interfaces with evidence |
| `flow-table.py` | reads a pcap with `tshark`, groups packets into bidirectional flows keyed on the 5-tuple, infers the outcome from the flags it saw, and prints the table in Markdown. It will not fill in what you expected |
