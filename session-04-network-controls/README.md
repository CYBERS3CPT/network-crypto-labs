# Session 4 — Network security controls

Firewalls, IDS/IPS, secure administration, segmentation, DMZs, NAC, policy
design, control placement and validation. Ten exercises, about an hour on keys,
and at the end a firewall that a scan from the internet cannot get through —
which you then prove, from three different places, because "I added a rule" is a
claim and "I scanned it and the port is filtered" is evidence.

The whole session in one sentence: **a control is a decision you put in the
path, default deny is the only safe place to start, and a control you have not
tested from the right place is a rumour.**

Everything runs inside your own Kali. There is no second VM to build and no
campus network to annoy. One script builds a four-zone company out of Linux
network namespaces; you spend the rest of the session defending it.

---

## Before you start

**Scope.** Everything is inside your Kali, on namespaces the script created
(`internet`, `web`, `pc`, `db`, `fw`). There is no real host on the other end
of any of these packets. Scan them, spoof them, flood them — the worst case is
you run `down` then `up` and start again. Nothing here touches `eth0`, your real
network, or anyone else.

**Root.** Namespaces are a root thing. Every `s4-lab.sh` command wants `sudo`.

**One log.**

```bash
mkdir -p ~/s4 && cd ~/s4
script -a ~/s4/session4.log       # everything you type and everything you see
date -Is                          # first line of every exercise
```

**Build the company once, at the start:**

```bash
cd network-crypto-labs/session-04-network-controls
sudo ./s4-lab.sh up               # four zones, one firewall, no rules yet
./s4-lab.sh status                # the map, and what the firewall currently says
```

`up` also installs a helper, `on`, so you can run a command "inside" a host:

```bash
on web  curl http://10.10.10.10     # as the web server
on fw   nft list ruleset            # talk to the firewall
on internet nmap -Pn -p 80 10.10.10.10
```

If everything goes sideways, there is always the reset:

```bash
sudo ./s4-lab.sh down && sudo ./s4-lab.sh up    # a clean company in ~3 seconds
```

### The company

```
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
```

Four zones, one firewall in the middle, each host a namespace with its own
interfaces and routes. The services are fakes — just enough protocol to be
recognised (an HTTP page, an SSH banner, a MySQL greeting), not enough to be
useful. The `db` host greets you with "if you read this from the internet, the
firewall has failed", which for the first five minutes it has.

---

## Block 1 — Firewalls

### Exercise 1 — Build it, then see it wide open (5 min)

**Why.** A network with no firewall is not "insecure once attacked". It is
insecure sitting still. Before you add a single rule, look at what a flat
network offers to anyone who can route to it.

```bash
sudo ./s4-lab.sh up                       # if you have not already
on internet curl http://10.10.10.10       # the public website — fine
on internet curl http://10.10.30.30:3306  # ...and the database. Not fine.
sudo ./s4-lab.sh matrix                   # test 15 flows against the intended policy
```

**What you should see.** Every flow OPEN. The matrix reports **6 of 15 match** —
the six that were *supposed* to be open. The other nine are the internet reaching
your database, your file share, and your admin ports. Nobody attacked anything.

**Log.** The matrix output, and which of the nine wrong flows you would close
first.

**Answer in one line.** Why is "insecure by default" a stronger reason for a
firewall than "insecure when attacked"?

---

### Exercise 2 — Default deny, then your first allow (7 min)

**Why.** The only safe firewall starts by denying everything and then names the
few flows it allows. You are about to feel *why* one allow rule is never enough.

```bash
on fw nft add table inet s4
on fw nft add chain inet s4 forward '{ type filter hook forward priority 0; policy drop; }'
on internet curl --max-time 3 http://10.10.10.10        # times out — all blocked
on fw nft add rule inet s4 forward ip daddr 10.10.10.10 tcp dport 80 accept
on internet curl --max-time 3 http://10.10.10.10        # ...still times out. Why?
```

**What you should see.** After the allow rule, the request reaches the server —
but the **reply** is dropped on its way back, because the default-drop policy
applies to the return direction too. You allowed the question, not the answer.

**Do not fix it yet.** The timeout is the whole point; the next exercise fixes
it properly.

**Log.** The command that opened port 80, and the fact that it was not enough.

**Answer in one line.** A firewall rule matched one direction of the
conversation. How many directions does a TCP conversation have?

---

### Exercise 3 — Watch the firewall remember (6 min)

**Why.** Writing a second rule for every reply direction doubles your rule set
and opens a hole an attacker can start a connection through. Stateful filtering
does it once: allow replies to conversations you already allowed.

```bash
on fw nft add rule inet s4 forward ct state established,related accept
on internet curl --max-time 3 http://10.10.10.10        # now the reply comes back
on fw conntrack -L                                      # the flow it is remembering
on fw nft list chain inet s4 forward                    # your three rules, in order
```

**What you should see.** The website loads. `conntrack -L` shows one TCP entry
(source `internet`, dest `web:80`) in state **ASSURED** — the firewall is
holding that flow in memory. You never wrote a rule for the reply; the state
table is what lets it back.

**Log.** The conntrack entry, and where in the chain the `established,related`
rule sits.

**Answer in one line.** Nothing in your ruleset mentions the reply. What is
letting it through — and what happens to that permission when the connection
goes idle?

---

### Exercise 4 — Load the policy, read the drops (7 min)

**Why.** Real policy lives in a file you can read, review and version, not in a
history of `nft add` commands nobody can reconstruct. [`zones.nft`](zones.nft)
is the whole company on one screen.

Read `zones.nft` first. It is seven rules, each the shape you already know:
match conditions on the left, one verdict on the right.

```bash
on fw nft -f zones.nft                              # replace everything with the file
sudo ./s4-lab.sh matrix                             # now 14 of 15 match
on internet curl --max-time 2 http://10.10.30.30:3306   # blocked
on fw nft list chain inet s4 forward                # watch the drop counter climb
```

**What you should see.** The matrix jumps from 6 to **14 of 15**. The
internet→database probe is refused, and the last rule — `counter log ... drop` —
counts every packet it bins. One flow still mismatches: `web → db:3306`, because
rule 6 in the file is deliberately a `TODO`.

**Log.** The 14/15 result, and the value of the drop counter.

**Answer in one line.** The web server cannot reach its own database yet. Which
rule is missing — and why is a `counter` on the final drop rule the first thing
you would look at in a real firewall review?

---

## Block 2 — Segmentation, DMZs and NAC

### Exercise 5 — Prove it from three places (6 min)

**Why.** Reachability is a property of the *path*, not of the host. The same
database answers differently depending on where you stand.

```bash
on internet nmap -Pn -p 22,80,3306 10.10.30.30    # db, from outside
on pc       nmap -Pn -p 22,80,3306 10.10.30.30    # db, from a LAN user
on web      nmap -Pn -p 22,3306    10.10.30.30    # db, from the web server
```

**What you should see.** One host, three answers. From the internet: everything
`filtered`. From the LAN: only `22` open. From the web server: `3306` open (once
you have added rule 6 — see the next exercise). Same target, three vantage
points, three truths.

**Log.** The three scans, each labelled with where it was run from.

**Answer in one line.** A port-scan report is worthless without one field. Which
one?

---

### Exercise 6 — Write the one missing rule (6 min)

**Why.** The DMZ pattern: the web application must reach its database on exactly
one port, and nothing else may. This is the rule you left as a `TODO`.

Edit line 6 of `zones.nft`:

```
iifname "fw-dmz" oifname "fw-data" ip saddr $WEB ip daddr $DB tcp dport 3306 accept
```

```bash
on fw nft -f zones.nft
sudo ./s4-lab.sh matrix          # should now read 15 / 15
```

**What you should see.** **15 of 15.** The web app talks to the database, and
still nobody else can — because the rule names both the source (`$WEB`) and the
destination (`$DB`).

**Then try this.** Delete `ip saddr $WEB` from the rule, reload, and run the
matrix again. It still says 15/15.

**Log.** The rule you wrote, the 15/15 result, and the fact that the
source-less version also passes.

**Answer in one line.** If both versions pass the tests, why keep
`ip saddr $WEB`? (What could a compromised LAN host do with the version that
omits it?)

---

### Exercise 7 — A MAC allow-list, and how to beat it (6 min)

**Why.** NAC decides whether a device gets onto the network at all. The most
common form — a MAC allow-list — is also the weakest, because a MAC address is a
name a device can rename itself to. You are about to do exactly that.

```bash
on fw nft add set inet s4 lan_macs '{ type ether_addr; }'
on fw nft add element inet s4 lan_macs '{ 02:00:00:00:20:20 }'          # the pc
on fw nft insert rule inet s4 forward iifname "fw-lan" ether saddr != @lan_macs drop
on pc curl --max-time 3 http://10.10.10.10                             # works — MAC is listed
on pc ip link set eth0 address 02:66:66:66:66:66                       # become a stranger
on fw ip neigh flush dev fw-lan
on pc curl --max-time 3 http://10.10.10.10                             # blocked
on pc ip link set eth0 address 02:00:00:00:20:20                       # put it back
on fw ip neigh flush dev fw-lan
on pc curl --max-time 3 http://10.10.10.10                             # works again
```

**What you should see.** With the real MAC, the pc works. Change the MAC, it is
cut off. Change the MAC to *any value on the list*, and it is back — the control
never knew the difference.

**Log.** The three results, and which MAC produced each.

**Answer in one line.** MAC filtering stops the honest and the lazy. Name one
NAC method a spoofed MAC does **not** beat. (Restore the real MAC before moving
on, or later exercises misbehave.)

---

## Block 3 — Detection, administration and proof

### Exercise 8 — Watch it detect, then block (8 min)

**Why.** A firewall on port 80 lets in a web request and a web exploit alike.
Reading the *payload* is a different control: an IDS watches it, an IPS blocks
it, and the difference between them is one word in the rule.

Read [`s4-ids.rules`](s4-ids.rules) and [`s4-ips.rules`](s4-ips.rules) first —
three rules and one, respectively.

**As an IDS (watches, out of band):**

```bash
on fw suricata -c /etc/suricata/suricata.yaml -S "$PWD/s4-ids.rules" -i fw-out -k none -l /tmp/ids &
sleep 10
on internet curl "http://10.10.10.10/view?file=/etc/passwd"     # trips rule 1
on internet nmap -Pn -sS -p 1-200 10.10.10.10                   # trips the scan rule
cat /tmp/ids/fast.log                                           # the alerts
sudo pkill suricata
```

**As an IPS (blocks, inline):** the firewall hands matching web traffic to
Suricata via an nftables `queue`, and the same `/etc/passwd` request that only
*alerted* before is now **dropped**. The full queue setup is a few lines — run
it from here:

```bash
on fw nft insert rule inet s4 forward ip daddr 10.10.10.10 tcp dport 80 queue num 0 bypass
on fw nft insert rule inet s4 forward ip saddr 10.10.10.10 tcp sport 80 queue num 0 bypass
on fw suricata -c /etc/suricata/suricata.yaml -S "$PWD/s4-ips.rules" -q 0 -k none -l /tmp/ips &
sleep 10
on internet curl --max-time 3 http://10.10.10.10/                       # normal page: passes
on internet curl --max-time 3 "http://10.10.10.10/view?file=/etc/passwd" # dropped
cat /tmp/ips/fast.log                                                   # [Drop] ...
sudo pkill suricata
```

**What you should see.** In IDS mode the alerts appear in `fast.log` but the
`curl` still succeeds — you watch the attack work. In IPS mode the same
signature `[Drop]`s the malicious request while the normal page loads fine.

**Log.** One alert line from IDS mode, one drop line from IPS mode.

**Answer in one line.** The IDS alerted and the attack still worked. What did
moving to an IPS give you — and what new way to cause an outage did you just
accept?

---

### Exercise 9 — Harden the admin door (6 min)

**Why.** You defended the services. The door you *manage* them from is a service
too, and it is the highest-value one: own the box you run `nft` from and every
rule is yours. This runs on your Kali host itself.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/s4 -N ''            # a key pair
ssh-copy-id -i ~/.ssh/s4 "$USER@localhost"          # trust the public half
sudo tee /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
EOF
sudo sshd -t && sudo systemctl restart ssh          # test config FIRST, then apply
ssh -i ~/.ssh/s4 "$USER@localhost" true             # key login: works
ssh -o PubkeyAuthentication=no "$USER@localhost"     # password login: refused
```

**What you should see.** Key login succeeds. Password login is refused with
`Permission denied (publickey)`. Brute force is now off the table for this door.

**The habit that matters more than the config.** Always `sshd -t` before you
restart, and always confirm the new way in works from a **second** terminal
before you close the first. On a real server, locking yourself out is a long
drive; here it is a container rebuild, but treat it as if it were the drive.

**Log.** The two `ssh` results, and the contents of your hardening file.

**Answer in one line.** Key-only auth kills password brute force. Name one way
into this door it does **not** stop.

---

### Exercise 10 / checkpoint — The control report (10 min, finish tonight)

**Why.** This is the deliverable Practical 2 starts from. Your firewall is
loaded, segmented and hardened — now prove it, on one page.

```bash
sudo ./s4-lab.sh matrix          # the 15/15 evidence
```

Your report, in the log:

1. **The matrix.** The `matrix` output at 15/15 — one row per intended flow.
2. **Three proofs**, each naming where it was run from: a scan from the
   internet, one drop-counter value, one IDS/IPS log line.
3. **Three sentences.** One control that worked, one that surprised you, and one
   thing this lab **cannot** tell you (a namespace lab has no real attacker, no
   encrypted payloads, no load — say so honestly).

**Keep `zones.nft` and your log.** Practical 2 starts from them.

---

## What each script refuses to do

A few things here will not do what you ask, briefly and with a reason:

| Thing | What it refuses |
|---|---|
| `s4-lab.sh matrix` | Passing a flow as "ok" on the wrong evidence. It tests all 15 against the written policy and prints every MISMATCH; it will not hide one because the number looks better. |
| `s4-lab.sh status` | Guessing which zone you meant. It draws the whole map and the current ruleset, because "the database is safe" is an assumption until the matrix says so. |
| `zones.nft` | Allowing a flow silently. The last rule is always `drop`, and it is a `counter log ... drop`, so nothing leaves without being counted. |
| `s4-ids.rules` | Deciding for you. `alert` writes a line; turning it into `drop` (an IPS) is a word **you** change, in a file you read first. |

## Two conventions, same as every session

**Every finding names its vantage point.** Which host you ran it from, which
interface, the exact command. A scan result with no "from where" is
unfalsifiable.

**Silence is not a result.** A `drop` is silent by design — a hung `curl` is the
firewall working, not failing. Add `--max-time` and write the honest version:
"no reply on this port, scanned from the internet zone", not "the port is
closed".

## The files

```
s4-lab.sh        build/inspect/test/tear-down the four-zone company; installs `on`
zones.nft        the seven-rule firewall policy (rule 6 is your exercise 6)
s4-ids.rules     three Suricata rules for exercise 8 (detect)
s4-ips.rules     the same idea with one word changed: alert -> drop (prevent)
```

Every script answers `--help`.
