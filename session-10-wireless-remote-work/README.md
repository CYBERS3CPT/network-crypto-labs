# Session 10 — Wireless and remote-work security

WPA2/WPA3, enterprise Wi-Fi, rogue access points, guest networks, VPN, device
posture and VDI. Thirteen exercises and a final challenge, about three hours,
all inside your own Kali.

The whole session in one sentence: **Wi-Fi tells everyone in range what it is
and who is asking; the defences are PMF, WPA3 and a checked certificate, and
once you leave the building the only network you trust is the tunnel you
built.**

---

## Before you start

**Scope, and why the Wi-Fi half is a file.** We never transmit tonight. Sending
deauthentication frames or running a fake access point against networks you do
not own is a crime, and it knocks real people offline. `air.pcap` contains the
same frames you would capture with a monitor-mode card outside an office, and
anyone can open it. The WireGuard half runs on namespaces inside your Kali:
there is no real café and no real office on the other end.

**Tools.** `tshark`, `wg`, `aircrack-ng`, `nft`, `tcpdump`, `curl`, `python3`:

```bash
sudo apt install -y tshark wireguard-tools aircrack-ng nftables tcpdump curl
```

**One log.**

```bash
mkdir -p ~/s10 && cd ~/s10
script -a ~/s10/session10.log
date -Is                          # first line of every exercise
```

## Files

| File | What it does |
|---|---|
| `make-air.py` | Builds `air.pcap`: one minute of 802.11 heard outside an office, 574 frames, including a **real** crackable WPA2 handshake. Standard library only, same bytes on every machine. |
| `wifi-words.txt` | A 33-word list for exercise 5. The NOVA-IoT PSK is in it. |
| `s10-lab.sh` | Builds the café and the office (laptop, café router, news site, VPN gateway, intranet) out of namespaces. `up`, `status`, `enrol`, `revoke`, `down`. Installs `on`. |
| `posture.sh` | Asks your Kali the questions a posture check asks (disk, firewall, updates, SSH, user). Read-only. `--json` for what a gateway would receive. |

Every script answers `--help` (or `help`).

---

## Part 1 — Reading Wi-Fi from the air

### Exercise 1 — Lab check

```bash
python3 make-air.py
tshark -r air.pcap | wc -l        # 574
wg --version
aircrack-ng --help | head -1
```

### Exercise 2 — Who is on the air?

```bash
tshark -r air.pcap -Y 'wlan.fc.type_subtype == 8' \
  -T fields -e wlan.bssid -e wlan_radio.channel -e radiotap.dbm_antsignal \
  -e _ws.col.info | sort -u -k1,1
```

Seven radios, six names. `NOVA-Staff` appears three times. Two of those are
normal (an office needs more than one access point). Exercise 5 is about the
third.

### Exercise 3 — How is each network protected?

```bash
tshark -r air.pcap -Y 'wlan.fc.type_subtype == 8' \
  -T fields -e wlan.bssid -e wlan.rsn.akms.type \
  -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr | sort -u -k1,1
```

AKM 1 = 802.1X (Enterprise), 2 = PSK (WPA2-Personal), 8 = SAE (WPA3-Personal),
`2,8` = transition mode, empty = open. `mfpc`/`mfpr` = Protected Management
Frames capable / required.

The question is not "what is the security". It is "what would you change, and
why": the guest network is open (a captive portal is not encryption), IoT is a
single PSK without PMF, the café runs transition mode (old clients pull it down
to WPA2), and the staff network is only PMF *capable*.

### Exercise 4 — Read a handshake

```bash
tshark -r air.pcap -Y eapol
tshark -r air.pcap -Y eapol -V | grep -E 'Message|Nonce|MIC:|Replay'
```

There is no password in any frame. With WPA2-Personal there does not need to
be: the nonces and the MIC are enough to test guesses offline. The next
exercise does exactly that.

### Exercise 5 — Crack the handshake

The NOVA-IoT handshake is real: a weak PSK was used to seal it, and you can
recover it offline, against a wordlist, without sending a single frame.

```bash
aircrack-ng -w wifi-words.txt -b 00:1a:2b:30:00:06 air.pcap
```

The password is `superman` — eight characters, a dictionary word, found in well
under a second. `wifi-words.txt` has 33 candidates; the real `rockyou.txt` has
14 million and still runs in minutes on a laptop. Each guess is tested on your
own machine (derive the key, recompute the MIC, compare), so nothing slows the
attacker down. The fix is not a cleverer password but a long random one, or
WPA3-SAE, which leaves an eavesdropper nothing to test offline.

## Part 2 — Rogue access points and guest networks

### Exercise 6 — Find the twin

Inventory: `00:1a:2b:10:00:01` (channel 1) and `00:1a:2b:10:00:06` (channel 6).

```bash
tshark -r air.pcap -Y 'wlan.fc.type_subtype == 8 && wlan.ssid == "NOVA-Staff"' \
  -T fields -e wlan.bssid -e wlan_radio.channel -e radiotap.dbm_antsignal \
  -e wlan.rsn.capabilities.mfpc | sort -u -k1,1
```

Four clues: not in the inventory; a locally administered MAC (second hex digit
2, 6, A or E); the loudest signal in the file; and different rules (no PMF, a
channel the company does not use).

### Exercise 7 — The disconnection storm

```bash
tshark -r air.pcap -Y 'wlan.fc.type_subtype == 12' | wc -l
tshark -r air.pcap -Y 'wlan.sa == 00:1a:2b:10:00:01 &&
    frame.time_relative > 29.9 && frame.time_relative < 30.1' \
  -T fields -e wlan.fc.type_subtype -e wlan.seq -e radiotap.dbm_antsignal
```

128 deauths in about 2.5 s, "from" the real AP. They are forged: the sequence
numbers jump from ~31 to 2903, and the signal is stronger than the real AP's.
Fix: PMF *required*.

### Exercise 8 — What the laptop did next

```bash
tshark -r air.pcap -Y 'wlan.addr == 3c:22:fb:a7:19:c4 && frame.time_relative > 32.9'
tshark -r air.pcap -Y 'wlan.fc.type_subtype == 4' -T fields -e _ws.col.info | sort -u
tshark -r air.pcap -Y eap -V | grep -i identity
```

The probes list the networks the laptop remembers; it joins the twin; the
802.1X identity goes out before any key exists. The capture stops when the twin
is about to present its certificate. A laptop that checks the certificate (the
right CA *and* the right server name) walks away. That one setting is the
difference.

### Exercise 9 — The guest network rules

On paper. Guests 10.30.0.0/24, staff 10.10.0.0/24, servers 10.20.0.0/24, guest
DNS 10.30.0.1. One answer: allow DNS to 10.30.0.1, deny 10.0.0.0/8, allow
80/443 to the internet, deny the rest, plus client isolation on the access
point.

## Part 3 — Remote access

```bash
sudo ./s10-lab.sh up
```

```
[laptop] 192.168.50.10 --wlan0-- [cafe] 192.168.50.1
                                   |           |
                    198.51.100.0/24             203.0.113.0/24
                                   |           |
   VPN gateway, UDP 51820 → [office] .10      [site] .80  worldnews.example
                                   | 10.20.0.1
                            [intranet] 10.20.0.20  HR portal, office only
```

### Exercise 10 — The café reads your login

```bash
on cafe tcpdump -nli wlan0 -A 'tcp port 80'                  # terminal 2
on laptop curl -s -d 'user=ana&password=Summer2025' http://198.51.100.10/login
on laptop curl -s -m 3 http://10.20.0.20                     # no route: exit 7
```

### Exercise 11 — Enrol your laptop, open the tunnel

```bash
on laptop sh -c 'umask 077; wg genkey > /tmp/laptop.key'
on laptop ip link add wg0 type wireguard
on laptop wg set wg0 private-key /tmp/laptop.key
sudo ./s10-lab.sh enrol "$(on laptop wg show wg0 public-key)"

OFFICE=$(sudo ./s10-lab.sh status | awk '/Office public key/{print $NF}')
on laptop ip addr add 10.99.0.2/32 dev wg0
on laptop wg set wg0 peer $OFFICE endpoint 198.51.100.10:51820 allowed-ips 10.20.0.0/24
on laptop ip link set wg0 up
on laptop ip route add 10.20.0.0/24 dev wg0
on laptop curl -s http://10.20.0.20                          # "You are 10.99.0.2"
```

The café now sees only UDP to 51820. The private key was never typed, sent or
shown: enrolment needs only the public half.

### Exercise 12 — Full tunnel

```bash
on laptop wg set wg0 peer $OFFICE allowed-ips 0.0.0.0/0
on laptop ip route add 198.51.100.10/32 via 192.168.50.1    # the tunnel itself stays outside
on laptop ip route replace default dev wg0
on laptop curl -s http://203.0.113.80 | tail -1             # "You are 198.51.100.10"
```

Without the /32 route, the encrypted packets would try to enter the tunnel they
are carrying, and nothing gets anywhere.

### Exercise 13 — The lost laptop

```bash
sudo ./s10-lab.sh revoke
on laptop curl -s -m 5 http://10.20.0.20 || echo "no way in"
```

The VPN is closed. The disk is not: without encryption the finder still reads
cached email, browser sessions and saved credentials. Revocation, disk
encryption, remote wipe and credential rotation are four different controls.

### Exercise 14 — Check your own Kali

```bash
./posture.sh
./posture.sh --json
```

A lab VM usually fails disk encryption and host firewall, which under the
script's rule means DENY. Argue with the rule; that is the exercise.

## Final challenge

In `~/remote.md`, one row per person: Ana (café, company laptop), Rui (home,
own iPad), a contractor (office, own laptop), the meeting-room TV. Columns:
network, access method, what it reaches, condition. Every condition must be
something a system can check.

## Clean up

```bash
sudo ./s10-lab.sh down
ip netns list                     # empty
```

Keep `air.pcap` and `~/remote.md` for the project appendix.
