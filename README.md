# Network & Crypto Labs

Exercises for *Infrastructure, Network and Cryptography*, one folder per
session. Laptop open from minute one, two terminals, one log file, and a
growing collection of packets you will be asked to explain.

Sessions are added as they happen. If a folder is missing, the session has not
happened yet. If a folder is present and you have never seen it, you missed a
session.

---

## What this is

Every session has ten-ish exercises. The slides give you the commands; this
repo gives you the commands **plus** what you should see, what to write down,
and the question you are actually being asked, which is rarely "did the
command run".

The point of every exercise is the same and it is worth saying once, here, so
nobody has to say it in the room:

> Every packet carries several claims about who sent it, and none of them is
> authenticated. Your job is to learn which tool reads which claim, and how far
> to trust each one. (Spoiler: not very.)

They are written to be **read** before they are run. Running them takes ten
minutes. Understanding why the output looks the way it does is the part that
transfers to a job.

## Layout

```
templates/session-log.md            how to keep the log, and the flow-table columns

session-02-protocols-and-flows/     Ethernet, IP, routing, TCP, UDP, conntrack, DNS, DHCP,
                                    exposure and visibility. Ten exercises.
    README.md                       the exercises, explained
    lab-check.sh                    are the tools there, which interface is which
    flow-table.py                   pcap in, five-tuple table out (you still fill in the thinking)
```

Every folder has its own README. Every script answers `--help`.

## How to work

Two terminals, always. One captures, one generates traffic. Start the capture
**before** you generate, stop it **after**. Traffic you did not capture is
traffic that, for assessment purposes, did not happen.

One log file, always:

```bash
mkdir -p ~/labs && cd ~/labs
script -a ~/labs/session.log      # records everything you type and everything you see
date -Is                          # first line of every exercise
```

For each exercise the log gets three things: the command, the output, and one
line saying what you expected. That third line is the one that gets marked.
Anyone can paste output. Not everyone can say, in advance, what it should be.

The log is your project appendix. Details in [`templates/session-log.md`](templates/session-log.md).

## Scope

Non-negotiable, and it is also the first thing in every session README.

- **Your two lab VMs, the host-only segment between them, and the public
  endpoints named on the slide.** Nothing else.
- Not the gateway. Not your host machine. Not your neighbour's VM, however
  tempting the port they left open. Not the campus network.
- If a command has `nmap` in it and the target is not your own VM, stop and
  re-read this section.

The lab segment is host-only for a reason. Everything on it is yours to break.
Everything off it is somebody else's, and they did not sign up for a course.

## Some opinions, baked in

A few things here will refuse to do what you ask, briefly and with a reason:

| Thing | What it refuses |
|---|---|
| `flow-table.py` | Filling in the *expected* column for you. It can count packets. It cannot know what you thought would happen, and that column is the whole exercise. |
| `flow-table.py` | Calling a UDP flow with no reply "closed". No reply on UDP means no reply. It does not mean anything else, and the script will not pretend otherwise. |
| `lab-check.sh` | Guessing which interface is your lab segment. It shows you the addresses and lets you decide, because "the traffic leaves through eth0" is an assumption until `ip route get` says so. |

## Two conventions

**Every finding names its capture point.** Interface, filter, and clock. A
finding with no capture point cannot be checked, and a finding that cannot be
checked is an opinion with a timestamp.

**Silence is not a result.** Three stars in a traceroute, no reply on a UDP
probe, an nmap port marked `filtered`: in all three cases you know that
something did not answer. You do not know what, or where, or why. Write the
honest version.

## Contributing

Found a command that does not do what the README says, on a distribution the
README did not anticipate? Open an issue with the distribution, the command and
the output. Corrections welcome; opinions clearly labelled as such, please.

## Licence

MIT. See `LICENSE`.
