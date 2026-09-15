# The session log

One file per session. It starts before the first exercise and it is still
running when you close the laptop.

```bash
mkdir -p ~/labs && cd ~/labs
script -a ~/labs/session2.log     # everything you type, everything you see
date -Is                          # first line of every exercise
```

`script -a` appends, so if you close the terminal and open another one, run it
again and carry on. Type `exit` when you are done for the day, otherwise the
file is not flushed and you will discover that at the least convenient moment.

## What goes in, per exercise

1. `date -Is` — so the entry has a clock.
2. The command, exactly as run. Not the version from the slide: the version you
   actually typed, with your IPs and your interface names.
3. The output. All of it, even the boring part. Especially the boring part,
   because "nothing happened" is a claim and the empty output is the evidence.
4. **One line saying what you expected.** Written *before* you look at the
   output, ideally. This is the line that separates a log from a paste.

If the output surprised you, add a second line saying how. Surprises are the
best material you will have for the forum.

## The flow table

Block 4 of Session 2 ends with a table, and Practical 1 starts from it. One row
per flow:

| 5-tuple | packets / bytes | outcome | expected / observed | capture point |
|---|---|---|---|---|
| `192.168.56.10:41234 → 192.168.56.20:22 tcp` | 6 / 480 | open | expected open, observed open | eth1, no filter, 14:02Z |
| `192.168.56.10:41235 → 192.168.56.20:9999 tcp` | 2 / 120 | closed (RST) | expected closed, observed closed | eth1, no filter, 14:02Z |
| `192.168.56.10:53710 → 1.1.1.1:53 udp` | 2 / 210 | answered | expected answered, observed answered | eth1, no filter, 14:02Z |

**5-tuple** — source IP, source port, destination IP, destination port,
protocol. Direction is *who spoke first*.

**Outcome** — what the packets say happened. For TCP that is one of: open
(SYN, SYN-ACK), closed (SYN, RST), or filtered (SYN, SYN, SYN, silence). For
UDP it is *answered* or *no reply*, and no reply means nothing more than that.

**Expected / observed** — what you thought would happen, then what did. If
both are the same, say so. If they differ, this row is the interesting one.

**Capture point** — interface, filter, and time. Without it, nobody, including
you next week, can say whether the table is complete.

`session-02-protocols-and-flows/flow-table.py` will produce the first three
columns from a pcap. The last two are yours.

## Three sentences

After the table, three sentences. Always the same three:

1. One flow you expected and saw.
2. One flow you did not expect.
3. One thing this capture point **cannot** tell you.

The third one is the hardest, and the one that distinguishes someone who ran a
capture from someone who understands what a capture is.
