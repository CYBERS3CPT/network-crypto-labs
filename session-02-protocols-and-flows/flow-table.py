#!/usr/bin/env python3
"""flow-table.py — a pcap in, the first three columns of your flow table out.

    ./flow-table.py s2_flows.pcap
    ./flow-table.py s2_flows.pcap --capture-point "eth1, no filter"
    ./flow-table.py s2_flows.pcap --csv > flows.csv
    ./flow-table.py ../examples/s2_sample.pcap     # try it on the sample first

Groups packets into bidirectional flows keyed on the 5-tuple (direction is
who spoke first), counts packets and bytes, and infers the outcome from the
flags it actually saw. Prints Markdown, ready to paste into the log.

Two columns are left blank on purpose. "Expected / observed" is what you
thought would happen before you looked, and no script can know that; it is the
whole exercise. "Capture point" is where you stood, which you supply with
--capture-point because the pcap does not know either.

Needs tshark on the PATH. Standard library only.
"""

import argparse
import csv
import shutil
import subprocess
import sys
from collections import OrderedDict

FIELDS = [
    "frame.number", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags", "icmp.type", "icmp.code", "frame.len",
]
PROTO = {1: "icmp", 6: "tcp", 17: "udp"}
ICMP_NAMES = {3: "unreachable", 11: "ttl exceeded", 5: "redirect"}
UNREACH = {0: "net", 1: "host", 2: "protocol", 3: "port", 9: "net prohibited", 10: "host prohibited", 13: "admin prohibited"}
SYN, RST, ACK = 0x02, 0x04, 0x10


class Flow:
    def __init__(self, src, sport, dst, dport, proto):
        self.src, self.sport, self.dst, self.dport, self.proto = src, sport, dst, dport, proto
        self.fwd = self.rev = self.bytes = 0
        self.syn = self.synack = self.rst = 0
        self.icmp_fwd = set()
        self.icmp_rev = set()
        self.icmp_codes = set()

    def key(self):
        return (self.src, self.sport, self.dst, self.dport, self.proto)

    def tuple_str(self):
        if self.proto == "icmp":
            return f"{self.src} → {self.dst} icmp {self.dport}"
        return f"{self.src}:{self.sport} → {self.dst}:{self.dport} {self.proto}"

    def outcome(self):
        p = self.proto
        if p == "tcp":
            if self.synack:
                return "open (SYN-ACK seen)"
            if self.rst:
                return "closed (RST seen)"
            if self.syn >= 2 and self.rev == 0:
                return f"filtered? ({self.syn} SYNs, no answer). Dropped by something, somewhere"
            if self.syn == 1 and self.rev == 0:
                return "no answer (one SYN). Too early to say anything"
            return "mid-conversation (no handshake in this capture)"
        if p == "udp":
            if self.rev:
                return "answered"
            return "no reply. Which means no reply, and nothing else"
        if p == "icmp":
            if 0 in self.icmp_rev and 8 in self.icmp_fwd:
                return "echo answered"
            if 8 in self.icmp_fwd:
                return "echo, no reply"
            if 3 in self.icmp_fwd:
                codes = ", ".join(UNREACH.get(c, f"code {c}") for c in sorted(self.icmp_codes))
                return f"{codes} unreachable: the target said so. Now find the UDP flow it refers to"
            if 11 in self.icmp_fwd:
                return "time exceeded: a router on the path threw the packet away"
            kinds = sorted(self.icmp_fwd | self.icmp_rev)
            return "icmp type(s) " + ",".join(map(str, kinds))
        return "?"


def run_tshark(pcap):
    if not shutil.which("tshark"):
        sys.exit("tshark not found. sudo apt install -y tshark, and say yes to the non-root capture question.")
    cmd = ["tshark", "-r", pcap, "-Y", "ip", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"tshark failed: {e.stderr.strip()}")
    return out.splitlines()


def parse(lines):
    flows = OrderedDict()
    skipped = 0
    for line in lines:
        cols = line.split("\t")
        if len(cols) != len(FIELDS):
            skipped += 1
            continue
        _, src, dst, proto, tsp, tdp, usp, udp_, flags, icmp_type, icmp_code, length = cols
        try:
            proto_n = int(proto)
        except ValueError:
            skipped += 1
            continue
        name = PROTO.get(proto_n, f"proto{proto_n}")
        if name == "tcp":
            sport, dport = tsp, tdp
        elif name == "udp":
            sport, dport = usp, udp_
        elif name == "icmp":
            t = int(icmp_type) if icmp_type else -1
            # same label on both ends so request and reply fold into one flow
            sport = dport = "echo" if t in (0, 8) else ICMP_NAMES.get(t, f"type {t}")
        else:
            sport = dport = ""
        fwd_key = (src, sport, dst, dport, name)
        rev_key = (dst, dport, src, sport, name)
        if fwd_key in flows:
            flow, forward = flows[fwd_key], True
        elif rev_key in flows:
            flow, forward = flows[rev_key], False
        else:
            flow = Flow(src, sport, dst, dport, name)
            flows[fwd_key] = flow
            forward = True

        flow.bytes += int(length or 0)
        if forward:
            flow.fwd += 1
        else:
            flow.rev += 1

        if name == "tcp" and flags:
            f = int(flags, 16)
            if f & SYN and not f & ACK:
                flow.syn += 1
            if f & SYN and f & ACK:
                flow.synack += 1
            if f & RST:
                flow.rst += 1
        if name == "icmp" and icmp_type:
            (flow.icmp_fwd if forward else flow.icmp_rev).add(int(icmp_type))
            if icmp_code:
                flow.icmp_codes.add(int(icmp_code))
    return list(flows.values()), skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--capture-point", default="", help='e.g. "eth1, no filter". Interface, filter, clock.')
    ap.add_argument("--csv", action="store_true", help="CSV instead of Markdown")
    ap.add_argument("--min-packets", type=int, default=1, metavar="N", help="hide flows with fewer than N packets (default 1: silence is a result too)")
    args = ap.parse_args()

    flows, skipped = parse(run_tshark(args.pcap))
    flows = [f for f in flows if f.fwd + f.rev >= args.min_packets]
    if not flows:
        sys.exit("No flows. Either the capture is empty, or --min-packets hid everything, or you captured on the wrong interface. Exercise 2 tells you which.")

    cp = args.capture_point
    if not cp:
        print("note: no --capture-point given. The column is blank, and a blank capture point is an unfalsifiable finding.", file=sys.stderr)

    header = ["5-tuple", "packets / bytes", "outcome", "expected / observed", "capture point"]
    rows = [[f.tuple_str(), f"{f.fwd + f.rev} / {f.bytes}", f.outcome(), "", cp] for f in flows]

    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(header)
        w.writerows(rows)
    else:
        print("| " + " | ".join(header) + " |")
        print("|" + "---|" * len(header))
        for r in rows:
            print("| " + " | ".join(f"`{r[0]}`" if i == 0 else c for i, c in enumerate(r)) + " |")
        print()
        print(f"{len(flows)} flows. The fourth column is yours: what you expected, then what you saw.")
        print("Then three sentences: one flow you expected, one you did not, one thing this capture point cannot tell you.")
    if skipped:
        print(f"note: {skipped} packet(s) skipped (non-IP or malformed).", file=sys.stderr)


if __name__ == "__main__":
    main()
