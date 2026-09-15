#!/usr/bin/env python3
"""make-sample.py — builds examples/s2_sample.pcap by hand, header by header.

    ./make-sample.py            # writes s2_sample.pcap next to this file

Why hand-built rather than captured: a real capture carries somebody's MAC
addresses, somebody's ISP and somebody's typos. This one carries exactly what
exercise 10 produces on the lab segment, with round timestamps, and nothing
else. Every byte is written by the code below, which doubles as a reminder of
what "four headers" actually means in bytes.

Standard library only. Checksums are real, so tshark stays quiet.
"""

import struct
from pathlib import Path

CLIENT = ("192.168.56.10", "00:0c:29:aa:bb:10")
TARGET = ("192.168.56.20", "00:0c:29:aa:bb:20")
BROADCAST = "ff:ff:ff:ff:ff:ff"

packets = []          # (timestamp, bytes)
T = [1_700_000_000.0]  # a clock. Round, and going nowhere near your real one.


def tick(seconds):
    T[0] += seconds
    return T[0]


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(dst, src, ethertype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, ttl, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def l4_checksum(src, dst, proto, segment):
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def tcp(src, sport, dst, dport, seq, ack, flags, payload=b""):
    window, urg = 64240, 0
    offset = 5 << 12
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset | flags, window, 0, urg)
    seg = hdr + payload
    csum = l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp(src, sport, dst, dport, payload):
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = l4_checksum(src, dst, 17, seg)
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def icmp(kind, code, rest, payload=b""):
    hdr = struct.pack("!BBH", kind, code, 0) + rest
    csum = checksum(hdr + payload)
    return hdr[:2] + struct.pack("!H", csum) + hdr[4:] + payload


def send(ts, src_host, dst_host, proto, l4, dst_mac=None):
    src_ip, src_mac = src_host
    dst_ip, dmac = dst_host
    frame = ethernet(dst_mac or dmac, src_mac, 0x0800, ipv4(src_ip, dst_ip, proto, l4))
    packets.append((ts, frame))


# Flags
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

# --- Exercise 1: ARP, because the kernel has to find the target before anything else
def arp(op, sender, target, dst_mac):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(sender[1]) + ip4(sender[0]) + mac(target[1] if op == 2 else "00:00:00:00:00:00") + ip4(target[0])
    return ethernet(dst_mac, sender[1], 0x0806, body)

packets.append((tick(0), arp(1, CLIENT, TARGET, BROADCAST)))
packets.append((tick(0.0004), arp(2, TARGET, CLIENT, CLIENT[1])))

# --- ping -c 3 <target>
for seq in range(1, 4):
    data = bytes(range(0x10, 0x48))
    send(tick(1.0), CLIENT, TARGET, 1, icmp(8, 0, struct.pack("!HH", 0x1a2b, seq), data))
    send(tick(0.0006), TARGET, CLIENT, 1, icmp(0, 0, struct.pack("!HH", 0x1a2b, seq), data))

# --- nc -vz <target> 22 : open. Three-way handshake, the banner, and a clean close.
c, s = 1000, 5000
send(tick(1.0),   CLIENT, TARGET, 6, tcp(CLIENT[0], 41234, TARGET[0], 22, c, 0, SYN))
send(tick(0.0005), TARGET, CLIENT, 6, tcp(TARGET[0], 22, CLIENT[0], 41234, s, c + 1, SYN | ACK))
send(tick(0.0002), CLIENT, TARGET, 6, tcp(CLIENT[0], 41234, TARGET[0], 22, c + 1, s + 1, ACK))
banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
send(tick(0.0100), TARGET, CLIENT, 6, tcp(TARGET[0], 22, CLIENT[0], 41234, s + 1, c + 1, PSH | ACK, banner))
send(tick(0.0002), CLIENT, TARGET, 6, tcp(CLIENT[0], 41234, TARGET[0], 22, c + 1, s + 1 + len(banner), FIN | ACK))
send(tick(0.0004), TARGET, CLIENT, 6, tcp(TARGET[0], 22, CLIENT[0], 41234, s + 1 + len(banner), c + 2, FIN | ACK))
send(tick(0.0002), CLIENT, TARGET, 6, tcp(CLIENT[0], 41234, TARGET[0], 22, c + 2, s + 2 + len(banner), ACK))

# --- nc -vz <target> 9999 : closed. The host is alive and says so.
c = 2000
send(tick(1.0),   CLIENT, TARGET, 6, tcp(CLIENT[0], 41235, TARGET[0], 9999, c, 0, SYN))
send(tick(0.0004), TARGET, CLIENT, 6, tcp(TARGET[0], 9999, CLIENT[0], 41235, 0, c + 1, RST | ACK))

# --- nc -vz <target> 8080 : filtered. The kernel retries with exponential backoff, then gives up.
c = 3000
for gap in (1.0, 1.0, 2.0):
    send(tick(gap), CLIENT, TARGET, 6, tcp(CLIENT[0], 41236, TARGET[0], 8080, c, 0, SYN))

# --- dig @<target> nova.pt : UDP to a port with nothing behind it.
# The target answers with ICMP port unreachable, which is the polite version. Many hosts say nothing.
query = struct.pack("!HHHHHH", 0xbeef, 0x0120, 1, 0, 0, 0) + b"\x04nova\x02pt\x00" + struct.pack("!HH", 1, 1)
udp_seg = udp(CLIENT[0], 53710, TARGET[0], 53, query)
send(tick(1.0), CLIENT, TARGET, 17, udp_seg)
offending = ipv4(CLIENT[0], TARGET[0], 17, udp_seg)[:28]   # IP header + first 8 bytes of UDP, as the RFC says
send(tick(0.0003), TARGET, CLIENT, 1, icmp(3, 3, b"\x00\x00\x00\x00", offending))


def write_pcap(path):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


if __name__ == "__main__":
    out = Path(__file__).with_name("s2_sample.pcap")
    write_pcap(out)
    print(f"{out.name}: {len(packets)} packets")
