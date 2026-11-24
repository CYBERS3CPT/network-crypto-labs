#!/usr/bin/env python3
"""
make-air.py — builds air.pcap, one minute of 802.11 "heard from the air"
outside a small office, so you can do wireless analysis without a Wi-Fi card,
without monitor mode and without transmitting a single frame.

    python3 make-air.py            # writes air.pcap next to this script
    python3 make-air.py out.pcap   # or wherever you like

Everything is synthetic and deterministic (same file every time). The NOVA-IoT
4-way handshake is a *real* WPA2 handshake sealed with a deliberately weak PSK
("superman"), so exercise 5 can recover it offline with aircrack-ng. Every other
frame is a plain management frame with nothing secret in it.

What happens in that minute (do not read this before exercise 6 — or do, and
then pretend to be surprised):

  * Seven access points beacon once per second.
  * At ~15 s a smart plug joins NOVA-IoT (WPA2-Personal): one real 4-way handshake.
  * At ~30 s someone floods deauthentication frames at one laptop, with the
    real NOVA-Staff BSSID as the (forged) sender.
  * At ~33 s the laptop, kicked off, probes for every network it remembers.
  * At ~36 s it associates to the "NOVA-Staff" that answered — the wrong one —
    and starts 802.1X with it, sending its identity before anything is encrypted.

Standard library only. Link type 127 (802.11 + radiotap), so Wireshark and
tshark decode it as if it had been captured in monitor mode.
"""

import hashlib
import hmac
import struct
import sys
from pathlib import Path

# ----------------------------------------------------------------------------- helpers

def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))

BCAST = mac("ff:ff:ff:ff:ff:ff")
T0 = 1_763_985_600.0  # 2025-11-24 12:00:00 UTC — a Monday lunchtime

def rnd(label: str, n: int) -> bytes:
    """Deterministic 'random' bytes, so the pcap is identical on every machine."""
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]

def radiotap(channel: int, dbm: int) -> bytes:
    # present = channel (bit 3) + dBm antenna signal (bit 5)
    freq = 2407 + 5 * channel
    return struct.pack("<BBHI", 0, 0, 13, (1 << 3) | (1 << 5)) + struct.pack("<HHb", freq, 0x00A0, dbm)

def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body

RATES = ie(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))
OUI = b"\x00\x0f\xac"

def rsn(akms, mfpc=False, mfpr=False) -> bytes:
    caps = (0x0080 if mfpc else 0) | (0x0040 if mfpr else 0)
    body = struct.pack("<H", 1) + OUI + b"\x04"           # version 1, group CCMP
    body += struct.pack("<H", 1) + OUI + b"\x04"          # 1 pairwise: CCMP
    body += struct.pack("<H", len(akms)) + b"".join(OUI + bytes([a]) for a in akms)
    body += struct.pack("<H", caps)
    return ie(48, body)

class Seq:
    def __init__(self): self.n = {}
    def __call__(self, who: bytes) -> bytes:
        self.n[who] = (self.n.get(who, 0) + 1) % 4096
        return struct.pack("<H", self.n[who] << 4)

seq = Seq()

def hdr(fc: int, flags: int, a1: bytes, a2: bytes, a3: bytes, sn: bytes = b"") -> bytes:
    return bytes([fc, flags]) + b"\x00\x00" + a1 + a2 + a3 + (sn or seq(a2))

# ----------------------------------------------------------------------------- the air

APS = [
    # name,            bssid,               ch, dBm, capability, security IE
    ("NOVA-Staff",     "00:1a:2b:10:00:01",  1, -48, 0x0411, rsn([1], mfpc=True)),            # WPA2-Enterprise
    ("NOVA-Staff",     "00:1a:2b:10:00:06",  6, -61, 0x0411, rsn([1], mfpc=True)),            # same ESS, 2nd AP
    ("NOVA-Guest",     "00:1a:2b:20:00:01",  1, -50, 0x0401, b""),                            # open + captive portal
    ("NOVA-IoT",       "00:1a:2b:30:00:06",  6, -63, 0x0411, rsn([2])),                       # WPA2-Personal, no PMF
    ("Lab-WPA3",       "00:1a:2b:40:00:0b", 11, -70, 0x0411, rsn([8], mfpc=True, mfpr=True)), # WPA3-Personal (SAE)
    ("Cafe Central",   "a4:91:b1:5c:22:7e",  6, -77, 0x0411, rsn([2, 8], mfpc=True)),         # WPA2/WPA3 transition
    ("NOVA-Staff",     "b6:3e:9c:6e:4f:02", 11, -39, 0x0411, rsn([1])),                       # the twin: loud, no PMF
]

STAFF_REAL = mac("00:1a:2b:10:00:01")
TWIN = mac("b6:3e:9c:6e:4f:02")
IOT_AP = mac("00:1a:2b:30:00:06")
LAPTOP = mac("3c:22:fb:a7:19:c4")   # a staff laptop, real (universally administered) MAC
PLUG = mac("50:02:91:0e:77:3d")     # a smart plug

frames = []  # (time, bytes)

def add(t: float, ch: int, dbm: int, frame: bytes):
    frames.append((T0 + t, radiotap(ch, dbm) + frame))

def beacon(ssid, bssid, ch, cap, sec, t):
    b = mac(bssid)
    body = struct.pack("<QHH", int(t * 1e6), 100, cap)
    body += ie(0, ssid.encode()) + RATES + ie(3, bytes([ch])) + sec
    return hdr(0x80, 0, BCAST, b, b) + body

for k in range(60):
    for i, (ssid, bssid, ch, dbm, cap, sec) in enumerate(APS):
        t = k + 0.013 * i
        add(t, ch, dbm + (k % 3) - 1, beacon(ssid, bssid, ch, cap, sec, t))

# --- ~15 s: the smart plug joins NOVA-IoT -------------------------------------
# A REAL WPA2-Personal 4-way handshake. The PSK below is deliberately weak, so
# exercise 8 can recover it offline with aircrack-ng. In real life this is why a
# Wi-Fi password must be long and random — or, better, why you use WPA3-SAE.
IOT_PSK = "superman"   # 8 characters, a dictionary word: the whole lesson, in one string.

def prf(key: bytes, label: bytes, data: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:n]

def wpa2_kck(psk: str, ssid: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes) -> bytes:
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid, 4096, 32)
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return prf(pmk, b"Pairwise key expansion", data, 16)   # KCK = first 16 bytes of the PTK

def eapol_body(key_info: int, replay: int, nonce: bytes, mic: bytes, data: bytes, keylen: int) -> bytes:
    body = struct.pack(">BHHQ", 2, key_info, keylen, replay) + nonce + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8
    body += mic + struct.pack(">H", len(data)) + data
    return struct.pack(">BBH", 2, 3, len(body)) + body     # 802.1X header + key frame

def eapol_signed(kck, key_info, replay, nonce, data, keylen):
    frame = eapol_body(key_info, replay, nonce, b"\x00" * 16, data, keylen)   # MIC field zeroed
    mic = hmac.new(kck, frame, hashlib.sha1).digest()[:16]                    # CCMP = HMAC-SHA1
    return eapol_body(key_info, replay, nonce, mic, data, keylen)

LLC = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
anonce, snonce = rnd("anonce", 32), rnd("snonce", 32)
rsn_plug = rsn([2])
KCK = wpa2_kck(IOT_PSK, b"NOVA-IoT", IOT_AP, PLUG, anonce, snonce)
add(15.00, 6, -55, hdr(0xB0, 0, IOT_AP, PLUG, IOT_AP) + struct.pack("<HHH", 0, 1, 0))           # auth (open system)
add(15.01, 6, -63, hdr(0xB0, 0, PLUG, IOT_AP, IOT_AP) + struct.pack("<HHH", 0, 2, 0))
add(15.02, 6, -55, hdr(0x00, 0, IOT_AP, PLUG, IOT_AP) + struct.pack("<HH", 0x0411, 10)
    + ie(0, b"NOVA-IoT") + RATES + rsn_plug)                                                    # assoc request
add(15.03, 6, -63, hdr(0x10, 0, PLUG, IOT_AP, IOT_AP) + struct.pack("<HHH", 0x0411, 0, 0xC001) + RATES)
# M1 AP→STA (ANonce, no MIC). M2 STA→AP (SNonce + MIC). M3/M4 carry real MICs too.
# FromDS (0x02) for AP→STA, ToDS (0x01) for STA→AP, so the BSSID sits where a sniffer expects it.
add(15.05, 6, -55, hdr(0x08, 0x02, PLUG, IOT_AP, IOT_AP) + LLC + eapol_body(0x008A, 1, anonce, b"\x00" * 16, b"", 16))
add(15.06, 6, -63, hdr(0x08, 0x01, IOT_AP, PLUG, IOT_AP) + LLC + eapol_signed(KCK, 0x010A, 1, snonce, rsn_plug, 0))
add(15.07, 6, -55, hdr(0x08, 0x02, PLUG, IOT_AP, IOT_AP) + LLC + eapol_signed(KCK, 0x13CA, 2, anonce, rsn_plug, 16))
add(15.08, 6, -63, hdr(0x08, 0x01, IOT_AP, PLUG, IOT_AP) + LLC + eapol_signed(KCK, 0x030A, 2, b"\x00" * 32, b"", 0))

# --- ~30 s: deauth flood, forged as coming from the real NOVA-Staff AP --------
# The forger cannot see the real AP's sequence counter, so it keeps its own:
# the real AP is around SN 60 here, the forged frames start near 2900.
for j in range(128):
    t = 30 + j * 0.02
    frame = hdr(0xC0, 0, LAPTOP, STAFF_REAL, STAFF_REAL, struct.pack("<H", (2903 + j) << 4)) + struct.pack("<H", 7)  # reason 7: class 3 frame from nonassociated STA
    add(t, 1, -41, frame)   # note the signal: louder than the real AP ever is (-48)

# --- ~33 s: the laptop shouts every network it remembers -----------------------
REMEMBERED = ["NOVA-Staff", "MEO-7A21C4", "Hotel_Lisboa_Guest", "Aeroporto-LIS-FREE", "iPhone de Rita"]
for r in range(2):
    for i, ssid in enumerate(REMEMBERED):
        t = 33 + r * 0.6 + i * 0.03
        ch = (1, 6, 11)[i % 3]
        add(t, ch, -52, hdr(0x40, 0, BCAST, LAPTOP, BCAST) + ie(0, ssid.encode()) + RATES)

# the twin answers the probe on channel 11
add(34.30, 11, -39, hdr(0x50, 0, LAPTOP, TWIN, TWIN)
    + struct.pack("<QHH", int(34.3e6), 100, 0x0411) + ie(0, b"NOVA-Staff") + RATES + ie(3, bytes([11])) + rsn([1]))

# --- ~36 s: and the laptop goes with it ---------------------------------------
add(36.00, 11, -52, hdr(0xB0, 0, TWIN, LAPTOP, TWIN) + struct.pack("<HHH", 0, 1, 0))
add(36.01, 11, -39, hdr(0xB0, 0, LAPTOP, TWIN, TWIN) + struct.pack("<HHH", 0, 2, 0))
add(36.02, 11, -52, hdr(0x00, 0, TWIN, LAPTOP, TWIN) + struct.pack("<HH", 0x0411, 10) + ie(0, b"NOVA-Staff") + RATES + rsn([1]))
add(36.03, 11, -39, hdr(0x10, 0, LAPTOP, TWIN, TWIN) + struct.pack("<HHH", 0x0411, 0, 0xC001) + RATES)

# 802.1X starts. EAP runs *before* any Wi-Fi key exists, so these are readable.
def eap(code: int, ident: int, typ: int, data: bytes = b"") -> bytes:
    pkt = struct.pack(">BBHB", code, ident, 5 + len(data), typ) + data
    return LLC + struct.pack(">BBH", 2, 0, len(pkt)) + pkt          # EAPOL type 0 = EAP packet

add(36.05, 11, -39, hdr(0x08, 0x02, LAPTOP, TWIN, TWIN) + eap(1, 1, 1))                              # who are you?
add(36.07, 11, -52, hdr(0x08, 0x01, TWIN, LAPTOP, TWIN) + eap(2, 1, 1, b"ana.silva@staff.nova.example"))
add(36.09, 11, -39, hdr(0x08, 0x02, LAPTOP, TWIN, TWIN) + eap(1, 2, 25, b"\x20"))                  # let's do PEAP
# ...and here the capture ends. What happens next depends on one setting on the laptop.

# ----------------------------------------------------------------------------- write

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__.split("What happens")[0].strip()); return
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("air.pcap")
    frames.sort(key=lambda f: f[0])
    with out.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for t, data in frames:
            sec, usec = int(t), int(round((t - int(t)) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)
    print(f"{out}: {len(frames)} frames, {frames[-1][0] - frames[0][0]:.0f} s of air")

if __name__ == "__main__":
    main()
