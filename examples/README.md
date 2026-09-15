# Examples

## `s2_sample.pcap`

Twenty-two packets: what exercise 10 of Session 2 looks like on the lab
segment, if nothing goes wrong and nobody sneezes. Client `192.168.56.10`,
target `192.168.56.20`, captured on `eth1` with no filter.

| Packets | What | Exercise |
|---|---|---|
| 1–2 | ARP request and reply. The kernel has to find the target before it can talk to it | 1 |
| 3–8 | `ping -c 3`: three echo requests, three replies | 10 |
| 9–15 | `nc -vz <target> 22`: handshake, the SSH banner, a clean close. **Open** | 4, 10 |
| 16–17 | `nc -vz <target> 9999`: SYN, RST. **Closed**, and the host said so | 4, 10 |
| 18–20 | `nc -vz <target> 8080` with a DROP rule on the target: SYN, SYN, SYN, silence. **Filtered** | 4 |
| 21–22 | `dig @<target> nova.pt`: a UDP query to a port with nothing behind it, and an ICMP *port unreachable* back. The polite outcome. Many hosts say nothing at all | 5, 7 |

Try the script on it before you try it on your own capture, so you know what
"working" looks like:

```bash
../session-02-protocols-and-flows/flow-table.py s2_sample.pcap --capture-point "eth1, no filter"
tshark -r s2_sample.pcap                      # the packets, one per line
tshark -r s2_sample.pcap -q -z conv,tcp       # what the slide asks for
```

Two things to notice in the output. The UDP query and the ICMP error come out
as **two rows**, because they are two flows: the script does not tie them
together, and neither does a firewall. Working out that row 6 is the answer to
row 5 is your job, and it is also the whole reason UDP scanning is slow and
ambiguous. And the ARP frames are not in the table at all, because ARP has no
IP header and therefore no 5-tuple. It still happened. Your log should say so.

### Provenance

Hand-built by `make-sample.py`, header by header, standard library only. A real
capture would carry somebody's MAC addresses, somebody's ISP and somebody's
typos; this one carries exactly the traffic above and nothing else. Timestamps
are round because they are invented. Checksums are correct because tshark
complains otherwise.

Read `make-sample.py` if you want to see what "four headers" means in bytes.
It is shorter than you would expect, which is rather the point of the session.

```bash
./make-sample.py            # regenerates s2_sample.pcap
```
