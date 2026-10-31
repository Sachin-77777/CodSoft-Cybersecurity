#!/usr/bin/env python3
"""
Sample PCAP generator
=====================
Creates ``sample.pcap`` with a handful of synthetic packets so the analyzer can
be demonstrated without capturing live traffic (and therefore without needing
root / Administrator privileges).

Usage:
    python generate_sample_pcap.py [output.pcap]
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
except ImportError:
    print("Error: Scapy is required. Install it with: pip install -r requirements.txt")
    sys.exit(2)


CLIENT_MAC = "aa:bb:cc:dd:ee:ff"
GATEWAY_MAC = "11:22:33:44:55:66"
CLIENT_IP = "192.168.1.10"
GATEWAY_IP = "192.168.1.1"
SERVER_IP = "93.184.216.34"  # example.com


def build_packets() -> list:
    """Return a small, realistic-looking list of packets."""
    return [
        # 1. ARP request: who has the gateway?
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc=CLIENT_IP, pdst=GATEWAY_IP),
        # 2. TCP SYN towards a web server
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=52344, dport=443, flags="S", seq=1000),
        # 3. TCP SYN-ACK coming back
        Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=443, dport=52344, flags="SA", seq=5000, ack=1001),
        # 4. Plain HTTP request with a readable payload
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=52344, dport=80, flags="PA", seq=1001, ack=5001)
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        # 5. HTTP response payload
        Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=80, dport=52344, flags="PA", seq=5001, ack=1043)
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello!"),
        # 6. DNS query for example.com
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT_IP, dst=GATEWAY_IP)
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        # 7. ICMP echo request (ping)
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT_IP, dst=GATEWAY_IP)
        / ICMP(type=8, code=0),
    ]


def main(argv: list[str]) -> int:
    output = Path(argv[1]) if len(argv) > 1 else Path("sample.pcap")
    packets = build_packets()
    for packet in packets:
        # Give each packet a distinct, increasing arrival time.
        packet.time = 1730000000.0 + len(str(packet))
    wrpcap(str(output), packets)
    print(f"Wrote {len(packets)} packets to {output.resolve()}")
    print(f"Analyse it with:  python packet_analyzer.py -r {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
