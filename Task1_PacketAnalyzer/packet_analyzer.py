#!/usr/bin/env python3
"""
Network Packet Analyzer
=======================
CodSoft Cyber Security Internship - Task 1

Captures live network traffic (or reads a saved .pcap file), parses the packet
headers and prints a clean, human readable summary of every packet.

Extracted per packet:
    * Timestamp
    * Source IP address (with port for TCP/UDP)
    * Destination IP address (with port for TCP/UDP)
    * Protocol (TCP / UDP / ICMP / ARP / IPv6 / IP / OTHER)
    * Packet length and protocol specific info (e.g. TCP flags)
    * A short payload snippet (ASCII + hex), clamped to N bytes

Examples
--------
    # Live capture, first 20 packets on interface "Wi-Fi"
    python packet_analyzer.py -i "Wi-Fi" -c 20

    # Live capture filtered to DNS traffic, also written to a log file
    python packet_analyzer.py -i "Wi-Fi" -f "udp port 53" -o capture.log

    # Read a saved capture (no admin rights required)
    python packet_analyzer.py -r sample.pcap -c 10

    # List the interfaces Scapy can see
    python packet_analyzer.py --list-interfaces

Note
----
Live sniffing requires elevated privileges (root on Linux/macOS, Administrator
on Windows) plus a packet capture driver (libpcap on Linux/macOS, Npcap on
Windows). Reading a .pcap file does not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------- #
# Third party dependency (Scapy)
# --------------------------------------------------------------------------- #
_SCAPY_ERROR: Optional[BaseException] = None
try:
    from scapy.all import ARP, ICMP, IP, IPv6, Raw, TCP, UDP, conf, sniff
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader
except ImportError as exc:  # pragma: no cover - depends on environment
    _SCAPY_ERROR = exc


SEPARATOR = "-" * 72
RULE = "=" * 72


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class PacketSummary:
    """A parsed, printable representation of a single network packet."""

    index: int
    timestamp: str
    protocol: str
    src: str
    dst: str
    length: int
    info: str = ""
    payload_ascii: str = ""
    payload_hex: str = ""
    payload_len: int = 0


@dataclass
class CaptureStats:
    """Aggregated counters shown once the capture finishes."""

    total: int = 0
    protocols: Counter = field(default_factory=Counter)
    bytes_total: int = 0

    def record(self, summary: PacketSummary) -> None:
        self.total += 1
        self.protocols[summary.protocol] += 1
        self.bytes_total += summary.length


# --------------------------------------------------------------------------- #
# Packet parsing helpers
# --------------------------------------------------------------------------- #
def _detect_protocol(packet) -> str:
    """Return a short, uppercase protocol name for the packet."""
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IP"
    return "OTHER"


def _extract_addresses(packet, protocol: str) -> tuple[str, str]:
    """Return ``(source, destination)`` strings, including ports when known."""
    if protocol == "ARP":
        arp = packet[ARP]
        return str(arp.psrc), str(arp.pdst)

    if packet.haslayer(IP):
        src, dst = str(packet[IP].src), str(packet[IP].dst)
    elif packet.haslayer(IPv6):
        src, dst = str(packet[IPv6].src), str(packet[IPv6].dst)
    else:
        return "unknown", "unknown"

    if packet.haslayer(TCP):
        return f"{src}:{packet[TCP].sport}", f"{dst}:{packet[TCP].dport}"
    if packet.haslayer(UDP):
        return f"{src}:{packet[UDP].sport}", f"{dst}:{packet[UDP].dport}"
    return src, dst


def _describe(packet, protocol: str) -> str:
    """Build the short ``info`` column for a packet."""
    try:
        if protocol == "TCP":
            flags = packet[TCP].flags
            return f"flags={flags} seq={packet[TCP].seq} ack={packet[TCP].ack}"
        if protocol == "UDP":
            return f"udp_len={len(bytes(packet[UDP].payload))}"
        if protocol == "ICMP":
            return f"type={packet[ICMP].type} code={packet[ICMP].code}"
        if protocol == "ARP":
            op = packet[ARP].op
            label = {1: "who-has", 2: "is-at"}.get(op, str(op))
            return f"op={op} ({label})"
    except Exception:  # malformed / truncated packet - keep the summary usable
        return ""
    return ""


def _extract_payload(packet) -> bytes:
    """Return the raw application payload, if any."""
    if packet.haslayer(Raw):
        try:
            return bytes(packet[Raw].load)
        except Exception:
            return b""
    return b""


def _format_payload(raw: bytes, limit: int) -> tuple[str, str, int]:
    """Clamp ``raw`` to ``limit`` bytes and return (ascii, hex, full length)."""
    if not raw:
        return "", "", 0
    snippet = raw[:limit]
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
    hex_view = snippet.hex(" ")
    return ascii_view, hex_view, len(raw)


def summarize_packet(packet, index: int, payload_bytes: int = 64) -> PacketSummary:
    """Convert a Scapy packet into a :class:`PacketSummary`."""
    try:
        timestamp = dt.datetime.fromtimestamp(float(packet.time)).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
    except Exception:
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    protocol = _detect_protocol(packet)
    src, dst = _extract_addresses(packet, protocol)
    ascii_view, hex_view, payload_len = _format_payload(
        _extract_payload(packet), payload_bytes
    )

    return PacketSummary(
        index=index,
        timestamp=timestamp,
        protocol=protocol,
        src=src,
        dst=dst,
        length=len(packet),
        info=_describe(packet, protocol),
        payload_ascii=ascii_view,
        payload_hex=hex_view,
        payload_len=payload_len,
    )


def format_summary(summary: PacketSummary, show_payload: bool = True) -> str:
    """Render a :class:`PacketSummary` as a block of printable text."""
    lines = [
        f"[#{summary.index:04d}] {summary.timestamp}  |  "
        f"{summary.protocol:<5}  |  {summary.length} bytes",
        f"    src   -> {summary.src}",
        f"    dst   -> {summary.dst}",
    ]
    if summary.info:
        lines.append(f"    info  -> {summary.info}")

    if show_payload and summary.payload_len:
        lines.append(f"    data  -> {summary.payload_len} bytes")
        if summary.payload_ascii:
            lines.append(f"             ascii: {summary.payload_ascii}")
        if summary.payload_hex:
            lines.append(f"             hex  : {summary.payload_hex}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
class PacketAnalyzer:
    """Drives capture/parsing and handles the printing and logging of results."""

    def __init__(
        self,
        output_path: Optional[str] = None,
        payload_bytes: int = 64,
        show_payload: bool = True,
    ) -> None:
        self.payload_bytes = payload_bytes
        self.show_payload = show_payload
        self._log_handle = None
        self._log_path: Optional[Path] = None
        self._index = 0
        self.stats = CaptureStats()

        if output_path:
            try:
                path = Path(output_path).expanduser()
                path.parent.mkdir(parents=True, exist_ok=True)
                self._log_path = path.resolve()
                self._log_handle = path.open("w", encoding="utf-8")
                self._log(RULE)
                self._log("Network Packet Analyzer - capture log")
                self._log(f"Started: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
                self._log(RULE)
            except OSError as exc:
                raise RuntimeError(f"could not open log file '{output_path}': {exc}") from exc

    # -- output ----------------------------------------------------------- #
    def _log(self, text: str) -> None:
        if self._log_handle:
            self._log_handle.write(text + "\n")
            self._log_handle.flush()

    def _emit(self, summary: PacketSummary) -> None:
        block = format_summary(summary, self.show_payload)
        print(SEPARATOR)
        print(block)
        self._log(SEPARATOR)
        self._log(block)

    def handle_packet(self, packet) -> None:
        """Callback compatible with ``scapy.sniff(prn=...)``."""
        self._index += 1
        try:
            summary = summarize_packet(packet, self._index, self.payload_bytes)
        except Exception as exc:  # never let one bad packet kill the capture
            print(f"[#{self._index:04d}] ! could not parse packet: {exc}", file=sys.stderr)
            return
        self.stats.record(summary)
        self._emit(summary)

    # -- capture modes ---------------------------------------------------- #
    def analyze_live(
        self,
        interface: Optional[str] = None,
        count: int = 0,
        bpf_filter: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Sniff live traffic on ``interface``."""
        print(f"Sniffing on {interface or 'default interface'}"
              f"{' with filter: ' + bpf_filter if bpf_filter else ''} "
              f"(limit: {'unlimited' if count <= 0 else count} packets, Ctrl+C to stop)")
        print(f"Protocols seen will be summarised when the capture ends.\n")

        sniff_kwargs = dict(
            iface=interface,
            count=count if count > 0 else 0,
            prn=self.handle_packet,
            store=False,
        )
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        if timeout:
            sniff_kwargs["timeout"] = timeout

        sniff(**sniff_kwargs)

    def analyze_pcap(self, path: str, count: int = 0) -> None:
        """Read packets from a .pcap / .pcapng file."""
        pcap_path = Path(path).expanduser()
        if not pcap_path.is_file():
            raise RuntimeError(f"capture file not found: {pcap_path}")

        print(f"Reading packets from: {pcap_path}")
        print(f"(limit: {'unlimited' if count <= 0 else count} packets)\n")

        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                self.handle_packet(packet)
                if count > 0 and self._index >= count:
                    break

    # -- lifecycle -------------------------------------------------------- #
    def report(self) -> None:
        """Print the end-of-capture summary."""
        lines = [
            RULE,
            "Capture summary",
            RULE,
            f"Packets captured : {self.stats.total}",
            f"Bytes captured   : {self.stats.bytes_total}",
        ]
        if self.stats.protocols:
            lines.append("Protocol breakdown:")
            for proto, hits in self.stats.protocols.most_common():
                lines.append(f"    {proto:<6} {hits}")
        lines.append(RULE)

        block = "\n".join(lines)
        print("\n" + block)
        self._log("")
        self._log(block)

    def close(self) -> None:
        if self._log_handle:
            self._log(f"Finished: {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
            self._log_handle.close()
            self._log_handle = None
            print(f"\nLog written to: {self._log_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def list_interfaces() -> None:
    """Print the interfaces Scapy is aware of."""
    try:
        interfaces = conf.ifaces.values()
    except Exception as exc:  # pragma: no cover - platform dependent
        print(f"Could not enumerate interfaces: {exc}", file=sys.stderr)
        return

    print(f"{'NAME':<28}{'DESCRIPTION':<30}IP")
    print(SEPARATOR)
    for iface in interfaces:
        try:
            address = iface.ip or "-"
        except Exception:
            address = "-"
        print(f"{str(iface.name):<28}{str(iface.description)[:28]:<30}{address}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_analyzer.py",
        description="Capture or read network packets and print a formatted summary.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            '  python packet_analyzer.py -i "Wi-Fi" -c 20\n'
            '  python packet_analyzer.py -r sample.pcap -o capture.log\n'
            "  python packet_analyzer.py --list-interfaces\n"
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", "--interface", help="live capture interface (default: Scapy default)")
    source.add_argument("-r", "--read", metavar="PCAP", help="read packets from a .pcap/.pcapng file")

    parser.add_argument("-c", "--count", type=int, default=0,
                        help="stop after N packets (0 = unlimited, default: 0)")
    parser.add_argument("-f", "--filter", dest="bpf_filter",
                        help="BPF capture filter for live capture, e.g. \"tcp port 443\"")
    parser.add_argument("-t", "--timeout", type=int, default=None,
                        help="stop live capture after N seconds")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also write the summary to this log file")
    parser.add_argument("--payload-bytes", type=int, default=64,
                        help="max payload bytes shown per packet (default: 64)")
    parser.add_argument("--no-payload", action="store_true",
                        help="hide payload snippets entirely")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="list available capture interfaces and exit")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if _SCAPY_ERROR is not None:
        print("Error: Scapy is required but is not installed.", file=sys.stderr)
        print("Install it with:  pip install -r requirements.txt", file=sys.stderr)
        return 2

    if args.list_interfaces:
        list_interfaces()
        return 0

    if not args.interface and not args.read:
        print("Error: choose a source with -i/--interface or -r/--read.", file=sys.stderr)
        print("Tip: run with --list-interfaces to see available interfaces.", file=sys.stderr)
        return 2

    if args.count < 0:
        print("Error: --count must be zero or positive.", file=sys.stderr)
        return 2

    try:
        analyzer = PacketAnalyzer(
            output_path=args.output,
            payload_bytes=max(args.payload_bytes, 0),
            show_payload=not args.no_payload,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        if args.read:
            analyzer.analyze_pcap(args.read, count=args.count)
        else:
            analyzer.analyze_live(
                interface=args.interface,
                count=args.count,
                bpf_filter=args.bpf_filter,
                timeout=args.timeout,
            )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.", file=sys.stderr)
    except PermissionError:
        print(
            "\nError: permission denied while opening the capture interface.\n"
            "  * Linux/macOS : re-run with sudo, e.g.  sudo python packet_analyzer.py ...\n"
            "  * Windows     : run the terminal as Administrator and ensure Npcap is installed.\n"
            "Alternatively, analyse a saved capture with -r/--read (no privileges needed).",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(
            f"\nError: could not open the capture interface ({exc}).\n"
            "Check that the interface name is correct (--list-interfaces), that you have\n"
            "capture privileges and that libpcap/Npcap is installed.",
            file=sys.stderr,
        )
        return 1
    except Scapy_Exception as exc:
        print(f"\nError: packet capture failed: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    finally:
        analyzer.report()
        analyzer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
