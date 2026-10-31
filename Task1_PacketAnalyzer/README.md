# Network Packet Analyzer

**CodSoft Cyber Security Internship — Task 1**

A command-line packet sniffer written in Python with [Scapy](https://scapy.net/).
It captures live traffic or reads a saved `.pcap` file, parses each packet and
prints a clean, formatted summary of the headers and a payload snippet.

---

## Features

| # | Requirement | Implementation |
|---|-------------|----------------|
| 1 | Capture live packets **or** read a sample PCAP | `-i/--interface` (live) and `-r/--read` (offline) |
| 2 | Parse headers — Source IP, Destination IP, Protocol, payload snippet | `summarize_packet()` extracts all four; ports are appended for TCP/UDP |
| 3 | Clean formatted summary to terminal **or** a log file | `format_summary()` renders each packet; `-o/--output` mirrors everything to a log file and adds an end-of-capture summary |
| 4 | Error handling for interface permissions | `PermissionError` / `OSError` / `Scapy_Exception` are caught and turned into actionable messages with a non-zero exit code |

Extras that come for free:

- BPF capture filters (`-f "tcp port 443"`)
- Packet and time limits (`-c`, `-t`)
- Configurable payload snippet size (`--payload-bytes`) or `--no-payload`
- Interface discovery (`--list-interfaces`)
- Per-protocol statistics printed when the capture ends
- `KeyboardInterrupt` (Ctrl+C) is handled cleanly

---

## Requirements

- Python 3.8+ (developed and tested on Python 3.13)
- Scapy 2.5+

```bash
pip install -r requirements.txt
```

**For live capture only**, you also need a packet-capture driver:

- **Windows** — [Npcap](https://npcap.com/) (install with "WinPcap API-compatible Mode")
- **Linux** — `libpcap` (`sudo apt install libpcap-dev`)
- **macOS** — `libpcap` (ships with the OS)

Reading a `.pcap` file needs **none** of the above and works without elevated privileges.

---

## Usage

```bash
# List the interfaces Scapy can see
python packet_analyzer.py --list-interfaces

# Live capture — first 20 packets on the "Wi-Fi" interface
python packet_analyzer.py -i "Wi-Fi" -c 20

# Live capture, only HTTPS traffic, for 15 seconds, also logged to a file
python packet_analyzer.py -i "Wi-Fi" -f "tcp port 443" -t 15 -o capture.log

# Read a saved capture (no admin rights needed)
python packet_analyzer.py -r sample.pcap

# Read only the first 10 packets and hide payload snippets
python packet_analyzer.py -r sample.pcap -c 10 --no-payload
```

### Options

| Flag | Description |
|------|-------------|
| `-i, --interface NAME` | Live capture interface (default: Scapy's default interface) |
| `-r, --read PCAP` | Read packets from a `.pcap` / `.pcapng` file instead of sniffing |
| `-c, --count N` | Stop after `N` packets (`0` = unlimited, default) |
| `-f, --filter BPF` | BPF capture filter for live capture, e.g. `"udp port 53"` |
| `-t, --timeout N` | Stop a live capture after `N` seconds |
| `-o, --output FILE` | Also write the summary to a log file |
| `--payload-bytes N` | Max payload bytes shown per packet (default: 64) |
| `--no-payload` | Hide payload snippets entirely |
| `--list-interfaces` | List available capture interfaces and exit |

---

## Try it without root

`generate_sample_pcap.py` builds a small synthetic capture (ARP, TCP handshake,
HTTP request/response, DNS, ICMP) so the analyzer can be demonstrated anywhere:

```bash
python generate_sample_pcap.py sample.pcap
python packet_analyzer.py -r sample.pcap
```

---

## Sample output

```
------------------------------------------------------------------------
[#0004] 2024-10-27 09:19:25.000000  |  TCP    |  101 bytes
    src   -> 192.168.1.10:52344
    dst   -> 93.184.216.34:80
    info  -> flags=PA seq=1001 ack=5001
    data  -> 47 bytes
             ascii: GET /index.html HTTP/1.1..Host: example.com....
             hex  : 47 45 54 20 2f 69 6e 64 65 78 2e 68 74 6d 6c 20 ...
------------------------------------------------------------------------
[#0006] 2024-10-27 09:19:02.000000  |  UDP    |  71 bytes
    src   -> 192.168.1.10:51000
    dst   -> 192.168.1.1:53
    info  -> udp_len=29

========================================================================
Capture summary
========================================================================
Packets captured : 7
Bytes captured   : 468
Protocol breakdown:
    TCP    4
    ARP    1
    UDP    1
    ICMP   1
========================================================================
```

---

## Permission errors

Live sniffing opens a raw socket, which requires elevated privileges:

- **Windows** — run the terminal as **Administrator** and make sure Npcap is installed.
- **Linux / macOS** — run with `sudo`, or grant the Python binary capture
  capabilities (`sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)`).

If the interface cannot be opened the script prints a clear explanation and exits
with status `1` rather than raising a traceback:

```
Error: permission denied while opening the capture interface.
  * Linux/macOS : re-run with sudo, e.g.  sudo python packet_analyzer.py ...
  * Windows     : run the terminal as Administrator and ensure Npcap is installed.
Alternatively, analyse a saved capture with -r/--read (no privileges needed).
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime failure (interface/permission/log-file error, missing capture file) |
| `2` | Usage error (no source selected, negative count, Scapy missing) |

---

## Legal notice

Only capture traffic on networks and devices you own or are explicitly
authorised to test. Unauthorised interception of network traffic is illegal in
most jurisdictions.
