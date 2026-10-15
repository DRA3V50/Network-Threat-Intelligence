
import csv
import os
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, PcapReader


def parse_pcap(
    output_dir: Path,
    top_n: int = 10,
    pcap_path: Path | None = None,
):
    """
    Analyze a genuine PCAP/PCAPNG capture and export observed
    source-IP packet statistics.

    Set PCAP_PATH to the path of an authorized capture, or pass
    pcap_path directly. No synthetic traffic is generated.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    configured_path = pcap_path or os.environ.get("PCAP_PATH")

    if configured_path:
        capture_file = Path(configured_path)
    else:
        capture_file = output_dir / "sample_traffic.pcap"

    csv_output = output_dir / "top_source_ips.csv"

    if not capture_file.is_file():
        raise FileNotFoundError(
            f"No packet capture found: {capture_file}\n"
            "Provide a genuine PCAP/PCAPNG capture using PCAP_PATH."
        )

    stats = defaultdict(
        lambda: {
            "count": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "unique_destinations": set(),
        }
    )

    packets_read = 0
    ip_packets = 0

    try:
        with PcapReader(str(capture_file)) as capture:
            for packet in capture:
                packets_read += 1

                if IP not in packet:
                    continue

                ip_packets += 1
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                destination_ip = ip_layer.dst

                record = stats[source_ip]
                record["count"] += 1
                record["unique_destinations"].add(destination_ip)

                if TCP in packet:
                    record["tcp_packets"] += 1
                elif UDP in packet:
                    record["udp_packets"] += 1

    except Exception as exc:
        raise RuntimeError(
            f"Could not read capture '{capture_file}': {exc}"
        ) from exc

    if packets_read == 0:
        raise ValueError(
            f"The capture contains no readable packets: {capture_file}"
        )

    ranked = sorted(
        stats.items(),
        key=lambda item: item[1]["count"],
        reverse=True,
    )[:max(1, top_n)]

    with csv_output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "source_ip",
            "count",
            "tcp_packets",
            "udp_packets",
            "unique_destinations",
        ])

        for source_ip, record in ranked:
            writer.writerow([
                source_ip,
                record["count"],
                record["tcp_packets"],
                record["udp_packets"],
                len(record["unique_destinations"]),
            ])

    print(f"[+] Capture analyzed: {capture_file}")
    print(f"[+] Packets read: {packets_read}")
    print(f"[+] IPv4 packets: {ip_packets}")
    print(f"[+] Unique IPv4 source IPs: {len(stats)}")
    print(f"[+] Source statistics written to: {csv_output}")

    return {
        "capture_file": str(capture_file),
        "packets_read": packets_read,
        "ipv4_packets": ip_packets,
        "unique_source_ips": len(stats),
        "output_file": str(csv_output),
    }
