
import csv
import ipaddress
from pathlib import Path

BUILD_DIR = Path("build")
IOC_FILE = BUILD_DIR / "iocs" / "osint_iocs.csv"
NETWORK_FILE = BUILD_DIR / "pcaps" / "top_source_ips.csv"
OUTPUT_FILE = BUILD_DIR / "iocs" / "ioc_matches.csv"


def normalize_ip(value):
    """Return a canonical IP address, or None if value is not an IP."""
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def correlate_iocs(
    ioc_file=IOC_FILE,
    network_file=NETWORK_FILE,
    output_file=OUTPUT_FILE,
):
    """Match IP indicators to observed source IPs; never infer URL-to-IP matches."""
    ioc_file = Path(ioc_file)
    network_file = Path(network_file)
    output_file = Path(output_file)

    if not ioc_file.is_file():
        raise FileNotFoundError(f"IOC feed not found: {ioc_file}")

    if not network_file.is_file():
        raise FileNotFoundError(f"Network observations not found: {network_file}")

    with ioc_file.open(newline="", encoding="utf-8-sig") as file:
        ioc_rows = list(csv.DictReader(file))

    with network_file.open(newline="", encoding="utf-8-sig") as file:
        network_rows = list(csv.DictReader(file))

    # Build an index of IP indicators only.
    indicators_by_ip = {}
    for row in ioc_rows:
        value = row.get("ioc_value") or row.get("indicator_value") or ""
        indicator_type = (
            row.get("ioc_type") or row.get("indicator_type") or ""
        ).strip().lower()

        normalized = normalize_ip(value)
        if normalized and indicator_type in {"ip", "ipv4", "ipv6"}:
            indicators_by_ip.setdefault(normalized, []).append(row)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "observed_source_ip",
        "packet_count",
        "tcp_packets",
        "udp_packets",
        "unique_destinations",
        "matched_indicator",
        "indicator_source",
        "indicator_type",
        "indicator_date_added",
        "match_status",
    ]

    matches = []
    for row in network_rows:
        observed_ip = normalize_ip(row.get("source_ip", ""))
        if not observed_ip:
            continue

        matched_indicators = indicators_by_ip.get(observed_ip, [])
        for indicator in matched_indicators:
            matches.append({
                "observed_source_ip": observed_ip,
                "packet_count": row.get("count", ""),
                "tcp_packets": row.get("tcp_packets", ""),
                "udp_packets": row.get("udp_packets", ""),
                "unique_destinations": row.get("unique_destinations", ""),
                "matched_indicator": (
                    indicator.get("ioc_value")
                    or indicator.get("indicator_value")
                    or ""
                ),
                "indicator_source": indicator.get("source", ""),
                "indicator_type": (
                    indicator.get("ioc_type")
                    or indicator.get("indicator_type")
                    or ""
                ),
                "indicator_date_added": indicator.get("date_added", ""),
                "match_status": "IP indicator matched observed source IP",
            })

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(matches)

    print(f"[+] Network source IPs checked: {len(network_rows)}")
    print(f"[+] IP indicators available: {len(indicators_by_ip)}")
    print(f"[+] Correlation matches: {len(matches)}")
    print(f"[+] Match report written to: {output_file}")

    return {
        "network_rows_checked": len(network_rows),
        "ip_indicators_available": len(indicators_by_ip),
        "matches": len(matches),
        "output_file": str(output_file),
    }


if __name__ == "__main__":
    correlate_iocs()
