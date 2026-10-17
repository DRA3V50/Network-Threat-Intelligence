
import csv
import json
from pathlib import Path

import requests


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT_FILENAME = "vuln_scan_sample.csv"


def generate_vulnerabilities(output_dir: Path, limit: int = 100):
    """
    Download CISA's Known Exploited Vulnerabilities catalog.

    These are vulnerability-intelligence records, not findings from
    a scan of the user's own systems.
    """
    print("[*] Downloading CISA Known Exploited Vulnerabilities catalog")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / OUTPUT_FILENAME
    temp_file = output_dir / f"{OUTPUT_FILENAME}.tmp"

    response = requests.get(
        CISA_KEV_URL,
        headers={"User-Agent": "Network-Threat-Intelligence/1.0"},
        timeout=30,
    )
    response.raise_for_status()

    catalog = response.json()
    vulnerabilities = catalog.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError("CISA KEV response contained no vulnerability records.")

    rows = []

    for item in vulnerabilities[:max(1, limit)]:
        cve_id = str(item.get("cveID", "")).strip()

        # Do not accept malformed or missing CVE identifiers.
        if not cve_id.startswith("CVE-"):
            continue

        rows.append(
            {
                "vulnerability": cve_id,
                "severity": "Unknown",
                "severity_score": "",
                "risk_score": "",
                "source": "CISA KEV",
                "date_added": item.get("dateAdded", ""),
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "description": item.get("shortDescription", ""),
                "required_action": item.get("requiredAction", ""),
                "due_date": item.get("dueDate", ""),
                "known_ransomware_use": item.get(
                    "knownRansomwareCampaignUse", ""
                ),
                "record_type": "Threat intelligence; not a local scan finding",
            }
        )

    if not rows:
        raise ValueError("No valid CVE records were found in the CISA catalog.")

    fieldnames = [
        "vulnerability",
        "severity",
        "severity_score",
        "risk_score",
        "source",
        "date_added",
        "vendor",
        "product",
        "description",
        "required_action",
        "due_date",
        "known_ransomware_use",
        "record_type",
    ]

    try:
        with temp_file.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        # Replace the previous report only after a successful download
        # and successful creation of the new CSV.
        temp_file.replace(output_file)

    finally:
        if temp_file.exists():
            temp_file.unlink()

    print(f"[+] Downloaded {len(rows)} CISA KEV records")
    print(f"[+] Report written to {output_file}")
    print("[!] These records do not establish that your systems are affected.")
