import csv
import io
import logging
from pathlib import Path

import requests

LOGGER = logging.getLogger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

CSV_COLUMNS = [
    "ioc_value",
    "ioc_type",
    "confidence",
    "source",
    "date_added",
    "url_status",
    "threat",
    "urlhaus_reference",
]


def pull_osint_iocs(output_dir: Path, limit: int = 100):
    """Import recent URLhaus malware URL indicators from its CSV feed."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "osint_iocs.csv"

    if limit < 1:
        raise ValueError("limit must be at least 1")

    LOGGER.info("Fetching recent URLhaus CSV feed")

    try:
        response = requests.get(
            URLHAUS_CSV_URL,
            timeout=(10, 30),
            headers={"User-Agent": "Network-Threat-Intelligence/1.0"},
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            "Could not download the URLhaus CSV feed. "
            "The previous IOC file has been left unchanged."
        ) from exc

    # URLhaus CSV exports use comment lines; the column header
    # begins with '# id,...'. Remove comments without losing that header.
    lines = response.text.splitlines()
    header_index = None

    for index, line in enumerate(lines):
        candidate = line.lstrip()
        if candidate.startswith("#"):
            candidate = candidate[1:].strip()

        if candidate.lower().startswith("id,dateadded,url,"):
            header_index = index
            lines[index] = candidate
            break

    if header_index is None:
        raise RuntimeError(
            "URLhaus response did not contain the expected CSV header. "
            "The previous IOC file has been left unchanged."
        )

    csv_text = "\n".join(
        line for line in lines[header_index:]
        if line.strip() and not line.lstrip().startswith("#")
    )

    reader = csv.DictReader(io.StringIO(csv_text))
    required = {"id", "dateadded", "url", "url_status", "threat"}

    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise RuntimeError(
            "URLhaus CSV columns were unexpected. "
            f"Found: {reader.fieldnames}"
        )

    rows = []
    seen = set()

    for item in reader:
        value = (item.get("url") or "").strip()
        if not value or value in seen:
            continue

        # Only accept HTTP(S) URLs from this URL-based feed.
        if not value.lower().startswith(("http://", "https://")):
            continue

        seen.add(value)
        rows.append({
            "ioc_value": value,
            "ioc_type": "url",
            "confidence": "",
            "source": "URLhaus",
            "date_added": item.get("dateadded", ""),
            "url_status": item.get("url_status", ""),
            "threat": item.get("threat", ""),
            "urlhaus_reference": item.get("urlhaus_link", ""),
        })

        if len(rows) >= limit:
            break

    if not rows:
        raise RuntimeError(
            "The URLhaus CSV feed returned no usable URLs. "
            "The previous IOC file has been left unchanged."
        )

    temporary_file = output_file.with_suffix(".csv.tmp")

    try:
        with temporary_file.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

        temporary_file.replace(output_file)
    finally:
        if temporary_file.exists():
            temporary_file.unlink()

    LOGGER.info("Imported %d URLhaus indicators", len(rows))
    LOGGER.info("Output: %s", output_file)

    return {
        "source": "URLhaus",
        "indicators_written": len(rows),
        "output_file": str(output_file),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pull_osint_iocs(Path("build/iocs"))
