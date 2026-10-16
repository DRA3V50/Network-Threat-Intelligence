
import csv
import ipaddress
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

LOGGER = logging.getLogger(__name__)

URLHAUS_FEED_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

CSV_COLUMNS = [
    "ioc_value",
    "ioc_type",
    "confidence",
    "source",
]


def classify_indicator(value: str) -> str:
    """Classify an indicator from its actual format, not at random."""
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if value.startswith(("http://", "https://")):
        return "url"

    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return "hash"

    return "domain"


def pull_osint_iocs(output_dir: Path, limit: int = 100):
    """
    Download recent malware URLs from URLhaus and export observed
    indicators. Confidence is left blank because this feed response
    is not a calibrated confidence score.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "osint_iocs.csv"

    if limit < 1:
        raise ValueError("limit must be at least 1")

    LOGGER.info("Fetching recent indicators from URLhaus")

    try:
        response = requests.get(
            URLHAUS_FEED_URL,
            timeout=(10, 30),
            headers={"User-Agent": "Network-Threat-Intelligence/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "URLhaus ingestion failed. No replacement IOC dataset "
            "was written; check network access and the feed status."
        ) from exc

    if not isinstance(payload, dict):
        raise RuntimeError("URLhaus returned an unexpected response format")

    urls = payload.get("urls", [])
    if not isinstance(urls, list):
        raise RuntimeError("URLhaus response did not contain a valid URL list")

    rows = []
    seen = set()

    for item in urls:
        if not isinstance(item, dict):
            continue

        value = str(item.get("url", "")).strip()
        if not value or value in seen:
            continue

        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue

        seen.add(value)
        rows.append(
            {
                "ioc_value": value,
                "ioc_type": "url",
                "confidence": "",
                "source": "URLhaus",
            }
        )

        if len(rows) >= limit:
            break

    if not rows:
        raise RuntimeError(
            "URLhaus returned no usable indicators. Existing output "
            "was left unchanged."
        )

    # Write to a temporary file first so a failed write does not
    # partially overwrite the previous dataset.
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

    LOGGER.info(
        "Saved %s URLhaus indicators to %s",
        len(rows),
        output_file,
    )

    return {
        "source": "URLhaus",
        "indicators_written": len(rows),
        "output_file": str(output_file),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    pull_osint_iocs(Path("build/iocs"))
