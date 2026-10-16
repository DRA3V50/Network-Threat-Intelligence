
from pathlib import Path
from datetime import datetime, timezone
import ipaddress

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(".")
README = ROOT / "README.md"

IOCS = ROOT / "build/iocs/osint_iocs.csv"
VULNS = ROOT / "build/vulnerabilities/vuln_scan_sample.csv"
PCAPS = ROOT / "build/pcaps/top_source_ips.csv"

CHART_DIR = ROOT / "build/charts"
CHART_DIR.mkdir(parents=True, exist_ok=True)

COMPOSITE_CHART = CHART_DIR / "composite_threat.png"
NETWORK_CHART = CHART_DIR / "network_behavior.png"
VULN_CHART = CHART_DIR / "vulnerability_distribution.png"

START = "<!-- AUTO-GENERATED-START -->"
END = "<!-- AUTO-GENERATED-END -->"


def load_csv(path):
    if not path.exists():
        print(f"[!] Missing dataset: {path}")
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def clean_iocs(df):
    if df.empty:
        return pd.DataFrame(
            columns=[
                "ioc_value", "ioc_type", "confidence", "source",
                "date_added", "url_status", "threat", "urlhaus_reference"
            ]
        )

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    for column in [
        "ioc_value", "ioc_type", "confidence", "source",
        "date_added", "url_status", "threat", "urlhaus_reference"
    ]:
        if column not in df.columns:
            df[column] = pd.NA

    df["ioc_value"] = df["ioc_value"].fillna("").astype(str).str.strip()
    df = df[df["ioc_value"] != ""].copy()

    # Do not invent confidence values. Blank, missing, and NaN
    # confidence values remain explicitly unavailable.
    confidence = pd.to_numeric(df["confidence"], errors="coerce")
    df["confidence"] = confidence.map(
        lambda value: f"{value:g}" if pd.notna(value) else "N/A"
    )

    for column in [
        "ioc_type", "source", "date_added", "url_status",
        "threat", "urlhaus_reference"
    ]:
        df[column] = df[column].fillna("").astype(str)

    return df


def clean_vulnerabilities(df):
    if df.empty:
        return pd.DataFrame(
            columns=["vulnerability", "severity", "severity_score", "risk_score"]
        )

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    if "vulnerability" not in df.columns:
        if "cve" in df.columns:
            df["vulnerability"] = df["cve"]
        else:
            df["vulnerability"] = "Unidentified finding"

    if "severity" not in df.columns:
        df["severity"] = "Unknown"

    df["severity"] = df["severity"].fillna("Unknown").astype(str).str.title()

    if "severity_score" not in df.columns:
        severity_values = {
            "Critical": 9,
            "High": 7,
            "Medium": 5,
            "Low": 3,
        }
        df["severity_score"] = df["severity"].map(severity_values)

    if "risk_score" not in df.columns:
        risk_values = {
            "Critical": 100,
            "High": 75,
            "Medium": 50,
            "Low": 25,
        }
        df["risk_score"] = df["severity"].map(risk_values)

    # Keep scores missing if the source did not provide them and
    # severity alone cannot justify a derived score.
    df["severity_score"] = pd.to_numeric(
        df["severity_score"], errors="coerce"
    )
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")

    return df


def clean_network(df):
    if df.empty:
        return pd.DataFrame(
            columns=["source_ip", "count", "tcp_packets", "udp_packets",
                     "unique_destinations"]
        )

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    if "source_ip" not in df.columns or "count" not in df.columns:
        print("[!] Network CSV lacks source_ip or count; not charting it.")
        return pd.DataFrame(
            columns=["source_ip", "count", "tcp_packets", "udp_packets",
                     "unique_destinations"]
        )

    df["source_ip"] = df["source_ip"].fillna("").astype(str).str.strip()
    df["count"] = pd.to_numeric(df["count"], errors="coerce")
    df = df.dropna(subset=["count"])
    df = df[df["source_ip"] != ""]
    df = df[df["count"] >= 0]

    return df.sort_values("count", ascending=False)


def extract_ip_iocs(iocs_df):
    """Extract only indicators explicitly represented as IP addresses."""
    found = set()

    for _, row in iocs_df.iterrows():
        value = str(row.get("ioc_value", "")).strip()
        kind = str(row.get("ioc_type", "")).strip().lower()

        # The URLhaus feed provides URLs. Only use an indicator as an
        # IP when its value itself is a valid IP address.
        if kind not in {"ip", "ipv4", "ipv6"}:
            continue

        try:
            found.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    return found


def calculate_network_behavior(network_df, iocs_df):
    """Add observed volume and exact source-IP indicator match fields."""
    df = network_df.copy()

    if df.empty:
        df["ioc_match"] = pd.Series(dtype=bool)
        return df

    ip_iocs = extract_ip_iocs(iocs_df)
    df["ioc_match"] = df["source_ip"].isin(ip_iocs)

    # Volume is a relative ranking, not an anomaly or maliciousness score.
    maximum = df["count"].max()
    df["relative_volume_pct"] = (
        df["count"] / maximum * 100 if maximum > 0 else 0
    )

    return df.sort_values("count", ascending=False)


def apply_dark_style(fig, ax):
    fig.patch.set_facecolor("#0B1118")
    ax.set_facecolor("#0B1118")
    ax.tick_params(colors="#C9D1D9")

    ax.xaxis.label.set_color("#C9D1D9")
    ax.yaxis.label.set_color("#C9D1D9")
    ax.title.set_color("#C9D1D9")

    for spine in ax.spines.values():
        spine.set_color("#263342")

    ax.yaxis.grid(True, color="#263342", linewidth=0.6)
    ax.set_axisbelow(True)


def table(df, limit=8):
    if df.empty:
        return "_No data available._"

    safe = df.head(limit).copy()
    safe = safe.fillna("N/A")
    return safe.to_markdown(index=False)


def generate_composite_chart(iocs_df, vulns_df, network_df):
    # These are source-data counts, not a fabricated overall risk score.
    values = [
        len(iocs_df),
        len(vulns_df),
        len(network_df),
    ]
    labels = [
        "Feed indicators",
        "Vulnerability records",
        "Observed source IPs",
    ]

    fig, ax = plt.subplots(figsize=(10, 5))
    apply_dark_style(fig, ax)

    bars = ax.bar(
        labels, values,
        color=["#8B78C6", "#D4AF37", "#4C9FAD"],
        width=0.55,
    )

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + max(values + [1]) * 0.02,
            f"{int(height)}",
            ha="center",
            color="#FFFFFF",
        )

    ax.set_title("Security Data Coverage")
    ax.set_ylabel("Records available")
    ax.tick_params(axis="x", labelrotation=12)
    ax.set_ylim(0, max(values + [1]) * 1.18)

    fig.tight_layout()
    fig.savefig(COMPOSITE_CHART, dpi=180, facecolor=fig.get_facecolor())
    plt.close(fig)


def generate_network_chart(network_df):
    fig, ax = plt.subplots(figsize=(10, 5))
    apply_dark_style(fig, ax)

    if network_df.empty:
        ax.text(
            0.5, 0.5, "No valid network observations available",
            ha="center", va="center", color="#C9D1D9",
            transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        top = network_df.head(10).copy()
        labels = top["source_ip"].astype(str)
        colors = [
            "#D4AF37" if matched else "#4C9FAD"
            for matched in top["ioc_match"]
        ]

        bars = ax.bar(labels, top["count"], color=colors, width=0.65)

        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{int(bar.get_height())}",
                ha="center", va="bottom", color="#FFFFFF", fontsize=8,
            )

        ax.set_title("Observed Packets by Source IP")
        ax.set_ylabel("Packet count")
        ax.set_xlabel("Source IP")
        ax.tick_params(axis="x", labelrotation=35)

        if top["ioc_match"].any():
            ax.plot([], [], color="#D4AF37", label="Exact source-IP IOC match")
            ax.legend(facecolor="#0B1118", labelcolor="#C9D1D9")

    fig.tight_layout()
    fig.savefig(NETWORK_CHART, dpi=180, facecolor=fig.get_facecolor())
    plt.close(fig)


def generate_vulnerability_chart(vulns_df):
    fig, ax = plt.subplots(figsize=(8, 5))
    apply_dark_style(fig, ax)

    if vulns_df.empty or "severity" not in vulns_df.columns:
        ax.text(
            0.5, 0.5, "No vulnerability records available",
            ha="center", va="center", color="#C9D1D9",
            transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        counts = (
            vulns_df["severity"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
        )
        ax.bar(counts.index, counts.values, color="#D4AF37")
        ax.set_title("Vulnerability Records by Reported Severity")
        ax.set_ylabel("Record count")
        ax.tick_params(axis="x", labelrotation=20)

    fig.tight_layout()
    fig.savefig(VULN_CHART, dpi=180, facecolor=fig.get_facecolor())
    plt.close(fig)


def update_readme():
    iocs_df = clean_iocs(load_csv(IOCS))
    vulns_df = clean_vulnerabilities(load_csv(VULNS))
    network_df = clean_network(load_csv(PCAPS))

    network_df = calculate_network_behavior(network_df, iocs_df)

    generate_composite_chart(iocs_df, vulns_df, network_df)
    generate_network_chart(network_df)
    generate_vulnerability_chart(vulns_df)

    ioc_columns = [
        column for column in [
            "ioc_value", "ioc_type", "confidence", "source",
            "date_added", "url_status", "threat", "urlhaus_reference"
        ]
        if column in iocs_df.columns
    ]

    network_columns = [
        column for column in [
            "source_ip", "count", "tcp_packets", "udp_packets",
            "unique_destinations", "ioc_match"
        ]
        if column in network_df.columns
    ]

    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    block = f"""{START}

## Enterprise Security Intelligence Dashboard
**Last Updated (UTC):** {updated}

> Feed indicators are not proof of compromise. Network matches below
> are exact source-IP matches only. Packet volume alone does not establish
> malicious behavior. Vulnerability records depend on the input dataset.

---

## Threat Intelligence Feed Indicators
**Source:** URLhaus and any other sources explicitly recorded in the feed.

{table(iocs_df[ioc_columns])}

---

## Vulnerability Records
**Note:** Verify whether the input is from an actual scanner or a sample dataset.

{table(vulns_df)}

---

## Security Data Coverage
![Security Data Coverage](build/charts/composite_threat.png)

---

## Observed Network Traffic
The chart reports packet counts from the network CSV. Gold bars indicate an
exact match between a source IP and an indicator explicitly typed as an IP.

![Observed Network Traffic](build/charts/network_behavior.png)

---

## Vulnerability Records by Reported Severity
![Vulnerability Distribution](build/charts/vulnerability_distribution.png)

{END}
"""

    text = README.read_text(encoding="utf-8") if README.exists() else ""

    if START in text and END in text:
        before = text.split(START, 1)[0]
        after = text.split(END, 1)[1]
        text = before + block + after
    else:
        text = text.rstrip() + "\n\n" + block

    README.write_text(text, encoding="utf-8")
    print("README and dashboard charts updated.")


if __name__ == "__main__":
    update_readme()
