from datetime import datetime, timezone
import ipaddress
from pathlib import Path
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

COVERAGE_CHART = CHART_DIR / "composite_threat.png"
NETWORK_CHART = CHART_DIR / "network_behavior.png"
VULN_CHART = CHART_DIR / "vulnerability_distribution.png"

START = "<!-- AUTO-GENERATED-START -->"
END = "<!-- AUTO-GENERATED-END -->"

# Absolute raw URLs make the README's chart images resolve consistently on GitHub.
RAW_CHART_BASE = (
    "https://raw.githubusercontent.com/"
    "DRA3V50/Network-Threat-Intelligence/main/build/charts"
)
CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def load_csv(path):
    """Load a CSV if it exists; report missing/empty inputs without crashing."""
    if not path.exists():
        print(f"[!] Missing dataset: {path}")
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        print(f"[!] Could not read {path}: {exc}")
        return pd.DataFrame()


def clean_iocs(df):
    columns = [
        "ioc_value", "ioc_type", "confidence", "source",
        "date_added", "url_status", "threat", "urlhaus_reference",
    ]
    if df.empty:
        return pd.DataFrame(columns=columns)

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    for column in columns:
        if column not in df.columns:
            df[column] = pd.NA

    df["ioc_value"] = df["ioc_value"].fillna("").astype(str).str.strip()
    df = df[df["ioc_value"] != ""].copy()

    # Do not manufacture confidence values when the source has none.
    confidence = pd.to_numeric(df["confidence"], errors="coerce")
    df["confidence"] = confidence.map(
        lambda value: f"{value:g}" if pd.notna(value) else "N/A"
    )

    for column in columns:
        if column != "confidence":
            df[column] = df[column].fillna("").astype(str).str.strip()

    return df[columns]


def clean_vulnerabilities(df):
    """Normalize KEV or scanner CSV data without inventing scores."""
    if df.empty:
        return pd.DataFrame(
            columns=[
                "vulnerability", "severity", "severity_score", "risk_score",
                "source", "date_added", "vendor", "product",
                "description", "required_action", "due_date",
                "known_ransomware_use", "record_type",
            ]
        )

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    if "vulnerability" not in df.columns:
        if "cve" in df.columns:
            df["vulnerability"] = df["cve"]
        elif "cve_id" in df.columns:
            df["vulnerability"] = df["cve_id"]
        else:
            df["vulnerability"] = "Unidentified finding"

    defaults = {
        "severity": "Unknown",
        "severity_score": pd.NA,
        "risk_score": pd.NA,
        "source": "Unknown",
        "date_added": "",
        "vendor": "",
        "product": "",
        "description": "",
        "required_action": "",
        "due_date": "",
        "known_ransomware_use": "Unknown",
        "record_type": "Source record; verify whether this is a local finding",
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default

    for column in ["vulnerability", "severity", "source", "date_added",
                   "vendor", "product", "description", "required_action",
                   "due_date", "known_ransomware_use", "record_type"]:
        df[column] = df[column].fillna(defaults.get(column, "")).astype(str).str.strip()

    df["severity"] = df["severity"].replace("", "Unknown")
    df["severity_score"] = pd.to_numeric(df["severity_score"], errors="coerce")
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")

    # Keep all source fields, including remediation guidance, in the CSV-backed
    # dataframe. The README table below deliberately displays only short fields.
    return df


def clean_network(df):
    columns = [
        "source_ip", "count", "tcp_packets", "udp_packets", "unique_destinations"
    ]
    if df.empty:
        return pd.DataFrame(columns=columns)

    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    if "source_ip" not in df.columns or "count" not in df.columns:
        print("[!] Network CSV lacks source_ip or count; not charting it.")
        return pd.DataFrame(columns=columns)

    for column in columns:
        if column not in df.columns:
            df[column] = pd.NA

    df["source_ip"] = df["source_ip"].fillna("").astype(str).str.strip()
    df["count"] = pd.to_numeric(df["count"], errors="coerce")
    df = df.dropna(subset=["count"])
    df = df[(df["source_ip"] != "") & (df["count"] >= 0)].copy()
    return df.sort_values("count", ascending=False)


def extract_ip_iocs(iocs_df):
    """Return only indicators explicitly typed as IP addresses."""
    found = set()
    for _, row in iocs_df.iterrows():
        value = str(row.get("ioc_value", "")).strip()
        kind = str(row.get("ioc_type", "")).strip().lower()
        if kind not in {"ip", "ipv4", "ipv6"}:
            continue
        try:
            found.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return found


def calculate_network_behavior(network_df, iocs_df):
    """Add an exact IP-indicator match; packet count is not a risk score."""
    df = network_df.copy()
    if df.empty:
        df["ioc_match"] = pd.Series(dtype=bool)
        return df

    df["ioc_match"] = df["source_ip"].isin(extract_ip_iocs(iocs_df))
    maximum = df["count"].max()
    df["relative_volume_pct"] = df["count"] / maximum * 100 if maximum > 0 else 0
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


def markdown_table(df, columns, limit=8):
    """Create a compact Markdown table with only the requested columns."""
    if df.empty:
        return "_No data available._"

    selected = df.copy()
    for column in columns:
        if column not in selected.columns:
            selected[column] = "N/A"
    selected = selected[columns].head(limit).fillna("N/A")

    # Avoid accidental Markdown table breakage and excessive cell height.
    for column in selected.columns:
        selected[column] = selected[column].astype(str).map(
            lambda value: value.replace("|", r"\|").replace("\n", " ").strip()
        )
    return selected.to_markdown(index=False)


def generate_coverage_chart(iocs_df, vulns_df, network_df):
    values = [len(iocs_df), len(vulns_df), len(network_df)]
    labels = ["Feed indicators", "CISA KEV records", "Observed source IPs"]

    fig, ax = plt.subplots(figsize=(9, 4.2))
    apply_dark_style(fig, ax)
    bars = ax.bar(labels, values, color=["#8B78C6", "#D4AF37", "#4C9FAD"], width=0.58)

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + max(values + [1]) * 0.025,
            f"{int(height)}",
            ha="center",
            color="#FFFFFF",
            fontsize=9,
        )

    ax.set_title("Security Data Coverage")
    ax.set_ylabel("Records")
    ax.tick_params(axis="x", labelrotation=10)
    ax.set_ylim(0, max(values + [1]) * 1.18)
    fig.tight_layout()
    fig.savefig(COVERAGE_CHART, dpi=170, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def generate_network_chart(network_df):
    fig, ax = plt.subplots(figsize=(9, 4.5))
    apply_dark_style(fig, ax)

    if network_df.empty:
        ax.text(
            0.5, 0.5, "No valid network observations available",
            ha="center", va="center", color="#C9D1D9", transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        top = network_df.head(10).copy()
        labels = top["source_ip"].astype(str)
        colors = ["#D4AF37" if matched else "#4C9FAD" for matched in top["ioc_match"]]
        bars = ax.bar(labels, top["count"], color=colors, width=0.65)
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{int(bar.get_height())}", ha="center", va="bottom",
                color="#FFFFFF", fontsize=8,
            )
        ax.set_title("Observed Packets by Source IP")
        ax.set_ylabel("Packet count")
        ax.set_xlabel("Source IP")
        ax.tick_params(axis="x", labelrotation=30)
        if top["ioc_match"].any():
            ax.plot([], [], color="#D4AF37", label="Exact source-IP IOC match")
            ax.legend(facecolor="#0B1118", labelcolor="#C9D1D9")

    fig.tight_layout()
    fig.savefig(NETWORK_CHART, dpi=170, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def generate_vulnerability_chart(vulns_df):
    """Chart CISA KEV records by vendor, not by unavailable severity scores."""
    fig, ax = plt.subplots(figsize=(9, 4.5))
    apply_dark_style(fig, ax)

    if vulns_df.empty:
        ax.text(
            0.5, 0.5, "No vulnerability intelligence records available",
            ha="center", va="center", color="#C9D1D9", transform=ax.transAxes,
        )
        ax.set_axis_off()
    else:
        vendors = vulns_df["vendor"].fillna("").astype(str).str.strip()
        vendors = vendors.replace("", "Vendor not specified")
        counts = vendors.value_counts().head(10).sort_values()
        ax.barh(counts.index, counts.values, color="#D4AF37")
        ax.set_title("CISA KEV Records by Vendor (Top 10)")
        ax.set_xlabel("Record count")

    fig.tight_layout()
    fig.savefig(VULN_CHART, dpi=170, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def update_readme():
    iocs_df = clean_iocs(load_csv(IOCS))
    vulns_df = clean_vulnerabilities(load_csv(VULNS))
    network_df = calculate_network_behavior(clean_network(load_csv(PCAPS)), iocs_df)

    generate_coverage_chart(iocs_df, vulns_df, network_df)
    generate_network_chart(network_df)
    generate_vulnerability_chart(vulns_df)

    ioc_columns = [
        "ioc_value", "ioc_type", "confidence", "source",
        "date_added", "url_status", "threat", "urlhaus_reference",
    ]
    vulnerability_columns = [
        "vulnerability", "vendor", "product", "date_added",
        "known_ransomware_use", "source",
    ]
    network_columns = [
        "source_ip", "count", "tcp_packets", "udp_packets",
        "unique_destinations", "ioc_match",
    ]

    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    block = f"""{START}

## Security Intelligence Dashboard

**Last updated (UTC):** {updated}

> External threat intelligence is not proof of compromise. CISA KEV records are not local scan findings. Packet volume alone does not establish malicious behavior.

### Data coverage

![Security Data Coverage]({RAW_CHART_BASE}/composite_threat.png)

### Threat-feed indicators

Source: [URLhaus](https://urlhaus.abuse.ch/) and sources recorded in the dataset. Confidence is shown as `N/A` when not provided by the source.

{markdown_table(iocs_df, ioc_columns, limit=8)}

### Known-exploited vulnerability intelligence

Source: [CISA Known Exploited Vulnerabilities Catalog]({CISA_KEV_URL}). These records describe known-exploited vulnerabilities; they do not confirm that this repository owner's systems are affected. Remediation guidance is retained in the CSV output.

{markdown_table(vulns_df, vulnerability_columns, limit=10)}

![CISA KEV Records by Vendor]({RAW_CHART_BASE}/vulnerability_distribution.png)

### Observed network traffic

The chart shows packet counts from the supplied network CSV. Gold bars indicate an exact source-IP match to an indicator explicitly typed as an IP address. No such match is inferred from a URL alone.

![Observed Network Traffic]({RAW_CHART_BASE}/network_behavior.png)

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
