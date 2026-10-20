# Network Threat Intelligence Analysis

⚠️ **Automated Network Threat Intelligence, OSINT Correlation, and Security Data Analysis** ⚠️

This repository implements an **automated defensive threat-intelligence pipeline** that collects open-source threat indicators, retrieves known-exploited vulnerability intelligence, analyzes supplied network traffic captures, and generates visual reports for security analysis.

It focuses on **traceable intelligence, observable network data, and transparent reporting** to support defensive security operations and Blue Team workflows.

---

## 🎯 Project Purpose & Scope

The primary objectives of this project are to:

- Collect and organize **open-source threat indicators** from external intelligence feeds.
- Retrieve **known-exploited vulnerability records** from trusted public sources.
- Analyze network traffic captured in PCAP files.
- Identify exact matches between observed source IP addresses and compatible threat indicators.
- Generate repeatable reports and visualizations through automated workflows.
- Demonstrate practical **SOC, threat-intelligence, and Blue Team analysis techniques**.

This project is an **intelligence aggregation and analysis tool**. It is not a replacement for a vulnerability scanner, intrusion detection system (IDS), endpoint detection and response (EDR) platform, or full incident investigation.

---

## 🔄 Automation & Update Frequency

⏱️ **Automated Processing**

- Runs through **GitHub Actions** on the schedule configured in the repository workflow.
- Can also run when supported workflow triggers are activated.
- Retrieves external intelligence feeds and processes available input data.
- Generates CSV reports, charts, and a README summary.
- Records report timestamps in **UTC**.

Actual update frequency depends on the workflow configuration and whether each run succeeds. External feeds may change between executions.

---

## 📡 Intelligence Sources & Analysis Layers

### 🛰️ Open-Source Threat Intelligence (OSINT)

- Retrieves URL indicators from the **URLhaus public threat-intelligence feed**.
- Records available indicator metadata, including submission dates, URL status, threat type, and source references.
- Preserves the source of each indicator for analyst review.
- Does not invent confidence scores when the feed does not provide them.
- Supports exact indicator matching when observed network data and indicator types are compatible.

**Important:** A threat-feed indicator is an intelligence lead, not proof that a system has been compromised.

### 🔥 Vulnerability Threat Intelligence

- Retrieves known-exploited vulnerability records from the **CISA Known Exploited Vulnerabilities (KEV) Catalog**.
- Records available CVE identifiers, vendors, products, descriptions, catalog dates, and remediation guidance.
- Provides information about vulnerabilities known to have been exploited in the wild.
- Leaves severity and risk scores unassigned when the input source does not supply the necessary scoring data.

**Important:** A CISA KEV record does not establish that a particular computer, server, or network device is affected. Confirming exposure requires checking the actual product, version, configuration, and available vulnerability assessment results.

### 🌐 Network Traffic Analysis

- Parses packets from a supplied PCAP capture using the configured packet-analysis tools.
- Summarizes observed source IP addresses and packet counts.
- Supports exact source-IP comparisons against threat indicators explicitly identified as IP addresses.
- Produces network activity visualizations for analyst review.

**Important:** High packet volume alone does not prove malicious behavior. Findings depend on the capture provided, the protocols supported by the parser, and the quality of the available intelligence.

---

## 📊 Network Activity Visualization

🚨 **Top Source IPs by Observed Packet Count**

![Network Threat Activity](build/charts/network_activity.png)

This chart summarizes the most active source IP addresses observed in the analyzed capture.

Elevated packet counts may warrant further investigation, but can also result from normal application traffic, busy servers, monitoring systems, or misconfigured devices.

Analysts should consider additional evidence, including:

- Whether the source communicates with unexpected destinations.
- Whether the traffic matches a known threat indicator.
- Whether packet timing, protocol usage, or connection patterns are unusual.
- Whether the activity is consistent with the system's expected role.

---

## 🛡️ Data Quality & Limitations

- **External intelligence is not a confirmed incident.** Indicators and vulnerability records require context before action is taken.
- **No unsupported risk scores.** Missing confidence, severity, or risk values should remain unknown until reliable evidence is available.
- **No assumed asset exposure.** A vulnerability catalog does not replace scanning or inventory checks against your own systems.
- **Network findings depend on input quality.** Results are limited by the supplied PCAP and the parser's capabilities.
- **Source attribution matters.** Reports should preserve source names and references so analysts can investigate records independently.
- **Automated reports require review.** Data collection and chart generation support analyst decisions; they do not independently confirm malicious activity.

---

## 📁 Project Outputs

The pipeline generates structured outputs for review, including:

- `build/iocs/osint_iocs.csv` — collected threat-feed indicators and source metadata.
- `build/vulnerabilities/vuln_scan_sample.csv` — CISA KEV vulnerability-intelligence records. Despite the legacy filename, these are not automatically findings from a local vulnerability scan.
- `build/pcaps/top_source_ips.csv` — source-IP packet-count summaries from the analyzed capture.
- `build/charts/` — generated security data visualizations.

Output availability depends on the success of the workflow and the availability of the required input files and external sources.

---

## ⚖️ Responsible Use

This project is intended for **authorized defensive security, threat-intelligence analysis, and educational Blue Team work**. Use network captures and other security data only when you are authorized to access and analyze them.

<!-- AUTO-GENERATED-START -->

## Security Intelligence Dashboard

**Last updated (UTC):** 2026-10-20 22:07 UTC

> External threat intelligence is not proof of compromise. CISA KEV records are not local scan findings. Packet volume alone does not establish malicious behavior.

### Data coverage

![Security Data Coverage](https://raw.githubusercontent.com/DRA3V50/Network-Threat-Intelligence/main/build/charts/composite_threat.png)

### Threat-feed indicators

Source: [URLhaus](https://urlhaus.abuse.ch/) and sources recorded in the dataset. Confidence is shown as `N/A` when not provided by the source.

| ioc_value                          | ioc_type   | confidence   | source   | date_added          | url_status   | threat           | urlhaus_reference                     |
|:-----------------------------------|:-----------|:-------------|:---------|:--------------------|:-------------|:-----------------|:--------------------------------------|
| http://175.170.11.184:58959/bin.sh | url        | N/A          | URLhaus  | 2026-10-20 22:00:19 | online       | malware_download | https://urlhaus.abuse.ch/url/3953092/ |
| http://222.141.63.159:57872/i      | url        | N/A          | URLhaus  | 2026-10-20 21:51:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3953091/ |
| http://31.56.209.86/i586           | url        | N/A          | URLhaus  | 2026-10-20 21:43:14 | online       | malware_download | https://urlhaus.abuse.ch/url/3953090/ |
| http://176.65.139.47/arm           | url        | N/A          | URLhaus  | 2026-10-20 21:42:16 | online       | malware_download | https://urlhaus.abuse.ch/url/3953089/ |
| http://176.65.139.47/arm5          | url        | N/A          | URLhaus  | 2026-10-20 21:42:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3953085/ |
| http://176.65.139.47/mips          | url        | N/A          | URLhaus  | 2026-10-20 21:42:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3953086/ |
| http://176.65.139.47/arm7          | url        | N/A          | URLhaus  | 2026-10-20 21:42:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3953087/ |
| http://176.65.139.47/sh4           | url        | N/A          | URLhaus  | 2026-10-20 21:42:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3953088/ |

### Known-exploited vulnerability intelligence

Source: [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). These records describe known-exploited vulnerabilities; they do not confirm that this repository owner's systems are affected. Remediation guidance is retained in the CSV output.

| vulnerability   | vendor              | product                  | date_added   | known_ransomware_use   | source   |
|:----------------|:--------------------|:-------------------------|:-------------|:-----------------------|:---------|
| CVE-2026-106931 | EG Secure Solutions | SiteGuard Server Edition | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-96656  | Plex                | Media Server             | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-96655  | Plex                | Media Server             | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-96654  | Plex                | Media Server             | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-96652  | Plex                | Media Server             | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-110936 | Siemens             | Software Center          | 2026-10-20   | Unknown                | CISA KEV |
| CVE-2026-102764 | BeyondTrust         | Remote Support           | 2026-10-16   | Unknown                | CISA KEV |
| CVE-2025-61624  | Fortinet            | Multiple Products        | 2026-10-16   | Unknown                | CISA KEV |
| CVE-2026-21589  | Atlassian           | Multiple Products        | 2026-10-15   | Unknown                | CISA KEV |
| CVE-2026-105134 | Ahsay               | AhsayCBS                 | 2026-10-14   | Unknown                | CISA KEV |

![CISA KEV Records by Vendor](https://raw.githubusercontent.com/DRA3V50/Network-Threat-Intelligence/main/build/charts/vulnerability_distribution.png)

### Observed network traffic

The chart shows packet counts from the supplied network CSV. Gold bars indicate an exact source-IP match to an indicator explicitly typed as an IP address. No such match is inferred from a URL alone.

![Observed Network Traffic](https://raw.githubusercontent.com/DRA3V50/Network-Threat-Intelligence/main/build/charts/network_behavior.png)

<!-- AUTO-GENERATED-END -->











