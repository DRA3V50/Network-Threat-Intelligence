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

## Enterprise Security Intelligence Dashboard
**Last Updated (UTC):** 2026-10-18 07:47 UTC

> Feed indicators are not proof of compromise. Network matches below
> are exact source-IP matches only. Packet volume alone does not establish
> malicious behavior. Vulnerability records depend on the input dataset.

---

## Threat Intelligence Feed Indicators
**Source:** URLhaus and any other sources explicitly recorded in the feed.

| ioc_value                         | ioc_type   | confidence   | source   | date_added          | url_status   | threat           | urlhaus_reference                     |
|:----------------------------------|:-----------|:-------------|:---------|:--------------------|:-------------|:-----------------|:--------------------------------------|
| http://220.161.160.148:39073/i    | url        | N/A          | URLhaus  | 2026-10-18 07:32:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3951778/ |
| http://219.157.254.40:41021/i     | url        | N/A          | URLhaus  | 2026-10-18 07:32:15 | online       | malware_download | https://urlhaus.abuse.ch/url/3951779/ |
| http://42.230.39.96:47720/bin.sh  | url        | N/A          | URLhaus  | 2026-10-18 07:18:08 | online       | malware_download | https://urlhaus.abuse.ch/url/3951777/ |
| http://61.53.135.200:51468/bin.sh | url        | N/A          | URLhaus  | 2026-10-18 07:17:10 | online       | malware_download | https://urlhaus.abuse.ch/url/3951775/ |
| http://61.53.135.200:51468/i      | url        | N/A          | URLhaus  | 2026-10-18 07:17:10 | online       | malware_download | https://urlhaus.abuse.ch/url/3951776/ |
| http://112.226.204.29:59814/i     | url        | N/A          | URLhaus  | 2026-10-18 07:15:38 | online       | malware_download | https://urlhaus.abuse.ch/url/3951774/ |
| http://59.180.135.152:41296/i     | url        | N/A          | URLhaus  | 2026-10-18 07:02:36 | online       | malware_download | https://urlhaus.abuse.ch/url/3951773/ |
| http://59.97.251.59:46282/i       | url        | N/A          | URLhaus  | 2026-10-18 07:02:10 | online       | malware_download | https://urlhaus.abuse.ch/url/3951769/ |

---

## Vulnerability Records
**Note:** Verify whether the input is from an actual scanner or a sample dataset.

| vulnerability   | severity   | severity_score   | risk_score   | source   | date_added   | vendor             | product              | description                                                                                                                                                                                                                                                                                                                                                                                                                 | required_action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | due_date   | known_ransomware_use   | record_type                                   |
|:----------------|:-----------|:-----------------|:-------------|:---------|:-------------|:-------------------|:---------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------|:-----------------------|:----------------------------------------------|
| CVE-2026-102764 | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-16   | BeyondTrust        | Remote Support       | BeyondTrust Remote Support contains an authentication bypass by spoofing vulnerability that could allow a remote attacker to perform file operations on the appliance.                                                                                                                                                                                                                                                      | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-19 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2025-61624  | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-16   | Fortinet           | Multiple Products    | FortiOS, FortiPAM, FortiProxy, and FortiSwitchManager contain a path traversal vulnerability that may allow an authenticated attacker with admin profile and at least read-write permissions to write or delete arbitrary files via specific CLI commands.                                                                                                                                                                  | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-19 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-21589  | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-15   | Atlassian          | Multiple Products    | Multiple Atlassian products (Bitbucket Data Center ,Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center, Crowd Data Center, Crucible and Fisheye) contain a files or directories accessible to external parties vulnerability which could allow an unauthenticated attacker to access specific files within the web application root directory in affected versions. | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-18 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-105134 | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-14   | Ahsay              | AhsayCBS             | Ahsay AhsayCBS contains a command injection vulnerability that could allow a remote attacker to execute operating system commands via manipulation of the random parameter in the Replication Receiver component’s /rps/api/json/UpdateReceivers.do endpoint. This vulnerability can be chained with CVE-2026-105133.                                                                                                       | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-17 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-76519  | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-14   | Cisco              | Secure Email Gateway | Cisco Secure Email Gateway contains a relative path traversal vulnerability that could allow an unauthenticated, remote attacker to write arbitrary files on the underlying operating system.                                                                                                                                                                                                                               | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-17 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-105133 | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-14   | Ahsay              | AhsayCBS             | Ahsay AhsayCBS contains an improper authentication vulnerability that could allow a remote attacker to bypass authentication via manipulation of the random parameter in the API component’s checkSysPwd function. This vulnerability can be chained with CVE-2026-105134.                                                                                                                                                  | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-17 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-0322   | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-14   | Palo Alto Networks | PAN-OS               | Palo Alto Networks PAN-OS contains a code injection vulnerability that could allow an authenticated attacker with network access to execute arbitrary code with root privileges on the firewall.                                                                                                                                                                                                                            | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-17 | Unknown                | Threat intelligence; not a local scan finding |
| CVE-2026-104935 | Unknown    | N/A              | N/A          | CISA KEV | 2026-10-13   | Ivanti             | Connect Secure       | Ivanti Connect Secure contains an authentication bypass by spoofing vulnerability that allows a remote unauthenticated attacker to execute arbitrary commands.                                                                                                                                                                                                                                                              | Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines. | 2026-10-16 | Unknown                | Threat intelligence; not a local scan finding |

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

<!-- AUTO-GENERATED-END -->


