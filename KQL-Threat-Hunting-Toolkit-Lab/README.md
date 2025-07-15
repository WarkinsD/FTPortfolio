# KQL Threat Hunting Toolkit Lab

## Overview
This lab involved building a custom threat-hunting toolkit in **Microsoft Sentinel** using **Kusto Query Language (KQL)**. It simulates how SOC analysts detect suspicious activity by translating attack behaviors into detection logic.

## Key Highlights
- **11 tested KQL queries** for real-world detections (brute-force, persistence, privilege escalation, exfiltration).  
- Queries validated using **SigninLogs_CL** & **SecurityEvent_CL** tables.  
- Environment provisioned via **Microsoft Sentinel Content Hub**.  
- Schema validation ensured field accuracy and reproducibility.

## Sample Queries
1. **Brute-Force Login Detection** – 3+ failed login attempts in 1 hour from same IP.  
2. **Suspicious Script Execution** – Detects PowerShell, WScript, MSHTA.  
3. **Geographic Login Anomaly** – Flags logins from different locations than prior session.

## Compliance Relevance
- Demonstrates SOC operational readiness to detect **HIPAA-relevant breaches** and log anomalies.  
- Aligned with **MITRE ATT&CK®** techniques for persistence and lateral movement.

## Files
- [Full Lab Write-Up (PDF)](./KQL%20Write%20up.pdf)  
- [Screenshots of All 11 Queries (PDF)](./KQL%20Screenshots.pdf)  
- [Full KQL Toolkit (Markdown – Viewable Online)](./KQL_Threat_Hunting_Toolkit.md)

## References
- Microsoft. (2024). [Kusto Query Language (KQL) documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)  
- Microsoft. (2024). [Hunt for threats with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/hunting)  
- MITRE ATT&CK®. (2024). [Techniques & Tactics for Threat Detection](https://attack.mitre.org/)
