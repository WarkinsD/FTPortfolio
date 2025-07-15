# Microsoft Security Stack Summary

## Overview
This lab explores the core use cases of **Microsoft’s Security Stack**—Microsoft Defender for Endpoint, Azure Active Directory (Azure AD), and Microsoft Sentinel. These tools are critical to cloud-based healthcare cybersecurity, particularly for identity protection and threat detection.

## Key Highlights
- **Microsoft Defender for Endpoint (EDR):**  
  - Blocks ransomware using ASR rules and behavioral analysis.  
  - Detects lateral movement or PowerShell abuse via suspicious command-line activity.  
- **Azure Active Directory (IAM):**  
  - Enforces MFA and conditional access for PHI-handling users.  
  - Blocks logins from suspicious regions or IPs.  
- **Microsoft Sentinel (SIEM/SOAR):**  
  - Detects brute-force login attempts and sign-in spikes.  
  - Monitors conditional access failures and anomalies with KQL queries.

## Compliance Relevance
- **Defender:** Secures endpoints that access PHI.  
- **Azure AD:** Ensures identity protection via MFA, RBAC, and access policies.  
- **Sentinel:** Supports **NIST SP 800-92** log monitoring and HITRUST reporting requirements.

## Files
- [Full Lab Write-Up (PDF)](./Microsoft%20Security%20Stack%20Summary.pdf)

## References
- Microsoft. (2024). Microsoft Defender for Endpoint: [Technical documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)  
- Microsoft. (2024). Azure AD: [Conditional Access and MFA best practices](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)  
- Microsoft. (2024). Microsoft Sentinel: [SIEM and SOAR overview](https://learn.microsoft.com/en-us/azure/sentinel/)  
- National Institute of Standards and Technology. (2012). [NIST SP 800-92 – Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
