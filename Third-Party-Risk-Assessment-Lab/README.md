# Third-Party Risk Assessment Lab

## Overview
This lab simulated a third-party risk assessment aligned with real-world vendor management practices, focusing on vendors handling PHI and HIPAA compliance requirements.

## Key Highlights
- Evaluated four vendors using a structured Excel risk matrix.
- Assigned **likelihood** and **impact** scores, calculated total risk (L×I).
- Proposed mitigation strategies (MFA, SOC 2, AES-256 encryption).
- Assessed **residual risk** after mitigation.

## Sample Vendors & Risks
- **Goku Cloud Scheduling Inc.** – High risk due to lack of MFA and missing SOC 2 (PHI exposure).
- **Zeta Data Analytics** – Moderate risk; no encryption at rest.
- **Nimbus Billing Solutions** – High priority; outdated SSL & missing BCP.
- **Elite HVAC** – Low sensitivity but remote access risk.

## Compliance Relevance
- Supports **HIPAA & HITRUST** vendor risk management requirements.
- Uses **NIST SP 800-30** methodology for risk scoring.

## Files
- [Risk Matrix (Excel)](./Third_Party_Risk_Assessment_Lab.pdf)
- [Full Lab Write-Up (PDF)](./Third_Party_Risk_Assessment_Write-up.pdf)

## References
- Center for Internet Security. (n.d.). [CIS Controls v8: Safeguards for third-party and service provider management](https://www.cisecurity.org/controls/cis-controls-list)  
- U.S. Department of Health and Human Services. (n.d.). [HIPAA Security Rule: Administrative safeguards – Business Associate Agreements](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)  
- National Institute of Standards and Technology. (2023). [Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations (NIST SP 800-161 Rev. 1 Update 1)](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final)  
- Verizon. (2024). [2024 Data Breach Investigations Report (DBIR): Third-party and supply chain incidents](https://www.verizon.com/business/resources/reports/dbir/)
