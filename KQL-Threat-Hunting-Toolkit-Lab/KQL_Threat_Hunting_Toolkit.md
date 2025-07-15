
# KQL Threat Hunting Toolkit

This toolkit contains 11 curated Kusto Query Language (KQL) queries designed to simulate real-world threat hunting scenarios. Each query includes a short description of its objective and use case.

---

## 1. Brute-Force Login Detection

Detects accounts with more than 2 failed login attempts from the same IP within a one-hour window.

```kql
SigninLogs_CL 
| where ResultType != 0
| summarize FailedLogins = count() 
    by UserPrincipalName_s, IPAddress, bin(TimeGenerated, 1h)
| where FailedLogins > 2
```

---

## 2. Abnormal Login Times

Finds logins occurring outside standard work hours (before 8 AM or after 5 PM).

```kql
SigninLogs_CL
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 8 or Hour > 17
| summarize Count = count() by UserPrincipalName_s, bin(TimeGenerated, 1d)
```

---

## 3. Potential File Exfiltration or Recon Activity

Flags users generating large numbers of object access or process events (4662, 4663, 4688).

```kql
SecurityEvent_CL
| where EventID_s in ("4662", "4663", "4688")
| summarize EventCount = count() by Account_s, Computer, EventID_s, bin(TimeGenerated, 1h)
| where (EventID_s in ("4662", "4663") and EventCount > 10) 
       or (EventID_s == "4688" and EventCount > 10)
| project TimeGenerated, Account_s, Computer, EventID_s, EventCount
```

---

## 4. Special Privilege Assignments

Lists accounts assigned special privileges via Event ID 4672.

```kql
SecurityEvent_CL
| where EventID_s == "4672"
| summarize Count = count() by Account_s, Computer
| sort by Count desc
```

---

## 5. Scheduled Task Creation

Detects creation of scheduled tasks (Event ID 4698).

```kql
SecurityEvent_CL
| where EventID_s == "4698"
| project TimeGenerated, Account_s, Computer, Activity_s 
```

---

## 6. Account Lockout or Failed Logins (Broad View)

Summarizes all failed login attempts across accounts (Event ID 4625).

```kql
SecurityEvent_CL
| where EventID_s == "4625"
| summarize FailCount = count() by Account_s, Computer, Activity_s
| sort by FailCount desc
```

---

## 7. Audit Policy or Log Tampering

Surfaces potential log clearing or audit config changes via 4719, 1102, and 4902.

```kql
SecurityEvent_CL
| where EventID_s in ("4719", "1102", "4902")
| summarize EventCount = count() by EventID_s, Activity_s, Account_s
```

---

## 8. User Account Lifecycle Monitoring

Detects creation, enabling, or deletion of user accounts (4720, 4722, 4726).

```kql
SecurityEvent_CL
| where EventID_s in ("4720", "4722", "4726")
| summarize EventCount = count() by EventID_s, Account_s, Activity_s
```

---

## 9. High Volume Process Creation

Identifies accounts creating large numbers of processes within an hour (4688).

```kql
SecurityEvent_CL
| where EventID_s == "4688"
| summarize CreatedProcesses = count() by Account_s, bin(TimeGenerated, 1h)
| where CreatedProcesses > 10
```

---

## 10. Suspicious Script Execution

Detects script interpreters (e.g., PowerShell, WScript, MSHTA) from several event sources.

```kql
SecurityEvent_CL
| where EventID_s in ("4688", "4104", "4103", "4100", "4101")
| where Activity_s has_any ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "wmic")
| project TimeGenerated, Account_s, Computer, EventID_s, Activity_s
```

---

## 11. Geographic Login Anomaly

Detects when a user logs in from a location different from their last login.

```kql
SigninLogs_CL
| where isnotempty(UserPrincipalName_s) and isnotempty(Location_s)
| sort by UserPrincipalName_s asc, TimeGenerated asc
| extend PreviousLocation = prev(Location_s)
| where Location_s != PreviousLocation
| project TimeGenerated, UserPrincipalName_s, PreviousLocation, Location_s, IPAddress
```
