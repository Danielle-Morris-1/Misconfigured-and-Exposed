
# Unintended Exposure: Hunting for Vulnerable VMs

## Scenario

During routine maintenance, the security team is assigned to review virtual machines within the shared services cluster (which handles network services such as DNS, Domain Services, and DHCP) that were mistakenly exposed to the public internet. The goal is to identify any VMs that may have been misconfigured and check for brute-force login activity or unauthorized access originating from external IP addresses.

![image](https://github.com/user-attachments/assets/7c9201da-d5b8-4f59-a342-0762d31bc946)

---

## Technology Utilized 🛠️

* Microsoft Sentinel: Cloud-native SIEM solution for threat detection and response.
* Windows 10 Virtual Machines (Microsoft Azure): Cloud-based virtual machines for testing and analysis.
* Microsoft Defender for Endpoint: Endpoint Detection and Response (EDR) platform for endpoint security monitoring.
* Kusto Query Language (KQL): Query language used for data analysis and threat hunting in Microsoft Sentinel.

---

## 📑 Table of Contents
- [Hypotheses](hypotheses-#)
- [Data Collection](data-collection-#)
- [Timeline & Investigation](timeline--investigation)
- [MITRE ATT&CK Framework Mapping](mitre-attck-framework-mapping-#)
- [Response](response-#)
- [Lessons Learned](lessons-learned-#)

---

## Hypotheses 🔎

- **Hypothesis 1 (Brute-Force Success):**  
  Given the lack of account lockout on some older devices during the exposure window, it's possible that external actors successfully brute-forced credentials on at least one VM.

- **Hypothesis 2 (Reconnaissance):**  
  Even if brute-force attempts failed, external actors may have performed network scanning or service enumeration on the exposed VMs to gather information for future attacks.

- **Hypothesis 3 (Lateral Movement – Less Likely):**  
   If a successful login occurred, the attacker *could* have attempted lateral movement to other systems within the shared services cluster or the broader network. To be investigated more deeply if evidence is found of a successful login. 

---
## Data Collection 📊

### Relevant Microsoft Defender Tables

- `DeviceInfo` Contains detailed information about the devices being monitored by Microsoft Defender. It typically includes data like device name, operating system, etc. 
- `DeviceLogonEvents` Logs interactive, remote, and network logon attempts and outcomes.


<details>
<summary>Data Flow in Microsoft Sentinel</summary>

![image](https://github.com/user-attachments/assets/60830218-f703-45dd-9b9b-a886c7dd6def)

</details>  

---
## Timeline & Investigation

### Detection Query
It was discovered that `windows-target-1` had internet exposure lasting multiple days.

Query Input 🔽

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

Last Internet-Facing Timestamp: `2025-05-18T10:53:40.8708297Z`

---

### Brute-Force Analysis

Several external IPs attempted and failed to log into the system.

Query Input 🔽

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

KQL Output ⏬

![image](https://github.com/user-attachments/assets/ff1b935e-b274-446b-a7fd-bac7001b5d6c)

---

### Investigate Potential Brute-Force Success

Despite generating the most failed login attempts, the top 10 originating IP addresses did not successfully access the target machine.

Query Input 🔽

```kql
let RemoteIPsInQuestion = dynamic(["194.180.49.123","185.39.19.56", "194.165.16.43", "103.143.143.215", "185.156.73.226", "185.39.19.57", "52.162.240.156", "194.180.49.196", "194.180.49.198", "102.88.21.217"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

KQL Output ⏬

*No successful logons from these IPs.*

---

### Review Successful Logins

Over the last 30 days, the `labuser` account had only two successful logins originating from remote/network access.

Query Input 🔽

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```
KQL Output ⏬

![image](https://github.com/user-attachments/assets/30af25b6-e6c9-4d68-a876-1c8c4066045d)

Zero failed logon attempts for the `labuser` account were found, suggesting the absence of a brute-force attack and making a successful one-time password guess an unlikely scenario.

Query Input 🔽

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```
---

### Verify for IP Location Anomalies

The login IP for `labuser` was consistent with expected geographic locations—no anomalies detected.

Query Input 🔽

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

KQL Output ⏬

![image](https://github.com/user-attachments/assets/c0e33aec-64b2-49df-8a8d-9481f208506d)

Although the device was vulnerable to the internet and clear brute-force attempts were made, we found no proof of any successful intrusion or unauthorized access involving the `labuser` account

---

## MITRE ATT&CK Framework Mapping 🧩 

| Tactic              | Technique                          | Technique ID | Description                                                                 |
|---------------------|-------------------------------------|--------------|-----------------------------------------------------------------------------|
| Initial Access       | External Remote Services           | T1133        | VM exposed to internet—potential access via RDP/SMB                         |
| Credential Access    | Brute Force                        | T1110        | Numerous failed login attempts from external IPs                            |
| Discovery (Potential)| Account Discovery (Domain Accounts)| T1087.002    | Brute-force attempts may indicate account enumeration efforts               |

## Summary

Although no compromise was confirmed, indicators show:

- Exposure to **Initial Access** via misconfigured remote access
- Multiple **Credential Access** attempts through brute-force
- A need for continuous review to prevent **future exploitation**

---

## Response 🛡️

Reviewed exposure details for `windows-target-1`, confirmed no unauthorized logins.  
- Performed audit log and threat scan  
- Ran full malware and vulnerability scans  
- Hardened NSG rules to block all public internet access  
- Allowed RDP from known IPs only  
- Implemented MFA and account lockout policy  
- Monitoring continues, escalation if new activity is observed

---

## Lessons Learned 💡

- **Misconfigured Network Security Groups (NSGs) Can Lead to Critical Exposure**<br>
  Routine auditing of NSG rules is essential to ensure only intended systems are accessible, and only from approved sources.

- **Exposed Infrastructure Services Are High-Value Targets**<br>
  Systems supporting DNS, Domain Services, and DHCP should never be exposed to the public internet, as they are often targeted for lateral movement and privilege escalation.

- **Lack of Account Lockout Policy Increases Brute-Force Risk** <br>
  Without a lockout threshold, attackers can attempt an unlimited number of password guesses. Account lockout or throttling helps deter brute-force attempts.

- **MFA and Conditional Access Are Crucial for Defense-in-Depth** <br>
  Multi-Factor Authentication should be enforced on all externally accessible services to reduce the likelihood of unauthorized access.

- **Threat Detection Must Include Failed and Successful Logon Correlation** <br>
  Investigations should consider not just brute-force failures but also check if any failed IPs later logged in successfully.
  
---

## 📅 Revision History

| Version | Changes       | Date       | Modified By      |
|---------|---------------|------------|------------------|
| 1.0     | Initial draft | May 2025   | Danielle Morris  |

---

![Project Status](https://img.shields.io/badge/Status-Completed-brightgreen)  ![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting-blue)  ![Platform](https://img.shields.io/badge/Platform-Microsoft%20Defender-blueviolet)  ![Language](https://img.shields.io/badge/Scripting-KQL-yellow)

---
> *"Vulnerabilities don’t compromise systems—humans ignoring them do."*

