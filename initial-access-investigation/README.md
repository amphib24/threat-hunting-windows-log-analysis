## Log Analysis Windows Event Viewer - Initial Access Investigation

## Introduction

&nbsp;&nbsp;&nbsp; Initial access is the point of the attack where the attacker successfully gains their initial foothold into a system or network. There are various techniques an attacker can leverage to gain initial access. This report focuses on three specific techniques which are the abuse of exposed services, which in this case will be Windows Remote Desktop Protocol(RDP),  the utilization of phishing-based execution, and the malicious use of USBs.

## Case 1 – Initial Access via RDP 
 ## Scenario
&nbsp;&nbsp;&nbsp; I am working as SOC Level 1 Analyst for an MSSP. An IT admin exposed RDP on a production server for the purpose of being able to access the server from home on the weekends. The service was configured with weak credentials (Username: Administrator Password: Summer2005). This misconfiguration likely enabled the attacker exploiting the vulnerable service to gain initial access to the server. The investigation will involve analyzing security logs using Windows Event Viewer to identify the nature of the initial compromise.

## Potential Indicators of Attack (IOAs)
-	High volume of failed logins on the Administrator account (Event ID 4625) within a short period of time
-	Successful login attempt (Event ID 4624) following the high volume of failed attempts
-	Presence of Remote Interactive logons (Logon Type 10), indicating successful RDP logon attempts

## Analysis

### Failed Login Attempts

#### Filter used:  
-	EventType 4625

#### Analyst Observation:
-	Investigation into failed login attempts identified a high volume of failed authentication attempts (Event ID 4625). Various accounts were identified during analysis, however the Administrator account appeared to be more targeted than the other. Given the elevated privileges associated with this account, and the volume of repeated failed attempts, is indicative of a potential brute force on the account. Further analysis is needed to determine if any account compromise occurred

### Filter Failed Logins by Administrator Account

#### Filter used: 
-	*[System[(EventID=4625]]
  and
  *[EventData[Data[@Name=’TargetUserName’]=’Administrator’]]

#### Analyst Observation: 
-	After narrowing the investigation to failed attempts specific to the Administrator account, the evidence shows 1,018 failed login attempts (Event ID 4625) occurring between 09:10:01 AM and 09:59:54 AM. The volume of failures targeted at a specific account is highly suspicious and indicative of behavior associated with brute force type attacks. 

### Filter Successful Logins by Administrator Account

#### Filter used:

-	*[System[(EventID=4624]]
  and
  *[EventData[Data[@Name=’TargetUserName’]=’Administrator’]]

#### Analyst Observation:
-	The evidence identifies three successful logins using the administrator account between 09:51:45 AM and 09:51:48 AM. The presence of a Successful login (Event ID 4624) with a Logon Type 10 indicates that RDP was used as the attacker’s initial access point into the network. 
-	Analysis of the preceding Logon Type 3 events reveals the originating workstation and source IP used by the attacker (IP= 203[.]205[.]34[.]107, Workstation= DESKTOP_QNBC4UU).
-	Sysmon Event ID 1 logs were analyzed for process correlation, however, no relevant entries were identified.

## Conclusion
&nbsp;&nbsp;&nbsp; The investigation uncovered a high volume of failed login attempts (Event ID 4625) isolated to one user (Administrator) over a short period of time, accompanied by a successful login (Event ID 4624) by the same user. The successful attempt was identified as Logon Type 10, which indicates the vector for initial access was RDP.  This behavior is consistent with techniques used in brute-force attacks against privileged user accounts. 
