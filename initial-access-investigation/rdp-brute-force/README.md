## Initial Access Investigation – RDP

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

<img width="1520" height="825" alt="4265_Initial_filter_step1" src="https://github.com/user-attachments/assets/c84f8d3c-060b-4fd7-afc5-287a124726b6" />

### Filter Failed Logins by Administrator Account

#### Filter used: 
-	*[System[(EventID=4625]]
  and
  *[EventData[Data[@Name=’TargetUserName’]=’Administrator’]]

#### Analyst Observation: 
-	After narrowing the investigation to failed attempts specific to the Administrator account, the evidence shows 1,018 failed login attempts (Event ID 4625) occurring between 09:10:01 AM and 09:59:54 AM. The volume of failures targeted at a specific account is highly suspicious and indicative of behavior associated with brute force type attacks. 

<img width="1520" height="867" alt="filter_out_by_admin_only_failed_pic1" src="https://github.com/user-attachments/assets/dab87e77-e0b2-44e4-a9b8-aaecb7df6502" />
<img width="1518" height="847" alt="filter_out_by_admin_only_failed_count_pic2" src="https://github.com/user-attachments/assets/a9ab9bc2-e9c5-4d71-9a2c-b69805b5f916" />

### Filter Successful Logins by Administrator Account

#### Filter used:

-	*[System[(EventID=4624]]
  and
  *[EventData[Data[@Name=’TargetUserName’]=’Administrator’]]

#### Analyst Observation:
-	The evidence identifies three successful logins using the administrator account between 09:51:45 AM and 09:51:48 AM. The presence of a Successful login (Event ID 4624) with a Logon Type 10 indicates that RDP was used as the attacker’s initial access point into the network. 
-	Analysis of the preceding Logon Type 3 events reveals the originating workstation and source IP used by the attacker (IP= 203[.]205[.]34[.]107, Workstation= DESKTOP_QNBC4UU).
-	Sysmon Event ID 1 logs were analyzed for process correlation, however, no relevant entries were identified.

<img width="1517" height="870" alt="filter_by4624_admin_filterpic" src="https://github.com/user-attachments/assets/81d3f52b-eec6-4765-b645-e7a56bd794a3" />
<img width="1517" height="866" alt="filter_by4624_admin_results" src="https://github.com/user-attachments/assets/2978b946-bb75-46c1-9adf-9a1046585393" />
<img width="1518" height="862" alt="attacker_workstation_ip" src="https://github.com/user-attachments/assets/714a2fd5-9424-4e01-aa3e-72bba5142be6" />

## Conclusion
&nbsp;&nbsp;&nbsp; The investigation uncovered a high volume of failed login attempts (Event ID 4625) isolated to one user (Administrator) over a short period of time, accompanied by a successful login (Event ID 4624) by the same user. The successful attempt was identified as Logon Type 10, which indicates the vector for initial access was RDP.  This behavior is consistent with techniques used in brute-force attacks against privileged user accounts.
