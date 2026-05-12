# Windows Threat Hunting and Log Analysis
&nbsp;&nbsp;&nbsp; This repository is a collection of SOC-level threat detection investigations utilizing Windows log analysis. The investigations follow the labs from TryHackMe's SOC 1 Windows Threat Detection rooms, and are structured to simulate real-world SOC workflows. The investigations are broken into three main categories: initial access, post-compromise activities, and persistence mechanisms. The purpose of this repository is to demonstrate a SOC analyst's approach to investigating threat activity on Windows hosts using native logging tools.

# Repository Status
Work in progress - continually updated as I complete write-ups
## Demonstrated Skills 
   - Windows Security log analysis using Event Viewer
   - Endpoint analysis using Sysmon for process creation and post compromise activity
   - Timeline Reconstruction
   - Attack vector analysis (RDP, Phishing, USB)
   - Threat hunting using log correlation and time-based analysis
   - Domain reputatation analysis

## Investigations

### Initial Access
 
&nbsp;&nbsp;&nbsp; This section contains investigations into initial access activity on Windows hosts. There are various techniques an attacker can leverage to gain initial access. These investigations focus on three specific techniques: the abuse of exposed services, which in this case will be Windows Remote Desktop Protocol (RDP), the utilization of phishing-based execution, and the malicious use of USBs.

#### Technical Write-Ups
<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/rdp-brute-force">RDP Brute Force</a>

<a href =  "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/phishing-based%20execution">Phishing Based Execution</a>

<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/usb-malware-persistence">USB Malware Execution<a/>

### Post Compromise

&nbsp;&nbsp;&nbsp; This section contains investigations into post-compromise activity on Windows hosts, focusing on discovery and reconnaissance techniques executed by malicious processes, detecting collection activity, and detecting tool transfers.

#### Technical Write-Ups

<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/post-compromise-investigations/discovery-investigation">Post-Compromise Discovery</a>

<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/blob/main/post-compromise-investigations/collection-and-exfil/README.md">Post-Compromise Collectection and Exfiltration</a>

### Persistence Mechanisms
Coming soon!
