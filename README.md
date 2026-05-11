# Windows Threat Hunting and Log Analysis
&nbsp;&nbsp;&nbsp; This repository is a collection of SOC level threat detection investigations Utilizing Windows log analysis. The investigations follow the labs from TryHackMe's SOC 1 Windows Threat Detection rooms, and are structured to simulate real-world SOC workflows. The investigations are broken into three main categories: initial access, post-compromise activities, and persistence mechanisms. The purpose of this repository is to demonstrate a SOC analyst approach to investigating threat activity on Windows hosts using native logging tools.

# Demonstrated Skills 
   - Windows Security log analysis using Event Viewer
   - Endpoint analysis using Sysmon for process creation and post compromise activity
   - Timeline Reconstruction
   - Attack vector analysis (RDP, Phishing, USB)
   - Threat hunting using log correlation and time-based analysis
   - Domain reputatatio analysis

# Investigations

 ## Initial Access
 
&nbsp;&nbsp;&nbsp; Initial access is the point of the attack where the attacker successfully gains their initial foothold into a system or network. There are various techniques an attacker can leverage to gain initial access. These reports report focuses on three specific techniques which are the abuse of exposed services, which in this case will be Windows Remote Desktop Protocol(RDP),  the utilization of phishing-based execution, and the malicious use of USBs.
### Technical Write ups
<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/rdp-brute-force">RDP Brute Force Writeup</a>

<a href =  "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/phishing-based%20execution">Phishing Base Execution Write up</a>

<a href = "https://github.com/amphib24/threat-hunting-windows-log-analysis/tree/main/initial-access-investigation/usb-malware-persistence">USB Malware Execution<a/>
