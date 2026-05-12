# Post-Compromise Collection and Exfiltration Investigation
## Scenario 
&nbsp;&nbsp;&nbsp;I am working as SOC Level 1 Analyst for an MSSP. I have been tasked with investigating post-compromise activity resulting from the execution of a malicious file on a Windows workstation. The investigation will be performed utilizing Windows Event Viewer and Sysmon logs to perform an analysis to determine the impact and scope of the incident. The malicious file (stealer.exe) was provided in the lab environment.

## Potential Indicators of Attack (IOAs)
   -	Execution of suspicious files from user directories 
   -	Creation of child processes from suspicious files 
   -	Execution of data staging commands 
   -	File compression
   -	Suspicious DNS queries 
   -	Suspicious outbound network connections

## Analysis

### Locate Suspicious Process

#### Filter Used:

-	*[System[(EventID=1)]
and EventData[Data[@Name=’Image’]=’C:\Users\Administrator\Desktop\Practice\Task 5\stealer.exe’]]

#### Analyst Observation: 

   -	Initial investigation of the suspected process (stealer.exe) identifies it was executed through Windows Explorer.exe (PPID=5276) with the process Id of 5164 which will be used for further investigation into the impact and scope of post-compromise activity.

<img width="1195" height="643" alt="initial_discovery" src="https://github.com/user-attachments/assets/ebc2e5eb-7443-456f-b2e4-099551307b03" />

### Filter For Process Creation Events (EventID 1)

#### Filter Used: 
 
  -	*[System[(EventID=1)] and EventData[Data[@Name=’ParentProcessId’]=’2500’]]

#### Analyst Observation 1: Directory Creation
   
   -	A brief review of all the corresponding events associated with stealer.exe identified a total of 12 processes following the execution of the file. Investigation of the first event identifies evidence of the malicious process creating a temporary directory (staging_58f1) using the command (cmd \c mkdir %%temp%%\staging_58f1). This behavior is consistent with data staging activity, where malware prepares a temporary location for staging collected data prior to exfiltration.

<img width="1201" height="507" alt="mkdir_command" src="https://github.com/user-attachments/assets/aac70a01-6335-4c58-852f-da4c8f5b4028" />


#### Analyst Observation 2: Copied User Information
   
   -	Further investigation of the next event identifies the process (stealer.exe) executing (powershell -c “Get-ClipBoard > $env:Temp\Staging_58f1\clipboard.txt”). This PowerShell command is used to extract clipboard contents and redirect the output to a file within a temporary staging directory. This behavior is consistent with data collection and staging activity targeting user-copied information.

<img width="1196" height="505" alt="clipboard_command_photo3" src="https://github.com/user-attachments/assets/0237e152-addd-4a3a-913e-1cd68e16c11a" />

#### Analyst Observation 3: Data Staging
   -	The process executed 8 xcopy commands targeting sensitive file locations and extensions:

   1)	cmd /c “xcopy %%userprofile%%\.aws %%temp%%\staging_58f1\aws /I /y” 

   2)	cmd /c "xcopy %%userprofile%%\.ssh %%temp%%\staging_58f1\ssh /i /y"
   
   3)	cmd /c "xcopy %%userprofile%%\Desktop\*.docx %%temp%%\staging_58f1\desktop /i /s /y"
   
   4)	cmd /c "xcopy %%userprofile%%\Desktop\*.pdf %%temp%%\staging_58f1\desktop /i /s /y"
   
   5)	cmd /c "xcopy %%userprofile%%\Desktop\*.xlsx %%temp%%\staging_58f1\desktop /i /s /y"
   
   6)	cmd /c "xcopy %%userprofile%%\Downloads\*.docx%%temp%%\staging_58f1\downloads /i /s /y"
   
   7)	cmd /c "xcopy %%userprofile%%\Downloads\*.pdf %%temp%%\staging_58f1\downloads /i /s /y"

   8)	cmd /c "xcopy %%userprofile%%\Downloads\*.xlsx %%temp%%\staging_58f1\downloads /i /s /y"

   These commands target common file types and directories, including AWS credentials, SSH keys, and user documents. All identified files were copied into temporary staging directories relevant to the directory they were found in. This behavior is indicative of broad data collection and staging activity, consistent with preparation for exfiltration. 


<img width="1186" height="498" alt="aws" src="https://github.com/user-attachments/assets/9d14d07c-c090-4328-ac56-7e699661e27b" />


<img width="1191" height="497" alt="docx" src="https://github.com/user-attachments/assets/1540fc0a-9dd3-44e6-93c5-46dd37af60ba" />


<img width="1186" height="497" alt="pdf" src="https://github.com/user-attachments/assets/da83fdfd-71c8-47ed-bc42-ac8ef8a020da" />

#### Analyst Observation 4: Staging Chrome Browser Data
   -	The process executed an additional xcopy command targeting browser user data:
      1)	cmd /c xcopy "%%localappdata%%\Google\Chrome\User Data\Default" %%temp%%\staging_58f1\browser /i /y
     This indicates an attempt to collect browser-stored data such as session data, cookies, and credentials. The data is staged in a temp directory, consistent with preparation for exfiltration.

<img width="1191" height="502" alt="browser" src="https://github.com/user-attachments/assets/aaf323a0-c2f3-4ae1-b553-de30e67d1717" />

#### Analyst Observation 5 :
   -	The process then compressed the temp directory (staging_58f1) into a .zip file using the following command: 
     1)	powershell -c "Compress-Archive -Force -Path $env:Temp\staging_58f1 -DestinationPath $env:Temp\staging_58f1.zip"
     This behavior is consistent with compression techniques used to make the exfiltration of large amounts of data easier to complete. 

<img width="1188" height="500" alt="compression" src="https://github.com/user-attachments/assets/5b1f0d19-4572-453e-8022-adbc066d84e3" />

### Cloud Based Exfiltration 

#### Filter used:
   -	*[EventData[Data[@Name=’Image’]=’C\:Users\Administrator\Desktop\Practice\Task 5\stealer.exe”

#### Analyst Observation:
   -	Further investigation identified DNS resolution and outbound network communication to collecteddata-storage-2025[.]s3[.]amazonaws[.]com(IP 16.182.40.97), which appears to be a Amazon S3 endpoint. The connection originated from stealer.exe (IP 10.66.144.110)
      which occurred over HTTPS (port 443), which indicates encrypted communication was used for the connection. This activity, combined with prior evidence of staging and compression, is indicative of data exfiltration to a cloud storage site. 

<img width="1196" height="765" alt="DNS " src="https://github.com/user-attachments/assets/37febb18-a459-44dd-9a18-309903f351f3" />

<img width="1190" height="737" alt="network connection" src="https://github.com/user-attachments/assets/c90e72b0-01c5-4642-9349-c5d35343a6ff" />

## Conclusion
&nbsp;&nbsp;&nbsp; The investigation of the stealer.exe process identified clear indications of post-compromise activity consistent with data collection, staging, and exfiltration. The process executed multiple commands to collect sensitive files, including AWS credentials (.aws), SSH keys (.ssh), browser data, and user documents (.pdf, .docx, .xlsx), which were then staged in a temporary directory (staging_58f1).
&nbsp;&nbsp;&nbsp; Further analysis revealed the collected data was compressed into a ZIP archive (staging_58f1.zip), indicating preparation for exfiltration. A network connection was identified via an active HTTPS connection to collecteddata-storage-2025[.]s3[.]amazonaws[.]com, an Amazon S3 endpoint. This communication combined with the staging activity is consistent with data exfiltration to a cloud storage site via encrypted communication.
