## Case 2 – Initial Access via Phishing 

## Scenario
&nbsp;&nbsp;&nbsp; I am working as SOC Level 1 Analyst for an MSSP. I have been tasked with investigating a phishing incident involving the download and execution of a malicious file.  The investigation will be performed utilizing Windows Event Viewer and Sysmon logs to perform an analysis of the event.

## Potential Indicators of Attack(IOAs)
-	Download of a .zip archive via Microsoft Edge
-	Creation of a file with double extensions
-	Execution of a suspicious file
-	Network connection to a suspicious domain following file execution
-	Files downloaded and Extracted to Administrator directories

## Analysis

### Filter For Process Creation and File creation Events

#### Filter used:
-	Filter by Event ID 1(Process Create) and 11 (File Create)

#### Analyst Observation:
-	Event IDs 1 and 11 were analyzed to identify patterns consistent with a web browser downloading and executing a file, a sequence commonly associated with phishing-based attacks. Further investigation will be required to determine the nature of the event sequence.

<img width="1307" height="402" alt="1_11_11_1" src="https://github.com/user-attachments/assets/8eb801fa-f374-4a37-bd49-2ddd49b6c764" />

### Event Sequence Investigation

#### Analyst Observation:
-	Investigation of the first Event ID (1) indicates behavior common to Microsoft Edge activity associated with browser-based file download activity preceding phishing-related execution.

<img width="1315" height="792" alt="browser_download_id1_step1" src="https://github.com/user-attachments/assets/6de6027f-d683-45da-872f-0ee491330b39" />


-	Investigation of the next Event ID (11) related to Sysmon file creation identified Microsoft Edge creating a file called top-cats.zip within the Administrators Downloads directory. The file is followed by Zone.Identifier, indicating the file originated from and external source, consistent with phishing-based delivery.

<img width="1307" height="765" alt="browser_download_id11_step2" src="https://github.com/user-attachments/assets/f3af84a0-4dbb-4857-9075-937d38a00d96" />


-	Further Analysis indicates the file best-cat.jpg.exe was created by Explorer.exe within the Administrator’s Picture directory following the extraction of the download archive. The use of a double file extension (.jpg.exe) is a commonly used technique used to disguise executable files as legitimate images, which is indicative of potentially malicious activity associated with phishing campaigns.

<img width="1315" height="787" alt="double_extension" src="https://github.com/user-attachments/assets/ff1d45b0-7b73-4dff-8982-66f7889a0fa6" />


-	Further analysis of the events identifies multiple files extracted from the original .zip archive.  However, the execution of best-cat.jpg.exe indicates a hidden executable was launched, consistent with malicious execution activity associated with phishing.

-	<img width="1310" height="782" alt="best_cat_exe_exe" src="https://github.com/user-attachments/assets/a64fc520-4362-4222-9664-52e5b6f70c18" />

### Investigate Events Related to Process ID 5484

#### Filter Used: 
*[EventData[Data[@Name=’ProcessId’]=’5484’]]

#### Analyst Observation:
-	Upon further analysis a network connection to a domain was identified (rjj.store). External threat intelligence validation was performed to demonstrate standard SOC workflow. The domain will appear as not malicious on VirusTotal, confirming it’s a lab-generated “malicious” domain. 

<img width="1852" height="952" alt="virustoal" src="https://github.com/user-attachments/assets/e1549960-1aef-49db-be3d-e636ad26274f" />


## Conclusion
The investigation identified a .zip archive (top-cats.zip) downloaded to the Administrator’s Downloads directory via Microsoft Edge. Following extractions a file with double extensions was created (best-cat.jpg.exe) which matches a common technique used to hide execution files as images. The execution of the file resulted in a connection to rjj.store, a simulated malicious domain. The correlation of these events follows malicious file delivery and execution events indicative of a potential phishing-style delivery mechanism.
