
## Example: Detection Of Reconnaissance Activities Leveraging Native Windows Binaries

Attackers often leverage native Windows binaries (such as net.exe) to gain insights into the target environment, identify potential privilege escalation opportunities, and perform lateral movement. Sysmon Event ID 1 can assist in identifying such behavior.

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count`
Splunk search results showing system executable paths, command lines, and event counts.
```

## Example: Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)

Attackers frequently exploit the use of githubusercontent.com as a hosting platform for their payloads. This is due to the common whitelisting and permissibility of the domain by company proxies. Sysmon Event ID 22 can assist in identifying such behavior.

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
Splunk search results showing PowerShell and svchost executable paths with GitHub query names and event counts.`
```

Within the search results, clear indications emerge, highlighting the utilization of githubusercontent.com for payload/tool-hosting purposes.

## Example: Detection Of PsExec Usage

PsExec, a part of the Windows Sysinternals suite, was initially conceived as a utility to aid system administrators in managing remote Windows systems. It offers the convenience of connecting to and interacting with remote systems via a command-line interface, and it's available to members of a computer’s Local Administrator group.

The very features that make PsExec a powerful tool for system administrators also make it an attractive option for malicious actors. Several MITRE ATT&CK techniques, including T1569.002 (System Services: Service Execution), T1021.002 (Remote Services: SMB/Windows Admin Shares), and T1570 (Lateral Tool Transfer), have seen PsExec in play.

Despite its simple facade, PsExec packs a potent punch. It works by copying a service executable to the hidden Admin$ share. Subsequently, it taps into the Windows Service Control Manager API to jump-start the service. The service uses named pipes to link back to the PsExec tool. A major highlight is that PsExec can be deployed on both local and remote machines, and it can enable a user to act under the NT AUTHORITY\SYSTEM account. By studying https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution and https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/ we deduce that Sysmon Event ID 13, Sysmon Event ID 11, and Sysmon Event ID 17 or Sysmon Event ID 18 can assist in identifying usage of PsExec.

# Case 1: Leveraging Sysmon Event ID 13

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```
Let's break down each part of this query:

index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath": This part of the query is selecting logs from the main index with the sourcetype of WinEventLog:Sysmon. We're specifically looking for events with EventCode=13. In Sysmon logs, EventCode 13 represents an event where a registry value was set. The Image field is set to C:\\Windows\\system32\\services.exe to filter for events where the services.exe process was involved, which is the Windows process responsible for handling service creation and management. The TargetObject field specifies the registry keys that we're interested in. In this case, we're looking for changes to the ImagePath value under any service key in HKLM\\System\\CurrentControlSet\\Services. The ImagePath registry value of a service specifies the path to the executable file for the service.
| rex field=Details "(?<reg_file_name>[^\\\]+)$": The rex command here is extracting the file name from the Details field using a regular expression. The pattern [^\\\]+)$ captures the part of the path after the last backslash, which is typically the file name. This value is stored in a new field reg_file_name.
| eval file_name = if(isnull(file_name),reg_file_name,(file_name)): This eval command checks if the file_name field is null. If it is, it sets file_name to the value of reg_file_name (the file name we extracted from the Details field). If file_name is not null, it remains the same.
| stats values(Image), values(Details), values(TargetObject), values(_time), values(EventCode), count by file_name, ComputerName: Finally, the stats command aggregates the data by file_name and ComputerName. For each unique combination of file_name and ComputerName, it collects all the unique values of Image, Details, TargetObject, and _time, and counts the number of events.
In summary, this query is looking for instances where the services.exe process has modified the ImagePath value of any service. The output will include the details of these modifications, including the name of the modified service, the new ImagePath value, and the time of the modification.

Splunk search results showing file names, computer names, executable paths, registry details, event times, and counts.

Among the less frequent search results, it is evident that there are indications of execution resembling PsExec.

# Case 2: Leveraging Sysmon Event ID 11

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename
```
Splunk search results showing Windows Update log file paths and event counts.

Again, among the less frequent search results, it is evident that there are indications of execution resembling PsExec.

# Case 3: Leveraging Sysmon Event ID 18

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
````
Splunk search results showing pipe names and event counts.

This time, the results are more manageable to review and they continue to suggest an execution pattern resembling PsExec.

## Example: Detection Of Utilizing Archive Files For Transferring Tools Or Data Exfiltration

Attackers may employ zip, rar, or 7z files for transferring tools to a compromised host or exfiltrating data from it. The following search examines the creation of zip, rar, or 7z files, with results sorted in descending order based on count.

  
```
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```
Splunk search results showing computer names, users, target filenames, and event counts for zip, rar, and 7z files.

Within the search results, clear indications emerge, highlighting the usage of archive files for tool-transferring and/or data exfiltration purposes.

## Example: Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools

Attackers may exploit PowerShell to download additional payloads and tools, or deceive users into downloading malware via web browsers. The following SPL searches examine files downloaded through PowerShell or MS Edge.

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count
```
Splunk search results showing PowerShell executable paths, target filenames, and event counts.

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count
```
The *Zone.Identifier is indicative of a file downloaded from the internet or another potentially untrustworthy source. Windows uses this zone identifier to track the security zones of a file. The Zone.Identifier is an ADS (Alternate Data Stream) that contains metadata about where the file was downloaded from and its security settings.

Splunk search results showing target filenames with Zone.Identifier and event counts.

Within both search results, clear indications emerge, highlighting the usage of PowerShell and MS edge for payload/tool-downloading purposes.

## Example: Detection Of Execution From Atypical Or Suspicious Locations

The following SPL search is designed to identify any process creation (EventCode=1) occurring in a user's Downloads folder.

  
```
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```
Splunk search results showing download paths for PsExec64.exe, SharpHound.exe, and randomfile.exe with event counts.

Within the less frequent search results, clear indications emerge, highlighting execution from a user's Downloads folder.

## Example: Detection Of Executables or DLLs Being Created Outside The Windows Directory

The following SPL identifies potential malware activity by checking for the creation of executable and DLL files outside the Windows directory. It then groups and counts these activities by user and target filename.

  
``
`index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```
Splunk search results showing users, target filenames, and event counts for executable and DLL files.

Within the less frequent search results, clear indications emerge, highlighting the creation of executables outside the Windows directory.

## Example: Detection Of Misspelling Legitimate Binaries

Attackers often disguise their malicious binaries by intentionally misspelling legitimate ones to blend in and avoid detection. The purpose of the following SPL search is to detect potential misspellings of the legitimate PSEXESVC.exe binary, commonly used by PsExec. By examining the Image, ParentImage, CommandLine and ParentCommandLine fields, the search aims to identify instances where variations of psexe are used, potentially indicating the presence of malicious binaries attempting to masquerade as the legitimate PsExec service binary.

  
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine
```
Splunk search results showing images, command lines, parent images, and parent command lines with event counts.

Within the search results, clear indications emerge, highlighting the misspelling of PSEXESVC.exe for evasion purposes.

## Example: Detection Of Using Non-standard Ports For Communications/Transfers

Attackers often utilize non-standard ports during their operations. The following SPL search detects suspicious network connections to non-standard ports by excluding standard web and file transfer ports (80, 443, 22, 21). The stats command aggregates these connections, and they are sorted in descending order by count.

  
```
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```
Splunk search results showing source IPs, destination IPs, destination ports, and event counts.

Within the search results, clear indications emerge, highlighting the usage of non-standard ports communication or tool-transferring purposes.

It should be apparent by now that with a comprehensive understanding of attacker tactics, techniques, and procedures (TTPs), we could have detected the compromise of our environment more swiftly. However, it is essential to note that crafting searches solely based on attacker TTPs is insufficient as adversaries continuously evolve and employ obscure or unknown TTPs to avoid detection.

