# New Hire Old Artifacts Walkthrough

<img width="1000" height="400" alt="Screenshot (115)" src="https://github.com/user-attachments/assets/99bad641-b225-4497-ba9d-c9d2b6abc5cf" />




"You are a SOC Analyst for an MSSP (managed Security Service Provider) company called TryNotHackMe.


A newly acquired customer (Widget LLC) was recently onboarded with the managed Splunk service. The sensor is live, and all the endpoint events are now visible on TryNotHackMe's end. Widget LLC has some concerns with the endpoints in the Finance Dept, especially an endpoint for a recently hired Financial Analyst. The concern is that there was a period (December 2021) when the endpoint security product was turned off, but an official investigation was never conducted. 

Your manager has tasked you to sift through the events of Widget LLC's Splunk instance to see if there is anything that the customer needs to be alerted on."


### 1. A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

I wanted to identify if a credential dumping utility had been executed. Browser-based password viewers often get used in post-exploitation to extract saved credentials. I looked for references to "password" or known tools.
The Splunk query I used was:

```
index=* sourcetype=*sysmon* ("BrowserPasswordDump.exe" OR "password")
```
<img width="1384" height="442" alt="Screenshot (116)" src="https://github.com/user-attachments/assets/fe45a944-523f-4ab1-8502-4ec5c7d15b20" />

The binary 11111.exe was located in a temp directory and flagged with the description “Web Browser Password Viewer.” This aligns with credential dumping activity commonly seen in red team exercises or live intrusions. Artifact confirms intent to extract stored credentials, likely from Chrome or similar browsers. 

Answer:`C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`

### 2. What is listed as the company name?

I already confirmed that 11111.exe executed from a temp directory and was tied to credential extraction. To trace its origin, I wanted to check metadata fields for company attribution — often helpful in identifying known utility authors or distinguishing custom malware from public tools.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* Image="*11111.exe" | table _time, Image, Company
```
<img width="1058" height="732" alt="Screenshot (120)" src="https://github.com/user-attachments/assets/6a321e13-f42a-4c09-8f45-b0ac71f11b4d" />

The binary 11111.exe, identified earlier as a web browser password viewer, is published by NirSoft. Nirsoft is a known developer of free Windows utilities. They are also used frequently by read team operations and post-compromise scenarios due to their ability to extract sensitive data silently and without installation

Answer:`NirSoft`

### 3. Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (format: file.xyz,file.xyz)

We already identified one suspicious binary (11111.exe) from the Temp folder. That immediately suggested a pattern — attackers often drop multiple executables in temp paths to avoid detection. To uncover others, I decided to search for all process executions from that same folder and inspect each hit for origin and behavior.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* Image="*Temp*"
```
Then sorted by Image field, looking for executables with suspicious names, metadata, or behavior indicators.
The first one is known NirSoft tooling used for dumping browser passwords. The second one is `IonicLarge.exe`. This looked like it was renamed for disguise. I looked down on the `OriginalFileName` and found `PalitExplorer.exe`

<img width="1409" height="822" alt="Screenshot (121)" src="https://github.com/user-attachments/assets/d88b8991-03fb-4969-973c-653b2ea06ff2" />

<img width="1403" height="1075" alt="Screenshot (123)" src="https://github.com/user-attachments/assets/0176ea16-43a7-444a-a5e6-e7c331ef889b" />

The two binaries were executed from C:\Users\FINANC~1\AppData\Local\Temp\, which is a common location for attacker staging. 11111.exe is a NirSoft credential dumper. IonicLarge.exe is likely renamed malware or a tool disguised to blend in. Their execution together suggests an initial compromise followed by credential harvesting or lateral movement preparation.

Answer:`IonicLarge.exe,PalitExplorer.exe`

### 4. The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.

After identifying IonicLarge.exe as a suspicious binary in the Temp folder, I wanted to verify if it established outbound connections. Sysmon logs (Event ID 3) can reveal destination IPs initiated by executables. This is perfect for spotting command-and-control or data exfiltration behavior.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* EventCode=3 Image="*IonicLarge.exe"
```
<img width="658" height="483" alt="Screenshot (126)" src="https://github.com/user-attachments/assets/a30fc5c5-4dd9-4520-99f5-68a4509bd9ce" />

There are two outbound connections coming from the given IP address. Defang the IP.

Answer:`2[.]56[.]59[.]42`

### 5. The same binary made some change to a registry key. What was the key path?

After confirming that IonicLarge.exe executed and made outbound connections, I wanted to check whether it also altered the system’s configuration to disable defenses. Registry modification is a common way attackers suppress antivirus or enable persistence.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* EventCode=13 Image="*IonicLarge.exe"
```
<img width="1051" height="874" alt="Screenshot (127)" src="https://github.com/user-attachments/assets/bd9576bf-a45c-4fd7-a29b-1911ed4ebfcb" />

Sysmon Event ID 13 shows that IonicLarge.exe modified a key within the Windows Defender policy path. This strongly suggests the binary attempted to weaken or disable security features on the host. Attackers often target this path to bypass antivirus protections and ensure follow-up malware executes without interference.

Answer:`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

### 6. Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (format: file.xyz,file.xyz)

After confirming that IonicLarge.exe modified registry keys and made outbound connections, I suspected the attacker might have tried to clean up traces. Killing processes and deleting binaries is a common tactic to evade detection or remove tools after use.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* (CommandLine="*taskkill*" OR CommandLine="*del*")

```
<img width="1396" height="506" alt="Screenshot (129)" src="https://github.com/user-attachments/assets/3508161f-2fb6-4002-b25c-e5dfa4eab689" />

Splunk logs show that two processes were explicitly terminated and their binaries deleted shortly after. The filenames appear randomly generated, which is typical of attacker tooling or payload droppers. This behavior suggests an attempt to clean up post-exploitation artifacts and avoid detection during forensic review.

Answer:`WvmIOrcfsuILdX6SNwIRmGOJ.exe,phcIAmLJMAIMSa9j9MpgJo1m.exe`

### 7. The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?

I broadened the scope to any Defender-related commands executed via PowerShell. By filtering for all process creation events involving PowerShell (EventCode=1), I inspected the CommandLine field directly.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* EventCode=1 powershell
```
<img width="1412" height="758" alt="Screenshot (130)" src="https://github.com/user-attachments/assets/090b3bad-3cf9-477a-9341-251a4cf8e48e" />

Mutliple entries show the same command above being executed. This WMIC command targets Windows Defender's internal namespace and sets a custom action for threat ID 2147737394. Action 6 represents “Allow,” meaning the attacker explicitly permitted this threat to run undetected. The use of Force=True applies it immediately, even if Defender policies would normally block it. This command is an advanced way to whitelist malware and suppress alerts.

Answer:`powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True`

### 8. Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)

After identifying the WMIC command used to modify Defender behavior, I wanted to extract all instances where ThreatIDDefaultAction_Ids were set. These IDs represent specific threat categories that the attacker configured to be allowed through Defender.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* CommandLine="*ThreatIDDefaultAction_Ids*" 
| table _time, CommandLine 
| sort _time
```

<img width="1406" height="1005" alt="Screenshot (132)" src="https://github.com/user-attachments/assets/5f8f5d5c-5723-402b-a0a6-9025bbfb58a2" />

Did some scanning...

Each of these IDs corresponds to a threat category that the attacker explicitly configured to be allowed `ThreatIDDefaultAction_Actions=6`. This effectively whitelists those threats in Defender, reducing its ability to block or alert on them. The use of WMIC and the `MSFT_MpPreference` class shows a deliberate attempt to bypass security controls using native Windows tooling.

Answer:`2147735503,2147737010,2147737007,2147737394`

### 9. Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?

After identifying multiple binaries in AppData\Local\Temp, I wanted to check other common AppData subdirectories like Roaming and LocalLow. Attackers often drop payloads in these paths to avoid detection and maintain persistence under user-level privileges.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* Image="*AppData*"
```
<img width="1423" height="85" alt="Screenshot (134)" src="https://github.com/user-attachments/assets/3ab48ea4-9f0f-47e7-a760-b120d5f0adef" />

his binary was executed from the Roaming directory, which is commonly used for user-specific application data. The folder name EasyCalc and the executable EasyCalc.exe suggest it may have been disguised as a legitimate calculator app. Its location and execution behavior indicate it was likely part of the attacker’s toolkit, possibly used for persistence or further compromise.

Answer:`C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe`

### 10. What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)

After confirming that EasyCalc.exe was executed from the AppData\Roaming\EasyCalc directory, I wanted to inspect which DLLs it loaded during runtime. DLL loading behavior can reveal dependencies, potential hijack targets, or malicious modules injected into the process.

The Splunk query I used was:
```
index=* sourcetype=*sysmon* EventCode=7 Image="*EasyCalc.exe"
```
Sort by time and ImageLoaded
```
index=* sourcetype=*sysmon* ImageLoaded Image="*EasyCalc.exe" | table _time, ImageLoaded
```
<img width="1423" height="941" alt="Screenshot (135)" src="https://github.com/user-attachments/assets/91c7f9e4-1718-48e7-b0bd-01d49751c2d4" />

These DLLs are part of standard Windows functionality, but their presence confirms that EasyCalc.exe successfully invoked system-level components. If any of these were loaded from non-standard paths or replaced by malicious versions, it could indicate DLL hijacking or injection. In this case, the loading behavior should be reviewed alongside file hashes and signatures for integrity.

Answer:`ffmpeg.dll,nw.dll,nw_elf.dll`

## Summary
During the forensic investigation of the “New Hire Old Artifacts” workstation, multiple indicators of compromise were uncovered. The attacker executed several malicious binaries from user-level `AppData paths`, including `11111.exe`, `IonicLarge.exe`, and `EasyCalc.exe`. These tools enabled credential harvesting, made outbound connections to a known malicious IP `(2[.]56[.]59[.]42)`, and actively modified Windows Defender settings through PowerShell and WMIC commands. Registry keys were altered to establish persistence and weaken system defenses, while evidence of cleanup was found in the form of terminated processes and deleted binaries. The attacker also used obscure directories to execute disguised malware (ex `EasyCalc.exe` from Roaming) which loaded multiple system DLLs during runtime.




