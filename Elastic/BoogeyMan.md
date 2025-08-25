# Boogeyman3

<img width="638" height="383" alt="Screenshot (150)" src="https://github.com/user-attachments/assets/b1984b69-d5be-4449-966e-d0ed340ba55f" />

## Summary 
A threat actor known as the Boogeyman managed to compromise an employee of Quick Logistics LLC through an initial phishing campaign. From this foothold, the attacker sought to escalate the attack by targeting CEO Evan Hutchinson with a phishing email containing a malicious attachment.

Evan opened the attachment despite his skepticism. Although it appeared to do nothing, he reported the email to the security team, who then examined his workstation. During the investigation, the email attachment was discovered in his Downloads folder.

The suspected time window for the incident is between August 29 and August 30, 2023.

The malicious email is seen below:

<img width="600" height="800" alt="Screenshot (151)" src="https://github.com/user-attachments/assets/9aa599b7-5100-4c8e-ae89-1cbba1870c6a" />


## Interesting Facts

 Target Organization:	`1Quick Logistics LL`
 
 Targeted Individual	`Evan Hutchinson (CEO)`
 
 Initial Access	`Attacker compromised another employee and pivoted to target Evan`
 
 Method of Attack	`Phishing email with malicious document attached`
 
 Attachment Location	`Discovered in Downloads folder on Evan’s workstation`
 
 Incident Timeframe	`Between August 29–30, 2023`
 
 Investigation Trigger	`CEO reported the phishing email after opening the attachment`




## Investigation



### 1. What is the PID of the process that executed the initial stage 1 payload?
Answer format: ****

To determine the PID of the initial stage 1 payload, I began by narrowing the investigation to the confirmed incident timeframe: August 29–30, 2023. I focused on process creation logs (Event ID 4688) from the winlogbeat data source.

Since the compromise originated from a phishing email with an attachment, I filtered for executions involving explorer.exe, assuming the user double-clicked the file from the Downloads folder or opened it directly via File Explorer.


<img width="2069" height="1072" alt="Screenshot (152)" src="https://github.com/user-attachments/assets/06b7c571-ce3d-4d17-b447-e4b21e69a825" />



Answer: `6392`

### 2. The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

Answer format: **:\*******\********\*****.**** /* /* /* /* *:\******.*** *:\*****\******.***\*******\*****\****\******.***

To determine the command-line used during the file implantation phase, I first traced the Stage 1 payload, previously identified as mshta.exe (PID 6392), which executed a disguised .hta file delivered via phishing.

Using the following Kibana query to filter process creation events by the parent process ID:

`process.parent.pid : 6392`

This showed the Stage 1 payload copying the suspicious file review.dat to the user’s temporary directory, confirming the implantation step.

<img width="2068" height="841" alt="Screenshot (153)" src="https://github.com/user-attachments/assets/8df082a5-efd0-4c67-94a3-35c95c9a3e70" />



Answer:`"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat`

### 3. The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

Answer format: **:\*******\********\********.**** *:\******.***,*****************

I searched for process command lines containing the implanted filename review.dat using the wildcard query "*review.dat*".

Among the results, I identified the execution of the implanted file via rundll32.exe with the full command line:
"C:\Windows\System32\rundll32.exe D:\review.dat,DllRegisterServer".

This confirmed that the implanted payload was executed using rundll32.exe to register and run the malicious DLL.

<img width="2055" height="689" alt="Screenshot (154)" src="https://github.com/user-attachments/assets/e9df969f-59c5-483f-b357-a69b312405a1" />




Answer: `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer`

###4.The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

Answer format: ******

To determine the persistence mechanism used by the stage 1 payload, I began by filtering the process logs within the relevant time frame (August 29–30, 2023). Since scheduled tasks are commonly created using PowerShell or command prompt, I applied a filter for processes where the name was either powershell.exe or cmd.exe.

Within the filtered results, I searched for command lines related to scheduled task creation by looking for keywords such as Register-ScheduledTask and New-ScheduledTask. This led me to a PowerShell command executed by mshta.exe at Aug 29, 2023 @ 23:51:16.809, which included the creation of a scheduled task with the following snippet:

`Register-ScheduledTask Review -InputObject $D -Force`


This clearly indicates that the scheduled task created by the malicious script was named “Review”. The task was configured to execute rundll32.exe with the implanted file review.dat as the argument, ensuring persistence via daily execution at a scheduled time.

<img width="2052" height="938" alt="Screenshot (155)" src="https://github.com/user-attachments/assets/fdbe5b68-15ae-4fa7-b706-debf6e9782f4" />



Answer: `Review`

### 5. The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

Answer format: ***.***.***.***:**

To find the C2 (Command and Control) connection initiated by the implanted file, I looked for network activity related to the process executing the file. Since the implanted file was run by rundll32.exe, I filtered for events where process.name was "rundll32.exe".

Using the query:

`process.name:"rundll32.exe"`


I then checked the network connection details associated with this process. This showed multiple outbound connections to the IP address 165.232.170.151 on port 80. This consistent communication indicated that the stage 1 payload was contacting this IP and port as its C2 server.

<img width="2059" height="1064" alt="Screenshot (156)" src="https://github.com/user-attachments/assets/f8ba1463-ef69-4869-8657-fd283a13be2c" />



Answer: `165.232.170.151:80`

### 6. The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

Answer format: *********.***

fodhelper.exe is a well-known UAC bypass binary. Normally, attackers launch it to gain elevated privileges without triggering UAC prompts.



Answer: `fodhelper.exe`

### 7. Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

Answer format: *****://******.***/**********/********/********/********/*.*.**********/********_*****.***

To identify the GitHub link used by the attacker, I searched for any PowerShell commands that included the keyword "github.com" in the command line. This is because attackers often download tools from GitHub, and filtering by "github.com" helps quickly pinpoint such activity.

Using the simple query with "*github.com*" revealed the exact download command where the attacker used Invoke-WebRequest (iwr) to fetch the Mimikatz credential dumping tool.

<img width="2055" height="261" alt="Screenshot (157)" src="https://github.com/user-attachments/assets/aea574b6-b0ef-4b67-b026-6d756a4c0251" />



Answer: `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`


### 8. After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

Answer format: *******:********************************

The attacker used Mimikatz to perform credential dumping and then executed a Pass-the-Hash (PtH) attack to move laterally. By searching for mimikatz.exe in the logs, I found the process creation command which contains the username and NTLM hash used:

<img width="1938" height="207" alt="Screenshot (158)" src="https://github.com/user-attachments/assets/f09a7e6a-940e-4692-8581-d02443ce0044" />



Answer: `itadmin:F84769D250EB95EB2D7D8B4A1C5613F2`

###9. Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

Answer format: **_**********.***

Scrolling down, I could see the fileshare:

<img width="1943" height="460" alt="Screenshot (159)" src="https://github.com/user-attachments/assets/7318a9ee-417b-4368-b3d9-98ff2ec16e29" />




Answer:`IT_Automation.ps1`

### 10. After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)

Answer format: **************\*****.*****:*****************

Again, looking down we can see the credentials used:

<img width="1727" height="444" alt="image" src="https://github.com/user-attachments/assets/7ad8f859-3a15-4497-9868-19b368ae95f0" />





Answer: `QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987`

###11. What is the hostname of the attacker's target machine for its lateral movement attempt?

Answer format: **********



Answer: `WKSTN-1327`

###12. Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?

Answer format: ***********.***


<img width="2191" height="792" alt="Screenshot (163)" src="https://github.com/user-attachments/assets/601935aa-310c-458f-84eb-e0343c2814d5" />



Answer: `wsmprovhost.exe`

### 13. The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

Answer format: *************:********************************

<img width="794" height="318" alt="Screenshot (164)" src="https://github.com/user-attachments/assets/fa54dc4e-61ec-4783-9000-c3fd0b027f18" />



Answer: `administrator:00f80f2538dcb54e7adc715c0e7091ec`

### 14. After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?

Answer format: ********

<img width="889" height="316" alt="Screenshot (165)" src="https://github.com/user-attachments/assets/546b9522-097a-4cd4-a397-f5ffbf3154aa" />




Answer:`backupda`

###15. After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

Answer format: ****://**.**************.**/************.***

My machine died, but from earlier I had the answer from looking at powershell (I think)

Answer: `http://ff.sillytechninja.io/ransomboogey.exe`









Thanks for reading! :)
