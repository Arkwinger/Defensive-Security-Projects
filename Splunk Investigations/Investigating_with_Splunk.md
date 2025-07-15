# Investigating with Splunk Walkthrough 

"Scemario: SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies."


## 1. How many events were collected and Ingested in the index main?

To kick off the investigation, I first needed to understand the scope of the dataset — how many log events we’re working with. This gives a rough sense of how active the ingestion process was and whether we’re dealing with a small subset or a flood of data.

The Splunk query used is:
```
index=main
````
I also need to set the appropriate time range. In this case, we will do "all time"

<img width="1531" height="896" alt="Screenshot (99)" src="https://github.com/user-attachments/assets/02a1d4bd-a93d-4a76-acb3-5a759990a1e8" />


###  **Answer:** `12256`

## 2. On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

To identify the newly created backdoor user, I focused on Windows Security Event ID 4720, which logs whenever a new user account is created. 

The Splunk query used is: 
```
index=main EventID=4720
```
This query filters for account creation events across all hosts. Once the results populated (which was only one event in this case), I inspected the TargetUserName or New_Account_Name field — depending on how the logs are structured — to find any unfamiliar or suspicious usernames.

<img width="1531" height="1168" alt="Screenshot (100)" src="https://github.com/user-attachments/assets/409d0727-84bb-471c-b8d3-7ae9421f399e" />


###  **Answer:** `A1berto`

## 3. On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

To answer this question, I focused on registry modification events, which are typically logged under EventCode 13 when using Sysmon. Since we already identified the backdoor user in the previous step, we can pivot off that username to find registry changes tied to their creation.

The Splunk query used is:
```
index=main EventID=13 A1berto
```

The field TargetObject or registry_path will show the full path of the registry key that was modified.

<img width="1531" height="1172" alt="Screenshot (101)" src="https://github.com/user-attachments/assets/813731e8-4deb-4620-be39-becba3f5da45" />


###  **Answer:** `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

## 4. Examine the logs and identify the user that the adversary was trying to impersonate.

From earlier, we know that the attacker created the account `A1berto`.

The Splunk query used is:
```
index=main A1berto
```
<img width="1526" height="1176" alt="Screenshot (102)" src="https://github.com/user-attachments/assets/c9f37fe1-4ab8-4667-ac71-8e95d89eda3c" />

This confirms that the adversary was attemption to impersonate an existing user with a similar name. 

(Impersonation allows attackers to blend in with normal operations. It can bypass detection systems that rely on known usernames. Spotting subtle name changes is key to identifying persistence and privilege abuse.)


###  **Answer:** `Alberto`

## 5. What is the command used to add a backdoor user from a remote computer?

To identify the command used to add a backdoor user remotely, I focused on process creation logs, which are typically captured under EventCode 1 in Splunk. These logs record every time a process is launched — including remote administrative commands.

<img width="1518" height="1148" alt="Screenshot (104)" src="https://github.com/user-attachments/assets/223759fe-f1d5-45eb-9c5a-65f18e1b9866" />

This command uses WMIC (Windows Management Instrumentation Command-line) to remotely execute a process on WORKSTATION6, adding the user A1berto with the password paw0rd1.

WMIC is a legitimate Windows tool often abused by attackers for remote execution.The use of net user /add confirms account creation. Running this remotely shows lateral movement and privilege escalation tactics.

### **Answer:** `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`

## 6. How many times was the login attempt from the backdoor user observed during the investigation?

To answer this, I focused on Windows Security Event ID 4624, which logs successful logon attempts. Since we’re tracking the backdoor user A1berto, we want to count how many times this account successfully logged in.

The Splunk query used:
```
index=main EventID=4624 Account_Name="A1berto"
| stats count
```

<img width="1536" height="535" alt="Screenshot (105)" src="https://github.com/user-attachments/assets/5fd1bc0d-8c91-4055-8c15-021422f7d348" />


Repeated logons by a backdoor account suggest active use or automation. Helps determine how long the attacker maintained access. Can be correlated with other events (file access, process creation) to build a full timeline.

### **Answer:** `0`

## 7. What is the name of the infected host on which suspicious Powershell commands were executed?

To identify the infected host where suspicious PowerShell commands were executed, I focused on process creation logs and PowerShell activity.

The Splunk query used:
```
index=main powershell

```
After using this query, I checked the Host name. Normally, I would have looked for entries with encoded or obfuscated PowerShell commands, long base64 strings, or suspicious cmdlets like Invoke-WebRequest, DownloadString, or FromBase64String. However, there was only one host...

<img width="1531" height="422" alt="Screenshot (106)" src="https://github.com/user-attachments/assets/412f03c6-2fad-49e7-b177-9254dcd9dc31" />

Identifying the host helps isolate the infection and begin remediation. PowerShell is often used for stealthy attacks — especially fileless malware and C2 communication. This host is likely the attacker’s initial foothold or staging point.

### Q1: **Answer:** `James.browne`

## 8. PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

To determine how many events were logged for the malicious PowerShell execution, I focused on EventCode 4103, which corresponds to PowerShell engine lifecycle events, which log when PowerShell starts up.

<img width="1536" height="249" alt="Screenshot (107)" src="https://github.com/user-attachments/assets/8a764a68-c341-4907-a07f-84da073783e8" />

### **Answer:** `79`

## 9. An encoded Powershell script from the infected host initiated a web request. What is the full URL?

To uncover the full URL from the encoded PowerShell script, I focused on EventID 4103, which logs PowerShell engine startup activity. These events often contain encoded commands in the CommandLine field.

The Splunk query used:
```
index=main EventID=4103
```
There is a very long string inside  `ContextInfo`:

<img width="1554" height="1161" alt="Screenshot (113)" src="https://github.com/user-attachments/assets/88adb4fb-06f6-4c99-904a-51e384c2e67f" />

I copied the Base64 string and decoded it using CyberChef with the From Base64 and Decode Text operations. The decoded script revealed two key variables:
Decoding 'aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==' gives:
```
http://10.10.10.5
```
<img width="2317" height="1053" alt="Screenshot (111)" src="https://github.com/user-attachments/assets/6c1820c6-f114-41f4-8b91-96b422900d8c" />

And looking into the output, we can also see the end of the full URL:
```
/news.php
```
<img width="1174" height="437" alt="Screenshot (112)" src="https://github.com/user-attachments/assets/9eaa230e-dd7c-4f10-af1a-4f0597f6160b" />

To safely report this as an Indicator of Compromise (IOC), we defang the URL:
### **Answer:** `hxxp[://]10[.]10[.]10[.]5/news[.]php`

















