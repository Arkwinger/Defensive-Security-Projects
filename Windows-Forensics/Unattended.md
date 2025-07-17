# Unattended Walkthrough

<img width="800" height="291" alt="Screenshot (148)" src="https://github.com/user-attachments/assets/007e3bf0-ecca-4f76-80e0-e327673d1894" />


## Summary: 
"Welcome to the team, kid. I have something for you to get your feet wet.
Our client has a newly hired employee who saw a suspicious-looking janitor exiting his office as he was about to return from lunch.
I want you to investigate if there was user activity while the user was away between 12:05 PM to 12:45 PM on the 19th of November 2022. If there are, figure out what files were accessed and exfiltrated externally."

## Task 1 - 2 `No Answer Needed`

In this room, we will be using `KAPE`, `Autopsy`, `Registry`, `Explorer`, and `JLECmd`.
Each tool plays a role in reconstructing user behavior and identifying signs of intrusion or exfiltration. Want help mapping these tools to specific steps in your report or timeline? I can help you stitch it all together.


## Task 3

We suspected someone accessed the user’s system during their lunch break with a specific goal in mind, rather than casually browsing. We need to find out keywords for searches they might have been doing.

Open the Registry Explorer from 'C:\Users\THM-RFedora\Desktop\tools' on the local disk. 

Load the User Hive (NTUSER.DAT) Navigate to the exported disk image folder: C:\Users\THM-RFedora\Desktop\kape-results\C From here, find the user's NTUSER.DAT — typically located in:
```
C:\Users\<USERNAME>\NTUSER.DAT
```
<img width="1085" height="443" alt="Screenshot (138)" src="https://github.com/user-attachments/assets/5643d451-6948-45fe-ba2e-0bf77ab64fbf" />

Navigate to the Search History Key Inside Registry Explorer, browse to:
```
Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```
This key stores entries typed into the Windows Explorer search bar.

<img width="1507" height="669" alt="Screenshot (139)" src="https://github.com/user-attachments/assets/802e6bfc-bb39-41c6-aea6-617dc68b2f46" />

<img width="1498" height="691" alt="Screenshot (140)" src="https://github.com/user-attachments/assets/fdb288d6-9dad-46cc-bb15-f8ab7358cc29" />

### What file type was searched for using the search bar in Windows Explorer? Answer: `.pdf`
### What top-secret keyword was searched for using the search bar in Windows Explorer? Answer: `continental`

# Task 4 

We need to identify the file downloaded to the Downloads folder during the suspicious activity window (12:05–12:45 PM on Nov 19, 2022). For this task, we will be using the `Autopsy` tool.

Open Autopsy and select `New Case` and use the local C drive.

<img width="1349" height="903" alt="Screenshot (143)" src="https://github.com/user-attachments/assets/5107681e-6717-44d5-ac5d-a3011a262261" />

We can see the file above. 

### What is the name of the downloaded file to the Downloads folder? Answer:`7z2201-x64.exe`
### When was the file from the previous question downloaded? (YYYY-MM-DD HH:MM:SS UTC) Answer:`2022-11-19 12:09:19 UTC`
### Thanks to the previously downloaded file, a PNG file was opened. When was this file opened? (YYYY-MM-DD HH:MM:SS) Answer: `2022-11-19 12:10:21` 

#Task 5

Uh oh. They've hit the jackpot and are now preparing to exfiltrate data outside the network.

There is no way to do it via USB. So what's their other option?

Next, we use the command:
```
JLECmd.exe -d C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ --csv .
```

This command is specifically crafted to:

Parse Jump List files from the disk image you've exported via KAPE.

Extract evidence of file activity — like which files were opened, how often, and when.

Convert all findings into a clean, searchable CSV file, making it easy to filter and analyze.

<img width="1275" height="675" alt="Screenshot (144)" src="https://github.com/user-attachments/assets/c68bced4-563c-40d2-9529-56d5669ffec3" />

It was interacted with 2 times. We can also see the date it was modified. 

To finish up, we have to answer the final two questions:  What is the generated URL of the exfiltrated data? What is the string that was copied to the pastebin URL?

Pastebin.com is a popular online platform where users can store and share plain text — often used for code snippets, logs, or quick notes. It’s been around since 2002, and its simplicity makes it a go-to tool for developers, cybersecurity analysts, and even threat actors.

The attacker used Pastebin.com to upload sensitive data outside the network.

<img width="1418" height="1111" alt="Screenshot (145)" src="https://github.com/user-attachments/assets/9e4f8389-50c0-44e8-a6b5-6c0d13f29783" />

<img width="459" height="290" alt="Screenshot (146)" src="https://github.com/user-attachments/assets/0e10f4a1-5541-42dc-85a6-359137647005" />

Exfiltrated URL: https://pastebin.com/1FQASAav

Data String Transferred: ne7AIRhi3PdESy9RnOrN

This method allowed the intruder to bypass physical transfer constraints (e.g., USB restrictions) and leverage a low-profile, browser-based exfiltration route.

We can find this by going back into autopsy, and lookinng in the web browser history. 

### A text file was created in the Desktop folder. How many times was this file opened? Answer: `2`
### When was the text file from the previous question last modified? (MM/DD/YYYY HH:MM) Answer: `11/19/2022 12:12`
### What is the generated URL of the exfiltrated data? Answer: `https://pastebin.com/1FQASAav`
### What is the string that was copied to the pastebin URL? Answer: `ne7AIRhi3PdESy9RnOrN`

## Summary:

The intruder began by searching for PDF files related to “continental,” then downloaded 7z2201-x64.exe, suggesting preparation for archiving or extracting sensitive data. A PNG was accessed shortly after, indicating visual content may have been viewed or staged. A text file was created on the Desktop, modified at 12:12 PM and opened twice. Its contents — ne7AIRhi3PdESy9RnOrN — were exfiltrated via Pastebin at this URL: https://pastebin.com/1FQASAav, bypassing physical transfer limitations like USB.

## Mitigations:
Block known paste-sharing platforms like Pastebin at the firewall level.
Monitor clipboard activity and outbound web submissions during sensitive timeframes.
Enable file access alerts for sensitive directories like Desktop or Downloads.
Restrict unauthorized install tools (e.g., 7-Zip installers) and limit execution via AppLocker or SRP.
Enforce stricter web proxy logging to track outbound connections in real time.


Thanks for reading! 






