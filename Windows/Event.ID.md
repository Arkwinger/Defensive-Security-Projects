# Windows System Logs

`Event ID 1074` (System Shutdown/Restart): This event log indicates when and why the system was shut down or restarted. By monitoring these events, you can determine if there are unexpected shutdowns or restarts, potentially revealing malicious activity such as malware infection or unauthorized user access.

`Event ID 6005` (The Event log service was started): This event log marks the time when the Event Log Service was started. This is an important record, as it can signify a system boot-up, providing a starting point for investigating system performance or potential security incidents around that period. It can also be used to detect unauthorized system reboots.

`Event ID 6006` (The Event log service was stopped): This event log signifies the moment when the Event Log Service was stopped. It is typically seen when the system is shutting down. Abnormal or unexpected occurrences of this event could point to intentional service disruption for covering illicit activities.

`Event ID 6013` (Windows uptime): This event occurs once a day and shows the uptime of the system in seconds. A shorter than expected uptime could mean the system has been rebooted, which could signify a potential intrusion or unauthorized activities on the system.

`Event ID 7040` (Service status change): This event indicates a change in service startup type, which could be from manual to automatic or vice versa. If a crucial service's startup type is changed, it could be a sign of system tampering.
Windows Security Logs

`Event ID 1102` (The audit log was cleared): Clearing the audit log is often a sign of an attempt to remove evidence of an intrusion or malicious activity.

`Event ID 1116` (Antivirus malware detection): This event is particularly important because it logs when Defender detects a malware. A surge in these events could indicate a targeted attack or widespread malware infection.

`Event ID 1118` (Antivirus remediation activity has started): This event signifies that Defender has begun the process of removing or quarantining detected malware. It's important to monitor these events to ensure that remediation activities are successful.

`Event ID 1119` (Antivirus remediation activity has succeeded): This event signifies that the remediation process for detected malware has been successful. Regular monitoring of these events will help ensure that identified threats are effectively neutralized.

`Event ID 1120` (Antivirus remediation activity has failed): This event is the counterpart to 1119 and indicates that the remediation process has failed. These events should be closely monitored and addressed immediately to ensure threats are effectively neutralized.

`Event ID 4624` (Successful Logon): This event records successful logon events. This information is vital for establishing normal user behavior. Abnormal behavior, such as logon attempts at odd hours or from different locations, could signify a potential security threat.

`Event ID 4625` (Failed Logon): This event logs failed logon attempts. Multiple failed logon attempts could signify a brute-force attack in progress.

`Event ID 4648 `(A logon was attempted using explicit credentials): This event is triggered when a user logs on with explicit credentials to run a program. Anomalies in these logon events could indicate lateral movement within a network, which is a common technique used by attackers.

`Event ID 4656` (A handle to an object was requested): This event is triggered when a handle to an object (like a file, registry key, or process) is requested. This can be a useful event for detecting attempts to access sensitive resources.

`Event ID 4672` (Special Privileges Assigned to a New Logon): This event is logged whenever an account logs on with super user privileges. Tracking these events helps to ensure that super user privileges are not being abused or used maliciously.

`Event ID 4698` (A scheduled task was created): This event is triggered when a scheduled task is created. Monitoring this event can help you detect persistence mechanisms, as attackers often use scheduled tasks to maintain access and run malicious code.

`Event ID 4700` & Event ID 4701 (A scheduled task was enabled/disabled): This records the enabling or disabling of a scheduled task. Scheduled tasks are often manipulated by attackers for persistence or to run malicious code, thus these logs can provide valuable insight into suspicious activities.

`Event ID 4702` (A scheduled task was updated): Similar to 4698, this event is triggered when a scheduled task is updated. Monitoring these updates can help detect changes that may signify malicious intent.

`Event ID 4719` (System audit policy was changed): This event records changes to the audit policy on a computer. It could be a sign that someone is trying to cover their tracks by turning off auditing or changing what events get audited.

`Event ID 4738` (A user account was changed): This event records any changes made to user accounts, including changes to privileges, group memberships, and account settings. Unexpected account changes can be a sign of account takeover or insider threats.

`Event ID 4771` (Kerberos pre-authentication failed): This event is similar to 4625 (failed logon) but specifically for Kerberos authentication. An unusual amount of these logs could indicate an attacker attempting to brute force your Kerberos service.

`Event ID 4776` (The domain controller attempted to validate the credentials for an account): This event helps track both successful and failed attempts at credential validation by the domain controller. Multiple failures could suggest a brute-force attack.

`Event ID 5001` (Antivirus real-time protection configuration has changed): This event indicates that the real-time protection settings of Defender have been modified. Unauthorized changes could indicate an attempt to disable or undermine the functionality of Defender.

`Event ID 5140` (A network share object was accessed): This event is logged whenever a network share is accessed. This can be critical in identifying unauthorized access to network shares.

`Event ID 5142` (A network share object was added): This event signifies the creation of a new network share. Unauthorized network shares could be used to exfiltrate data or spread malware across a network.

`Event ID 5145` (A network share object was checked to see whether client can be granted desired access): This event indicates that someone attempted to access a network share. Frequent checks of this sort might indicate a user or a malware trying to map out the network shares for future exploits.

`Event ID 5157` (The Windows Filtering Platform has blocked a connection): This is logged when the Windows Filtering Platform blocks a connection attempt. This can be helpful for identifying malicious traffic on your network.

`Event ID 7045` (A service was installed in the system): A sudden appearance of unknown services might suggest malware installation, as many types of malware install themselves as services.
