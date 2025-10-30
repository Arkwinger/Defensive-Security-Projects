## Notes

Issued by: TryDetectThis Intelligence

Classification: Internal – TLP:AMBER

TryDetectThis Intelligence has identified a coordinated supply chain attack campaign targeting open-source ecosystems, specifically, npm and Python package repositories. The campaign appears to be orchestrated by a threat actor leveraging long-term infiltration of neglected or low-profile projects to weaponize legitimate packages.

The attacker’s strategy involves contributing to moderately used but under-maintained libraries, gaining contributor or maintainer status through helpful commits. Once trusted, they publish malicious updates, embedding post-installation payloads or obfuscated backdoors within version releases that appear minor or maintenance-related.

These weaponized libraries often act as stagers for follow-on actions—such as downloading secondary payloads, establishing persistence, or exfiltrating tokens and credentials from developer machines. Due to their presence in tutorials, starter templates, or widely shared codebases, they have a high chance of spreading through organic adoption.



Your task as a Threat Hunter is to conduct a comprehensive hunting session in the TryGovMe environment to identify potential anomalies and threats. You are expected to:

1. Validate a Hunting Hypothesis

Investigate the given hypothesis and determine - based on your findings - whether it is valid or not.

2. Review IOCs from External Sources

Analyse the list of Indicators of Compromise provided by security teams from compromised partner organisations. These may lead you to uncover additional malicious activity or pivot points.

3. Reconstruct the Attack Chain

Perform a detailed investigation within the environment and reconstruct the attack chain, starting from the initial point of compromise to the attacker's final objective.

4. Determine the Scope of the Incident

Identify the impacted users, systems, and assets. Understanding the full scope is critical for response and containment.

5. Generate a Final Threat Hunting Report

Based on your findings and the reconstructed attack chain, compile a final Threat Hunting report highlighting the key observations and affected entities.



Host-Based IOCs
Type	Value
NPM Package	healthchk-lib@1.0.1
Registry Path	HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Registry Value Name	Windows Update Monitor
Registry Value Data	powershell.exe -NoP -W Hidden -EncodedCommand <base64>
Downloaded File Path	%APPDATA%\SystemHealthUpdater.exe
PowerShell Command	Invoke-WebRequest -Uri ... -OutFile ...
Process Execution	powershell.exe -NoP -W Hidden -EncodedCommand ...
Script Artifact	Found in package.json under "postinstall"
Network-Based IOCs
Type	Value
Download URL	http://global-update.wlndows.thm/SystemHealthUpdater.exe
Hostname Contacted	global-update.wlndows.thm
Protocol	HTTP (unencrypted)
Port	80
Traffic Behavior	Outbound file download to %APPDATA% via PowerShell









