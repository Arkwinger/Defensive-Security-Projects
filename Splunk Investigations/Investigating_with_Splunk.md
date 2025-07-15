# Investigating with Splunk Walkthrough 

## Scemario: SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.


## 1. How many events were collected and Ingested in the index main?









###  **Answer:** `12256`

## 2. On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?






###  **Answer:** `A1berto`

## 3. On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?






###  **Answer:** `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

## 4. Examine the logs and identify the user that the adversary was trying to impersonate.






###  **Answer:** `Alberto`

## 5. What is the command used to add a backdoor user from a remote computer?






### **Answer:** `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`

## 6. How many times was the login attempt from the backdoor user observed during the investigation?



### **Answer:** `0`

## 7. What is the name of the infected host on which suspicious Powershell commands were executed?





### Q1: **Answer:** `James.browne`

## 8. PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?






### **Answer:** `79`

## 9. An encoded Powershell script from the infected host initiated a web request. What is the full URL?








### **Answer:** `hxxp[://]10[.]10[.]10[.]5/news[.]php`

















