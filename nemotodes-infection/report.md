# Nemotodes Infection Analysis – November 2024

## Preliminary Finding
Captured malware traffic from a medical research facility showing signs of early-stage infection and C2 callbacks.

##  Detection Strategy
- Alert on encoded HTTP URIs
- Flag outbound traffic to low-reputation IPs

## False Positive – OCSP Certificate Check

During the analysis of packet #12788, an outbound HTTP GET request to r10.o.lencr.org appeared suspicious due to:

-A long, Base64-style URI

-External IP communication (104.117.247.99)

-Minimal payload size

However, upon investigation, this traffic was identified as part of a standard Online Certificate Status Protocol (OCSP) check initiated by the Windows host (Microsoft-CryptoAPI/10.0 user-agent).

The response headers confirmed this was a legitimate certificate validation:

Content-Type: application/ocsp-response
Server: nginx
Host: Let's Encrypt
This finding emphasizes the importance of context in SOC investigations — encoded traffic and external requests can mimic malicious behavior, but not all anomalies are threats.

[GET Request Packet Screenshot](screenshots/suspicious-get-request.png)](screenshots/suspicious-get-request.png)

*Figure 1: Encoded request sent to Let's Encrypt OCSP server by Windows host.*

-- (This was a start, and false, but am keeping it here for realistic reasons)


## Findings
The analysis began with a broad sweep using the following Wireshark filters:

```
http.request || tls.handshake.extensions_server_name
```
This revealed:

Multiple encrypted TLS sessions to known Microsoft services (legit)

One standout anomaly: a base64-style encoded HTTP POST to 194.180.191.64.

[GET Request Packet Screenshot](screenshots/suspicious-post-request.png)](screenshots/suspicious-post-request.png)

hxxp://194[.]180[.]191[.]64/fakeurl[.]htm

[View VirusTotal Screenshot](screenshots/suspicious-url-virustotal.png)

VirusTotal detection showing multiple engines flagging NetSupport RAT indicators linked to suspicious URL.*


This endpoint is linked to NetSupport Manager RAT operations and known malware campaigns.


 Confirmation
Packet analysis showed:

- No encryption (plain HTTP)

- Host 10.11.26.183 reaching out to a confirmed C2 server

- No headers resembling legitimate telemetry















