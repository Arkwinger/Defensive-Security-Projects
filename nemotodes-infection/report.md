# Nemotodes Infection Analysis – November 2024

##  Summary
Captured malware traffic from a medical research facility showing signs of early-stage infection and C2 callbacks.

##  Key IOCs
- External IP: `104.117.247.99`
- Internal Victim IP: `10.11.26.183`
- Suspicious HTTP Request: Base64-style GET traffic

##  Detection Strategy
- Alert on encoded HTTP URIs
- Flag outbound traffic to low-reputation IPs

##  Mitigation
- Patch systems, restrict outbound traffic, segment network zones
