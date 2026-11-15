# network-forensics-attack-mapping

## Overview
A simulated three-phase attack was executed against an isolated lab target (Metasploitable2) while a full packet capture ran throughout - 185,378 packets, start to finish. The capture was then analyzed entirely from a defender's persepective:every finding in this repo was reconstructed from the wire, using nothing but Wireshark filters, timestamps, and packet contents - no assumption was made about the attacker's tooling or intent in advance. <br/>

Three phases were identified and reconstructed: an exhaustive 131,945-packet port scan (~3 minutes), a 69-minute, 50,940-packet SSH brute-force campaign ending in one successful authentication, and a 311-packet exploitation of a known backdoor in vsftpd 2.3.4 that delivered shell access in under a second once triggered. The whole incident, start to finish, spans roughly 95 minutes - most of it a brute-force window that offered a long, unused detection and response opportunity. </br>

This project demonstartes the SOC analyst workflow end to end: 
`raw packet capture -> phase reconstruction -> MITRE ATT&CK mapping -> a Python-genrated timeline visualization -> a structured incident analysis report with concrete detection and remediation recommendations` 
the same artefacts a real incident response handoff would produce.

Find the PDF report here: **[PDF Report](https://github.com/SheetalKaswan/network-forensics-attack-mapping/blob/main/network_forensics_attack_mapping.pdf)**

## Tools Used
- Wireshark
- Nmap
- Metasploit Framework
- Python (pandas, matplotlib)

## Attack Phases Captured

| Phase | Network Signature | Packets | Duration | MITRE Technique |
| ----- | ---------- | ----- | ----- | ------ | 
| 1 - Reconnaisance | SYN packets from a single source port, swept across a wide, non-sequential range of destination ports | 133,945 | ~3 min | T1046 - Network Service Discovery |
| 2 - SSH Brute Force | Repeated short-lived connections to port 22 - banner excahnge, then FIN,ACK close - until one connection completes key exchange and stays open | 50,940 | ~69 min | T1110 - Brute Force -> T1078 - Valid Accounts |
| 3 - vsftpd Backdoor Exploitation | FTP login with a :) trigger string in the username, immediately followed by an unsolicited session on port 6200 | 311 | <1 sec to trigger | T1190 - Exploit Public-Facing Application / T1059.004 - Unix Shell | 

## Attack Traffic Timeline – chronological reconstruction of events
<img width="969" height="726" alt="attack traffic timeline" src="https://github.com/user-attachments/assets/ea89d669-6f51-46c1-b429-6e4637b7c993" />

## Attack Timeline Visualization
Generated from a Wireshark packet export using analyze_attack.py:
1. **Top Panel (log scale):** Packet volume per time window, coloor-coded by phase. Reconnaissance is a sharp, compressesd spike; the brute force is a long, steady band; the successful session's close (packet 185060, RST,ACK) and the backdoor trigger are both marked right at the point exploitation begins.
2. **Bottom Panel:** Protocol distribution per phase - recon is 100% bare TCP (scan probes, no real service use), brute force splits almost evenly between SSHv2 and TCP overhead, and exploitation is dominated by TCp with a small FTP component (the login that triggered the backdoor)
3. **The two panels corroborate the phase boundaries identified manually in Wireshark:** each phase is time-bound and protocol-distinct, confirming these are three genuinely separate stages rather than an arbitrary split of one of continuous event.

## How to Reproduce
```bash
# Generate the traffic (attacker hat)

# Start a Wireshark capture on the host-only interface first
# Phase 1: Recon
nmap -sV -A -p- <target-ip> -oN evidence/project4_nmap.txt

# Phase 2: Brute force
msfconsole -q
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target-ip>
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
run

# Phase 3: Exploitation
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target-ip>
exploit

# Stop the Wireshark capture
```

## Key Findings

#### Phase 1 - Reconnaissance: 
A single source IP generated SYN packets against a wide, non-sequential spread of destination ports (133,945 packets total) in roughly 3 minutes - the port order itself (8888, 110, 113, 111, 21, 993, 80, 1723..) is consistent with Nmap's randomized scan order for a full-range (-p-) scan, not a simple linear sweep. Detection threshold: >100 connection attempts from one source in 10 seconds -> IDS alert, which would have fired within the first 10 seconds of the capture.
#### Phase 2 - SSH Brute Force:
A long run of short, automated connections to port 22 - each completing a protocol banner exchange and then closing via FIN,ACK - ran for roughly 69 minutes (50,940 packets) before one connection deviated from the pattern: it completed a full Diffie-Hellman key exchange itself, which happens on every attempt - is the clearest network-level indicator of a successful login. Note: because SSH encrypts everything after key exchange, the actual username/password pair isn't recoverable from the packet capture alone; that detail can only come from the attacking host's own tool output. Detection:>5 failed authentications per source per minute -> SIEM alert, which would have fired within minutes of the campaign starting.
#### Phase 3 - Exploitation: 
A connection to vsftpd on port 21 included a login attempt with the username Fsyx:) - the :) sequence is the known trigger for the vsftpd 2.3.4 supply-chain backdoor. Within the same second, an entirely unsolicited session opened on port 6200 and exchanged short, interactive command/response traffic before both connections closed. Port 6200 has no legitimate purpose on an FTP server; any traffic there in a production environment should trigger an immediate alert.

---

### Python Script
- analyze_attack.py takes a Wireshark CSV export and produces:
- A two-panel matplotlib chart (timeline + protocol breakdown)
- A terminal summary table with packet counts, timestamps and duration per phase
- Phase labels mapped to MITRE ATT&CK technique IDs
- The script is designed to be re-run against any .pcap export by updating the phase time-boundary constants at the top of the file.

### MITRE ATT&CK Summary
| Phase | Tactic | Technique ID | Technique |
| ----- | ------ | ------ | ------ |
| Recon | Discovery | T1046 | Network Service Discovery |
| Brute Force | Credential Access | T1110 | Brute Force |
| Auth Success | Initial Access | T1078 | Valid Accounts |
| Exploitation | Initial Access | T1190 | Exploit Public-Facing Application |
| Shell Access | Execution | T1059.004 | Unix Shell |

### Skills Demonstrated
- Network packet capture and analysis (Wireshark - filters, timestamp correlation, protocol dissection)
- Attack pattern recognition from raw traffic (recon signature, brute-force cadence, backdoor trigger)
- Recognizing the limits of passive network forensics (e.g., credentials hidden by SSH's own encryption) rather than overstating what the evidence shows
- MITRE ATT&CK framework - mapping observed network behaviour to technique IDs
- Python data analysis (pandas) and visualization (matplotlib) applied to security data
- Incident analysis report writing - defender framing, timeline reconstruction, detection recommendations
- Cross-discipline thinking: offensive security knowledge used to improve defensive detection

---

### Legal Disclaimer
This project was conducted entirely within an isolated, provate lab environment using Metasploitable2 - a freely distributed VM published by Rapid7 specifically for security training. No real systems, production networks, or user data were invloved. the attack techniques demonstrated here are well-documented and widely taught for defensive security purposes.


