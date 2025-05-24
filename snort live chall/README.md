# TryHackMe "Snort Challenge - Live Attacks" room [here](https://tryhackme.com/room/snortchallenges2)

## Task 2: Stopping a Brute-Force Attack (SSH)

**Objective**: Use Snort in sniffer mode to identify the attack source, service, and port, then write an IPS rule to stop a brute-force attack and obtain the flag.

**Steps** :
1. **Sniffer Mode**:
   - Started Snort in sniffer mode to inspect traffic:
     ```bash
     snort -v
     ```
   - Observed traffic on ports 80 (HTTP, seemed legitimate) and 22 (SSH, repeated from one IP, indicating a brute-force attack).
   - Identified the attack source IP: `10.10.245.36`, targeting `tcp/22` (SSH).

2. **IPS Rule Creation**:
   - Created a directory and rule file:
     ```bash
     mkdir snort-2
     cd snort-2
     touch local.rules
     ```
   - Edited the rule file:
     ```bash
     nano local.rules
     ```
   - Added a rule to block the attacker’s traffic:
     ```text
     reject tcp 10.10.245.36 any <> any any (msg:"Blocked attacker"; sid:1000001; rev:1;)
     ```

3. **Test Rule**:
   - Tested the rule in console mode:
     ```bash
     snort -c local.rules -A console -Q --daq afpacket -i eth0:eth1
     ```
   - Confirmed the rule triggered alerts for `10.10.245.36` traffic.

4. **Run IPS Mode**:
   - Ran Snort in IPS mode with full logging to stop the attack:
     ```bash
     snort -c local.rules -A full -Q --daq afpacket -i eth0:eth1
     ```
   - Blocked traffic for at least one minute, causing the flag to appear on the desktop.

5. **Flag Retrieval**:
   - Checked the desktop:
     ```bash
     ls ~/Desktop
     cat ~/Desktop/flag.txt
     ```
   - Flag: `THM{81b7fef657f8aaa6e4e200d616738254}`.

**Answers** (per your input):
- **Flag**: `THM{81b7fef657f8aaa6e4e200d616738254}`
- **Name of the service under attack**: `tcp` (corrected to `SSH`, as `tcp` is the protocol, not the service; port 22 indicates SSH)  
- **Used protocol/port in the attack**: `tcp/22`


## Task 3: Stopping a Brute-Force Attack (Metasploit)

**Objective**: Use Snort in sniffer mode to identify the attack source, service, and port, then write an IPS rule to stop a Metasploit-related attack and obtain the flag.

**Steps** :
1. **Sniffer Mode**:
   - Created a directory and started Snort in sniffer mode:
     ```bash
     mkdir snort-1
     cd snort-1
     snort -X
     ```
     - **Note**: 
   - Observed traffic on ports 80 (HTTP, legitimate) and 4444 (suspicious, commonly associated with Metasploit reverse shells).
   - Identified the attack source IP: `10.10.144.156`, targeting `tcp/4444`.

2. **IPS Rule Creation**:
   - Created the rule file:
     ```bash
     touch local.rules
     nano local.rules
     ```
   - Added rules to block the attacker and Metasploit port (corrected SIDs and syntax):
     ```text
     reject tcp 10.10.144.156 any <> any any (msg:"Blocked malicious user"; sid:1000001; rev:1;)
     reject tcp any any <> any 4444 (msg:"Blocked default Metasploit port"; sid:1000002; rev:1;)
     ```

3. **Test Rule**:
   - Tested the rules in console mode:
     ```bash
     snort -c local.rules -A console -Q --daq afpacket -i eth0:eth1
     ```
   - Confirmed alerts for `10.10.144.156` and port 4444 traffic.

4. **Run IPS Mode**:
   - Ran Snort in IPS mode with full logging:
     ```bash
     snort -c local.rules -A full -Q --daq afpacket -i eth0:eth1
     ```
   - Blocked traffic for at least one minute, causing the flag to appear.

5. **Flag Retrieval**:
   - Checked the desktop:
     ```bash
     ls ~/Desktop
     cat ~/Desktop/flag.txt
     ```
   - Flag: `THM{0ead8c494861079b1b74ec2380d2cd24}`.

**Answers** (per your input):
- **Flag**: `THM{0ead8c494861079b1b74ec2380d2cd24}`
- **Used protocol/port in the attack**: `tcp/4444`
- **Tool highly associated with this port**: `Metasploit`  

