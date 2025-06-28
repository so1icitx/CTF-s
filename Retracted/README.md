

# Incident Analysis: Sophie's Ransomware Incident [Retracted](https://tryhackme.com/room/retracted)

On January 8, 2024, Sophie, a user at a charity organization, experienced a ransomware incident after downloading an "antivirus" installer. The malware encrypted files, changed the desktop wallpaper with a ransom note, and was later reversed by an intruder who decrypted the files and left a message.

## Investigation Questions and Findings

### 1. Full Path of the Text File Containing the Message
**Question**: What is the full path of the text file containing the "message"?

**Search**: Identified a text file named `SOPHIE.txt` on the desktop via windows logs.

**Finding**: The file is located in the user Sophie's desktop directory.

**Log**:
- windows log and screenshot show `SOPHIE.txt` on the desktop.
![SOPHIE.txt on Desktop](1.png)
![SOPHIE.txt Content](3.png)

**Answer**: The full path is `C:\Users\Sophie\Desktop\SOPHIE.txt`.

**MITRE ATT&CK**: T1059.001 (Command and Scripting Interpreter: PowerShell)

### 2. Program Used to Create the Text File
**Question**: What program was used to create the text file?

**Search**: Analyzed Sysmon event logs for file creation events related to `SOPHIE.txt`.

**Finding**: Sysmon logs confirm `notepad.exe` created the file.

**Log**:
- Sysmon event log indicates `notepad.exe` was used.
![Sysmon Event for SOPHIE.txt](4.png)

**Answer**: The program used is `notepad.exe`.

**MITRE ATT&CK**: T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

### 3. Time of Execution of the Process That Created the Text File
**Question**: What is the time of execution of the process that created the text file? (Timezone UTC, Format YYYY-MM-DD hh:mm:ss)

**Search**: Checked Sysmon logs for the `notepad.exe` process creating `SOPHIE.txt`.

**Finding**: The execution time is recorded in the Sysmon log.

**Log**:
- Sysmon event log shows `notepad.exe` execution at 2024-01-08 14:25:30 UTC.
![Sysmon Time Log](5.png)

**Answer**: The execution time is `2024-01-08 14:25:30`.

**MITRE ATT&CK**: T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

### 4. Filename of the "Installer"
**Question**: What is the filename of this "installer"? (Including the file extension)

**Search**: Queried windows for download events and checked Microsoft Edge download history.

**Finding**: The malicious installer is identified as `antivirus.exe`.

**Log**:
- windows log and Edge download history confirm the file.
![Download Event](6.png)

**Answer**: The filename is `antivirus.exe`.

**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment)

### 5. Download Location of the Installer
**Question**: What is the download location of this installer?

**Search**: Analyzed windows logs and Edge download history for the source of `antivirus.exe`.

**Finding**: The installer was downloaded from `10.10.8.111`.

**Log**:
- windows log and screenshot show the download source.
![Download Source](7.png)

**Answer**: The download location is `10.10.8.111`.

**MITRE ATT&CK**: T1105 (Ingress Tool Transfer)

### 6. File Extension Added by the Installer
**Question**: The installer encrypts files and then adds a file extension to the end of the file name. What is this file extension?

**Search**: Filtered windows for Sysmon event ID 11 (file creation) related to `antivirus.exe`.

**Finding**: Files encrypted by `antivirus.exe` have the `.dmp` extension appended.

**Log**:
- windows log shows encrypted files with `.dmp` extension.
![File Extension Log](8.png)

**Answer**: The file extension is `.dmp`.

**MITRE ATT&CK**: T1486 (Data Encrypted for Impact)

### 7. IP Address Contacted by the Installer
**Question**: The installer reached out to an IP. What is this IP?

**Search**: Reused the download location log, as the installer contacted the same IP.

**Finding**: The installer communicated with `10.10.8.111`.

**Log**:
- windows log confirms the IP.
![Download Source](7.png)

**Answer**: The IP is `10.10.8.111`.

**MITRE ATT&CK**: T1071.001 (Application Layer Protocol: Web Protocols)

### 8. Source IP of RDP Login
**Question**: The threat actor logged in via RDP right after the “installer” was downloaded. What is the source IP?

**Search**: Filtered windows for `ms-wbt-server` (RDP protocol) around the time `antivirus.exe` was downloaded.

**Finding**: The RDP login originated from `10.11.27.46`.

**Log**:
- windows log shows RDP connection via `ms-wbt-server`.
![RDP Login Log](9.png)

**Answer**: The source IP is `10.11.27.46`.

**MITRE ATT&CK**: T1021.001 (Remote Services: RDP)

### 9. Time the Decryptor File Was Run
**Question**: This other person downloaded a file and ran it. When was this file run? (Timezone UTC, Format YYYY-MM-DD hh:mm:ss)

**Search**: Searched windows for process creation events involving `decryptor.exe`.

**Finding**: Sysmon logs show `decryptor.exe` executed at 2024-01-08 14:24:18 UTC.

**Log**:
- windows log confirms `decryptor.exe` execution time.
![Decryptor Execution](11.png)

**Answer**: The file was run at `2024-01-08 14:24:18`.

**MITRE ATT&CK**: T1059.001 (Command and Scripting Interpreter: PowerShell)

### 10. Sequential Order of Events
**Question**: Arrange the following events in sequential order from 1 to 7, based on the timeline in which they occurred.

**Events Provided**:
- Sophie downloaded the malware and ran it. (1)
- The downloaded malware encrypted the files on the computer and showed a ransomware note. (2)
- After seeing the ransomware note, Sophie ran out and reached out to you for help. (3)
- While Sophie was away, an intruder logged into Sophie’s machine via RDP and started looking around. (4)
- The intruder realized he infected a charity organization. He then downloaded a decryptor and decrypted all the files. (5)
- After all the files are restored, the intruder left the desktop telling Sophie to check her Bitcoin. (6)
- Sophie and I arrive on the scene to investigate. At this point, the intruder was gone. (7)

**Analysis**:
- **Event 1**: Sophie downloaded and ran `antivirus.exe` (T1566.001).
- **Event 2**: `antivirus.exe` encrypted files with `.dmp` extension and displayed a ransom note (T1486).
- **Event 3**: Sophie saw the ransom note and contacted help (no specific log, but follows encryption).
- **Event 4**: Intruder logged in via RDP from `10.11.27.46` (T1021.001).
- **Event 5**: Intruder ran `decryptor.exe` at 2024-01-08 14:24:18 to restore files (T1059.001).
- **Event 6**: Intruder created `SOPHIE.txt` at 2024-01-08 14:25:30 using `notepad.exe` (T1059.003).
- **Event 7**: Sophie and investigator arrived after the intruder left (post-14:25:30).



