# Volatility Forensics Challenge: Investigating Banking Trojan and Ransomware

## Scenario
Two cases require memory forensics using **Volatility 3** to analyze memory dumps from compromised systems.

## Challenge Questions and Findings

### Case 001: Banking Trojan
#### 1. Build Version of the Host Machine
**Question**: What is the build version of the host machine in Case 001?

**Answer**: `2600.xpsp.080413-2111`

![Build Version](screenshots/1.png)

#### 2. Memory File Acquisition Time
**Question**: At what time was the memory file acquired in Case 001?

**Answer**: `2012-07-22 02:45:08`

![Acquisition Time](screenshots/2.png)

#### 3. Suspicious Process
**Question**: What process can be considered suspicious in Case 001?

**Answer**: `reader_sl.exe`

![Suspicious Process](screenshots/3.png)

#### 4. Parent Process of Suspicious Process
**Question**: What is the parent process of the suspicious process in Case 001?

**Answer**: `explorer.exe`

![Parent Process](screenshots/4.png)

#### 5. PID of Suspicious Process
**Question**: What is the PID of the suspicious process in Case 001?

**Answer**: `1640`

![Suspicious PID](screenshots/5.png)

#### 6. Parent Process PID
**Question**: What is the parent process PID in Case 001?

**Answer**: `1484`

![Parent PID](screenshots/6.png)

#### 7. User-Agent Employed by Adversary
**Question**: What user-agent was employed by the adversary in Case 001?

**Answer**: `Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)`

![User-Agent](screenshots/7.png)

#### 8. Chase Bank as Suspicious Domain
**Question**: Was Chase Bank one of the suspicious bank domains found in Case 001? (Y/N)

**Answer**: `Y`

![Chase Bank Domain](screenshots/8.png)

### Case 002: Ransomware
#### 9. Suspicious Process at PID 740
**Question**: What suspicious process is running at PID 740 in Case 002?

**Answer**: `@WanaDecryptor@`

![Suspicious Process](screenshots/9.png)

#### 10. Full Path of Suspicious Binary
**Question**: What is the full path of the suspicious binary in PID 740 in Case 002?

**Answer**: `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe`

![Binary Path](screenshots/10.png)

#### 11. Parent Process of PID 740
**Question**: What is the parent process of PID 740 in Case 002?

**Answer**: `tasksche.exe`

![Parent Process](screenshots/11.png)

#### 12. Suspicious Parent Process PID
**Question**: What is the suspicious parent process PID connected to the decryptor in Case 002?

**Answer**: `1940`

![Parent PID](screenshots/12.png)

#### 13. Malware Present
**Question**: From our current information, what malware is present on the system in Case 002?

**Answer**: `WannaCry`

![Malware Identification](screenshots/no_picture)

#### 14. DLL for Socket Creation
**Question**: What DLL is loaded by the decryptor used for socket creation in Case 002?

**Answer**: `Ws2_32.dll`

![Socket DLL](screenshots/13.png)

#### 15. Mutex Indicator of Malware
**Question**: What mutex can be found that is a known indicator of the malware in question in Case 002?

**Answer**: `MsWinZonesCacheCounterMutexA`

![Mutex Indicator](screenshots/14.png)

#### 16. Plugin for File Identification
**Question**: What plugin could be used to identify all files loaded from the malware working directory in Case 002?

**Answer**: `windows.filescan`

![File Scan Plugin](screenshots/15.png)
