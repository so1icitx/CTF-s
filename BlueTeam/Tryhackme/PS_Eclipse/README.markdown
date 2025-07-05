# PS Eclipse

## Scenario

Keegan’s machine is operational but exhibits files with strange extensions, raising concerns of a ransomware attempt. The task is to analyze Splunk logs for May 16, 2022, to determine the events, including the suspicious binary, download details, execution methods, and indicators of compromise (IOCs) like the ransomware note and wallpaper image.

## Investigation Questions and Findings

### 1. Name of the Suspicious Binary
**Question**: A suspicious binary was downloaded to the endpoint. What was the name of the binary?

**Search**: Queried `index=* EventCode=3` for Sysmon network connection events, identifying `OUTSTANDING_GUTTER.exe` in the `C:\Windows\Temp` directory, a common location for malicious files.

**Finding**: The binary is `OUTSTANDING_GUTTER.exe`.

![Binary Name](screenshots/1.png)

**Answer**: `OUTSTANDING_GUTTER.exe`

### 2. Address the Binary Was Downloaded From
**Question**: What is the address the binary was downloaded from? Add http:// to your answer & defang theავ

**Search**: Queried `index=* OUTSTANDING_GUTTER.exe` for network activity, finding an encoded PowerShell command. Decoded it with UTF-16LE to reveal the download URL.

**Finding**: The binary was downloaded from `hxxp[://]886e-181-215-214-32[.]ngrok[.]io`.

![Encoded Command](screenshots/2.png)
![Decoded Command](screenshots/3.png)
![URL Confirmation](screenshots/4.png)

**Answer**: `hxxp[://]886e-181-215-214-32[.]ngrok[.]io`

### 3. Windows Executable Used to Download the Binary
**Question**: What Windows executable was used to download the suspicious binary? Enter full path.

**Search**: Analyzed `index=* OUTSTANDING_GUTTER.exe` logs, identifying PowerShell as the tool used for the download.

**Finding**: The executable is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

![PowerShell Download](screenshots/5.png)

**Answer**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### 4. Command to Configure Elevated Privileges
**Question**: What command was executed to configure the suspicious binary to run with elevated privileges?

**Search**: Queried `index=* OUTSTANDING_GUTTER.exe sourcetype=WinEventLog:Security` for scheduled task creation events, finding a `schtasks.exe` command.

**Finding**: The command is `"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f`.

![Scheduled Task](screenshots/6.png)

**Answer**: `"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f`

### 5. Permissions and Command for Elevated Execution
**Question**: What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)

**Search**: Inspected the scheduled task logs from the previous query, noting the `/RU SYSTEM` parameter and the command to run the task.

**Finding**: The binary runs as `NT AUTHORITY\SYSTEM` with the command `"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe`.

![Task Permissions](screenshots/7.png)
![Task Execution](screenshots/8.png)

**Answer**: `NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe`

### 6. Address of Remote Server Connection
**Question**: The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.

**Search**: Queried `index=* EventCode=3 OUTSTANDING_GUTTER.exe` for outbound network connections, identifying the same URL as the download source.

**Finding**: The binary connected to `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`.

![Server Connection](screenshots/9.png)

**Answer**: `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`

### 7. Name of the Downloaded PowerShell Script
**Question**: A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?

**Search**: Queried `index=* sourcetype=WinEventLog:Security C:\Windows\Temp` for file creation events in the same directory as `OUTSTANDING_GUTTER.exe`.

**Finding**: The script is `script.ps1`.

![Script Name](screenshots/10.png)

**Answer**: `script.ps1`

### 8. Actual Name of the Malicious Script
**Question**: The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?

**Search**: Analyzed `index=* script.ps1` logs, identifying `BlackSun.ps1` as the true name based on its malicious behavior.

**Finding**: The actual name is `BlackSun.ps1`.

![Malicious Script](screenshots/11.png)
![Script Confirmation](screenshots/12.png)

**Answer**: `BlackSun.ps1`

### 9. Full Path of the Ransomware Note
**Question**: A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?

**Search**: Queried `index=* sourcetype=WinEventLog:Security BlackSun` for file creation events, finding the ransom note path.

**Finding**: The path is `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`.

![Ransom Note](screenshots/13.png)

**Answer**: `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

### 10. Full Path of the Wallpaper Image
**Question**: The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?

**Search**: Queried `index=* sourcetype=WinEventLog:Security BlackSun` for image file creation events, identifying `blacksun.jpg`.

**Finding**: The path is `C:\Users\Public\Pictures\blacksun.jpg`.

![Wallpaper Image](screenshots/14.png)
![Image Confirmation](screenshots/15.png)

**Answer**: `C:\Users\Public\Pictures\blacksun.jpg`

