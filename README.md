<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ilevillani/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that included the string “tor” and discovered what looks like the user “ile_vm” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-06-02T19:49:32.884203Z. These events began at: 2025-06-02T19:37:39.6713949Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ile-vm-threathu"
| where InitiatingProcessAccountName == "ile_vm"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-02T19:37:39.6713949Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/9a776693-f529-40fa-b810-cd0166e43816">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.3.exe”. Based on the logs returned, at 2025-06-02T19:39:57.6058331Z, an employee on the “ile-vm-threathu” device (logged in as the user “ile_vm”) ran the file named tor-browser-windows-x86_64-portable-14.5.3.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ile-vm-threathu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1e76a23e-bf0a-4afe-9575-55ef3201d217">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user “ile_vm” actually opened the tor browser. There was evidence that they did open it at 2025-06-02T19:40:48.0832459Z.
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ile-vm-threathu"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ab0445fc-de74-4b9b-a7de-719460a3a90d">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the tor browser was used to establish a connection using any of the known tor ports.
At 2025-06-02T19:41:05.6328746Z, the user “ile_vm” on the machine named “ile-vm-threathu” launched the Tor executable (tor.exe) from:
c:\users\ile_vm\desktop\tor browser\browser\torbrowser\tor\tor.exe
Immediately afterward, that process established a successful connection to the remote server at IP 176.9.39.196 on port 9001, reaching out to https://www.fs5ld3x5rz4.com.
There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ile-vm-threathu"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/7a569292-76ef-4c39-9e9f-d3545fe71a0b">

---

## Chronological Event Timeline (All timestamps in UTC)

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-02T19:37:39.6713949Z`
- **Event:** The user "ile_vm" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ile_vm\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-02T19:39:57.6058331Z`
- **Event:** The user "ile_vm" executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\ile_vm\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-02T19:40:52.1230000Z`
- **Event:** User "ile_vm" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-02T19:41:05.6328746Z`
- **Event:** A network connection to IP `92.60.37.143:9001` on port `9001` by user "ile_vm" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-02T19:41:11.4470000Z` - Connected to `85.208.144.164` on port `443`.
  - `2025-06-02T19:42:12.1540000Z` - Connected to `217.79.252.202` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ile_vm" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-02T19:49:32.8842030Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ile_vm\Desktop\tor-shopping-list.txt`

# File Download - TOR Installer

| Timestamp                      | Action      | Event                              | Command | Filepath                                                                 | AdditionalInfo |
|--------------------------------|-------------|------------------------------------|---------|--------------------------------------------------------------------------|----------------|
| 2025-06-02T19:37:39.6713949Z   | FileRenamed | Tor installer moved to Downloads   |         | `C:\Users\ile_vm\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe` |                |

# Process Execution - TOR Browser Installation

| Timestamp                      | Action         | Event                          | Command                                                                         | Filepath                                                                 | AdditionalInfo |
|--------------------------------|----------------|--------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------------------------|----------------|
| 2025-06-02T19:39:57.6058331Z   | ProcessCreated | Silent install of Tor Browser  | `"C:\Users\ile_vm\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe /S"` | `C:\Users\ile_vm\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe` |                |

# Process Execution - TOR Browser Launch

| Timestamp                      | Action         | Event                                    | Command                                                         | Filepath                                                                                         | AdditionalInfo |
|--------------------------------|----------------|------------------------------------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------|----------------|
| 2025-06-02T19:40:48.0832459Z   | ProcessCreated | Launched Tor Browser                     | `"C:\Users\ile_vm\Desktop\Tor Browser\Browser\firefox.exe"`     | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\firefox.exe`                                         |                |
| 2025-06-02T19:40:51.9230000Z   | ProcessCreated | Spawned Tor Browser subprocesses (tabs, GPU, utility) |                                                                 | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\firefox.exe`                                         |                |
| 2025-06-02T19:40:52.1230000Z   | ProcessCreated | Started Tor daemon                       | `"C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe --defaults-torrc ..."` | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                         |                |

# Network Connection - TOR Network

| Timestamp                      | Action            | Event                  | Command | Filepath                                                                                                 | AdditionalInfo                                            |
|--------------------------------|-------------------|------------------------|---------|----------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| 2025-06-02T19:41:05.6328746Z   | ConnectionSuccess | Tor relay connection   |         | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                                | RemoteIP = 92.60.37.143:9001                              |
| 2025-06-02T19:42:13.8842030Z   | ConnectionSuccess | Tor relay connection   |         | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                                | RemoteIP = 176.9.39.196:9001; RemoteURL = `https://www.fs5ld3x5rz4.com` |

# Additional Network Connections - TOR Browser Activity

| Timestamp                      | Action            | Event                  | Command | Filepath                                                                                                 | AdditionalInfo                                                    |
|--------------------------------|-------------------|------------------------|---------|----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| 2025-06-02T19:41:11.4470000Z   | ConnectionSuccess | Tor relay connection   |         | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                                | RemoteIP = 85.208.144.164:443                                     |
| 2025-06-02T19:42:08.3020000Z   | ConnectionSuccess | Tor relay connection   |         | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                                | RemoteIP = 217.79.252.202:443                                     |
| 2025-06-02T19:42:12.1540000Z   | ConnectionSuccess | Tor relay connection   |         | `C:\Users\ile_vm\Desktop\Tor Browser\Browser\Tor\tor.exe`                                                | RemoteIP = 217.79.252.202:443; RemoteURL = `https://www.a2fftavtckqhyk2czvpl.com`   |

# File Creation - TOR Shopping List

| Timestamp                      | Action       | Event                         | Command | Filepath                                            | AdditionalInfo |
|--------------------------------|--------------|-------------------------------|---------|-----------------------------------------------------|----------------|
| 2025-06-02T19:49:32.8842030Z   | FileCreated  | Created `tor-shopping-list.txt` |         | `C:\Users\ile_vm\Desktop\tor-shopping-list.txt`     |                |
| 2025-06-02T19:49:32.9900000Z   | FileRenamed  | Renamed/Updated `tor-shopping-list.txt` |         | `C:\Users\ile_vm\Desktop\tor-shopping-list.txt`     |                |
| 2025-06-02T19:50:04.3020000Z   | FileModified | Edited `tor-shopping-list.txt`  |         | `C:\Users\ile_vm\Desktop\tor-shopping-list.txt`     |                |


---

## Summary

The user “ile_vm” downloaded and silently installed the Tor Browser on the virtual machine named “ile-vm-threathu.” They then launched Tor Browser, which initialized its internal processes and successfully connected to several Tor relays to establish a secure circuit. Over the next few minutes, multiple browser tabs opened, indicating active browsing through the Tor network. Finally, the user created and edited a text file on their Desktop named “tor-shopping-list.txt,” likely documenting links or notes related to their Tor activity.

---

## Response Taken

TOR usage was confirmed on the endpoint ile-vm-threathu by the user ile_vm. The device was isolated and the user's direct manager was notified.

---
