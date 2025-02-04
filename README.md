<img width="400" src="https://github.com/user-attachments/assets/1e08f1c5-a880-42df-80a6-658e29845684" alt="ProtonVPN logo"/>



# Threat Hunt Report: Unauthorized VPN Usage
- [Scenario Creation](https://github.com/Dmugs1/Threat-hunting-scenario-VPN/blob/main/VPN-threat-hunt-scenario-event-creation.md)
  
## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- ProtonVPN

##  Scenario

Management suspects that an employee is using unauthorized VPN services to bypass network security controls and access restricted content. Recent logs show unusual network activity and connections to known VPN servers. The goal is to detect any unauthorized use of VPN services and analyze related security incidents to mitigate potential risks. If any unauthorized use of VPN services is found, notify management.

### High-Level VPN-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `vpn(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known VPN servers and ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any files related to VPN activity (e.g., VPN client installers). Discovered that the user "employee" downloaded a VPN client installer at: 2025-02-04T08:46:48.910731Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "vpn"
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessAccountName == "employee"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5c6e83d9-339b-497f-a7f7-54ecbce9812a">



---

### 2. Searched the `DeviceProcessEvents` Table

Based on the information gathered from the DeviceFileEvents table, searched the DeviceProcessEvents table for any ProcessCommandLine that contained the names “vpn” or “proton”. Based on the logs returned on 2025-02-04T08:49:52.9576914Z, an employee started a process on the device named "dmug-threat-hun." The process involved the execution of the file "ProtonVPN_v3.5.1_x64.exe" with the ProcessCommandLine indicating a silent installation “ProtonVPN_v3.5.1_x64  /S”

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where ProcessCommandLine contains "vpn" or ProcessCommandLine contains "proton"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ae841d6e-ba01-4670-b072-042406c11067">




---

### 3. Searched the `DeviceProcessEvents` Table for ProtonVPN Execution

Searched the DeviceProcessEvents table for indications that user "employee" actually opened the Installed VPN. There was evidence that they did open it at 2025-02-04T08:51:08.3814379. 
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where ProcessCommandLine contains "vpn" or ProcessCommandLine contains "proton"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d28a5b59-a4f4-41f2-b5db-5d4e95189ad3">

---

### 4. Searched the DeviceNetworkEvents Table for ProtonVPN Server Connections

Searched the DeviceNetworkEvents table for any indication of network connections to VPN servers. On 2025-01-28T08:38:29.400644Z, a successful connection was made from the device named "dmug-threat-hun" by the user account "employee." The process involved the execution of the file "openvpn.exe" with connections to known VPN servers.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessFileName == "protonvpn.exe"
| where RemoteUrl has_any ("vpn", "proton")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8bc57f64-9856-4cf1-a3e2-1a69be9a1a01">

---



### 5.  User Created ```Innocentvideo1.mp4.txt``` inside ```Innocent folder```  and finally deleted installer for protonvpn at 2025-02-04T09:02:57.3403446Z 
```kql
DeviceFileEvents
| where DeviceName == "dmug-threat-hun"
| where ActionType == "FileCreated" or ActionType == "FileDeleted" 
| where InitiatingProcessAccountName == "employee"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName```
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/11b4773f-6a86-4dac-90a0-ac14d172129f3">

---

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4d242c08-8072-4d7c-8f88-eb44db9c7f39">






---

## Chronological Event Timeline 



### VPN Installation Detected – 2025-02-04T08:46:48Z
Action: User downloaded a VPN client installer (ProtonVPN_v3.5.1_x64.exe).
Detection Method: Querying DeviceFileEvents for VPN-related file names.
Device: dmug-threat-hun
User Account: employee
Evidence: VPN installer file found in logs.


### Silent VPN Installation Executed – 2025-02-04T08:49:52Z
Action: Employee executed the installer in silent mode (/S flag).
Detection Method: Querying DeviceProcessEvents for process execution containing "vpn" or "proton".
Device: dmug-threat-hun
User Account: employee
Evidence: Process log confirmed execution of ProtonVPN_v3.5.1_x64.exe with silent installation parameters.
### VPN Application Launched – 2025-02-04T08:51:08Z
Action: Employee opened the installed VPN application.
Detection Method: DeviceProcessEvents analysis for "vpn" or "proton" execution.
Device: dmug-threat-hun
User Account: employee
Evidence: Process logs confirmed the launch of ProtonVPN.


### VPN Connection Established – 2025-02-04T08:38:29Z
Action: Employee successfully connected to a ProtonVPN server using openvpn.exe.
Detection Method: Querying DeviceNetworkEvents for remote connections to known VPN servers.
Device: dmug-threat-hun
User Account: employee
Evidence: Logs showed network traffic directed to a ProtonVPN server.


### - Deletion of installer -  2025-02-04T09:02:57Z
Action: Employee created a misleading file (Innocentvideo1.mp4.txt) inside a folder named "Innocent folder", then deleted the ProtonVPN installer.
Detection Method: Querying DeviceFileEvents for file creation and deletion activities.
Device: dmug-threat-hun
User Account: employee
Evidence: Logs showed file creation of a decoy text file, followed by the deletion of ProtonVPN_v3.5.1_x64.exe.
Possible Intent: Attempting to cover tracks and mislead forensic analysis.


---


## Investigation Summary

An employee was suspected of using unauthorized VPN services to bypass security controls. The investigation utilized Microsoft Defender for Endpoint, Kusto Query Language (KQL), and log analysis to confirm unauthorized VPN installation, execution, and network activity.

These actions suggest potential misuse of the system warranting further response.


---

## Response Taken

VPN usage was confirmed on the endpoint `dmug-threat-hun` by the user `employee` as well as suspicious files creation shortly after. The device was isolated, and the user's direct manager was notified.

---


