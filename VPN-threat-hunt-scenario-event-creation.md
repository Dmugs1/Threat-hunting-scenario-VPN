# Threat Event (Unauthorized VPN Usage)
**Unauthorized VPN Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded the Proton VPN installer installer: https://protonvpn.com/download-windows
2. Install it silently: ```ProtonVPN_v3.5.1_x64.exe/S```
3. Opens the proton VPN 
4. Connects to VPN 
6. Creates a folder on your desktop called ```Innocent folder``` 
7. Created ```Innocentvideo1.mp4.txt``` inside ```Innocent folder```  
7. Deleted the VPN installer.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting VPN download and installation, as well as the Innocent folder and .mp4 files creation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of VPN as well as the VPN launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect VPN network activity, specifically protonvpn.exe making connections over ports (80,443).|

---

## Related Queries:
```kql
// Installer name == ProtonVPN_v3.5.1_x64
// Detect the installer was downloaded
// Detect when Installer was deleted
DeviceFileEvents
| where FileName contains "vpn" 
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessAccountName == "employee"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

// VPN being silently installed
DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where ProcessCommandLine contains "vpn" or ProcessCommandLine contains "proton"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

// VPN service was launched
DeviceProcessEvents
| where DeviceName == "dmug-threat-hun"
| where ProcessCommandLine contains "vpn" or ProcessCommandLine contains "proton"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

// VPN service is being used and is actively connecting
DeviceNetworkEvents
| where DeviceName == "dmug-threat-hun"
| where InitiatingProcessFileName == "protonvpn.exe"
| where RemoteUrl has_any ("vpn", "proton")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User Created ```Innocentvideo1.mp4.txt``` inside ```Innocent folder```  
DeviceFileEvents
| where DeviceName == "dmug-threat-hun"
| where ActionType == "FileCreated" or ActionType == "FileDeleted" 
| where InitiatingProcessAccountName == "employee"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName```
```
---

## Created By:
- **Author Name**: Daniel Muguercia
- **Author Contact**: https://www.linkedin.com/in/danielmug
- **Date**: February 04, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `February 04, 2025`  | `Daniel Muguercia`   
