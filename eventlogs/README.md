**Important links with nice information:**
IMP:
https://www.xplg.com/windows-server-security-events-list/

https://www.ijert.org/utilizing-event-logs-of-windows-operating-system-in-digital-crime-investigations (shallo copy, restore ids)


https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j (important has sytem info too)

------------
**Micrsoft documentation on all event ids:**
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor


------------

**Default path of logs in windows:** `"C:\Windows\System32\winevt\Logs"`


**Event logs pdf:** https://drive.google.com/file/d/19YGCprq1Ki1T2B2_9wjufEQxnvqwipgW/view?usp=sharing


Folder view,

![Screenshot (580)](https://user-images.githubusercontent.com/43678329/190682149-e4145bbd-91cc-4a08-b271-4cf790e3b9fd.png)

-----------
**Resources:**


https://flylib.com/books/en/3.210.1.51/1/

https://www.ijert.org/utilizing-event-logs-of-windows-operating-system-in-digital-crime-investigations

https://medium.com/@lucideus/introduction-to-event-log-analysis-part-1-windows-forensics-manual-2018-b936a1a35d8a

https://andreafortuna.org/2017/10/20/windows-event-logs-in-forensic-analysis/

https://www.ijert.org/utilizing-event-logs-of-windows-operating-system-in-digital-crime-investigations

https://www.socinvestigation.com/windows-rdp-event-ids-cheatsheet/


https://adamtheautomator.com/windows-security-events/

https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor

https://www.xplg.com/windows-server-security-events-list/

https://resources.infosecinstitute.com/topic/6-windows-event-log-ids-to-monitor-now/

https://stackoverflow.com/questions/73050212/create-a-windows-event-listener-with-win32evtlog

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4610

https://nxlog.co/top-5-windows-security-logs-everyone-should-collect


https://www.beyondtrust.com/blog/entry/windows-server-events-monitor



-----------------

```
Application.evtx
DebugChannel.etl
HP Analytics.evtx
HardwareEvents.evtx
Internet Explorer.evtx
Key Management Service.evtx
Microsoft-Client-Licensing-Platform/Admin.evtx
Microsoft-Windows-AAD/Operational.evtx
Microsoft-Windows-All-User-Install-Agent/Admin.evtx
Microsoft-Windows-AllJoyn/Operational.evtx
Microsoft-Windows-AppHost/Admin.evtx
Microsoft-Windows-AppID/Operational.evtx
Microsoft-Windows-AppLocker/EXE and DLL.evtx
Microsoft-Windows-AppLocker/MSI and Script.evtx
Microsoft-Windows-AppLocker/Packaged app-Deployment.evtx
Microsoft-Windows-AppLocker/Packaged app-Execution.evtx
Microsoft-Windows-AppModel-Runtime/Admin.evtx
Microsoft-Windows-AppReadiness/Admin.evtx
Microsoft-Windows-AppReadiness/Operational.evtx
Microsoft-Windows-AppXDeployment/Operational.evtx
Microsoft-Windows-AppXDeploymentServer/Operational.evtx
Microsoft-Windows-AppXDeploymentServer/Restricted.evtx
Microsoft-Windows-ApplicabilityEngine/Operational.evtx
Microsoft-Windows-Application Server-Applications/Admin.evtx
Microsoft-Windows-Application Server-Applications/Operational.evtx
Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant.evtx
Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter.evtx
Microsoft-Windows-Application-Experience/Program-Inventory.evtx
Microsoft-Windows-Application-Experience/Program-Telemetry.evtx
Microsoft-Windows-Application-Experience/Steps-Recorder.evtx
Microsoft-Windows-AppxPackaging/Operational.evtx
Microsoft-Windows-Audio/CaptureMonitor.evtx
Microsoft-Windows-Audio/Operational.evtx
Microsoft-Windows-Audio/PlaybackManager.evtx
Microsoft-Windows-Authentication User Interface/Operational.evtx
Microsoft-Windows-BackgroundTaskInfrastructure/Operational.evtx
Microsoft-Windows-Backup.evtx
Microsoft-Windows-Biometrics/Operational.evtx
Microsoft-Windows-BitLocker/BitLocker Management.evtx
Microsoft-Windows-Bits-Client/Operational.evtx
Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational.evtx
Microsoft-Windows-Bluetooth-MTPEnum/Operational.evtx
Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational.evtx
Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational.evtx
Microsoft-Windows-Cleanmgr/Diagnostic.evtx
Microsoft-Windows-CloudStore/Operational.evtx
Microsoft-Windows-CodeIntegrity/Operational.evtx
Microsoft-Windows-Compat-Appraiser/Operational.evtx
Microsoft-Windows-Containers-BindFlt/Operational.evtx
Microsoft-Windows-Containers-Wcifs/Operational.evtx
Microsoft-Windows-Containers-Wcnfs/Operational.evtx
Microsoft-Windows-CoreApplication/Operational.evtx
Microsoft-Windows-CoreSystem-SmsRouter-Events/Operational.evtx
Microsoft-Windows-CorruptedFileRecovery-Client/Operational.evtx
Microsoft-Windows-CorruptedFileRecovery-Server/Operational.evtx
Microsoft-Windows-Crypto-DPAPI/BackUpKeySvc.evtx
Microsoft-Windows-Crypto-DPAPI/Operational.evtx
Microsoft-Windows-Crypto-NCrypt/Operational.evtx
Microsoft-Windows-DAL-Provider/Operational.evtx
Microsoft-Windows-DSC/Admin.evtx
Microsoft-Windows-DSC/Operational.evtx
Microsoft-Windows-DataIntegrityScan/Admin.evtx
Microsoft-Windows-DataIntegrityScan/CrashRecovery.evtx
Microsoft-Windows-DateTimeControlPanel/Operational.evtx
Microsoft-Windows-DeviceGuard/Operational.evtx
Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin.evtx
Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational.evtx
Microsoft-Windows-DeviceSetupManager/Admin.evtx
Microsoft-Windows-DeviceSetupManager/Operational.evtx
Microsoft-Windows-DeviceSync/Operational.evtx
Microsoft-Windows-DeviceUpdateAgent/Operational.evtx
Microsoft-Windows-Devices-Background/Operational.evtx
Microsoft-Windows-Dhcp-Client/Admin.evtx
Microsoft-Windows-Dhcpv6-Client/Admin.evtx
Microsoft-Windows-Diagnosis-DPS/Operational.evtx
Microsoft-Windows-Diagnosis-PCW/Operational.evtx
Microsoft-Windows-Diagnosis-PLA/Operational.evtx
Microsoft-Windows-Diagnosis-Scheduled/Operational.evtx
Microsoft-Windows-Diagnosis-Scripted/Admin.evtx
Microsoft-Windows-Diagnosis-Scripted/Operational.evtx
Microsoft-Windows-Diagnosis-ScriptedDiagnosticsProvider/Operational.evtx
Microsoft-Windows-Diagnostics-Networking/Operational.evtx
Microsoft-Windows-Diagnostics-Performance/Operational.evtx
Microsoft-Windows-DiskDiagnostic/Operational.evtx
Microsoft-Windows-DiskDiagnosticDataCollector/Operational.evtx
Microsoft-Windows-DiskDiagnosticResolver/Operational.evtx
Microsoft-Windows-DxgKrnl-Admin.evtx
Microsoft-Windows-DxgKrnl-Operational.evtx
Microsoft-Windows-EDP-Application-Learning/Admin.evtx
Microsoft-Windows-EDP-Audit-Regular/Admin.evtx
Microsoft-Windows-EDP-Audit-TCB/Admin.evtx
Microsoft-Windows-EapHost/Operational.evtx
Microsoft-Windows-EapMethods-RasChap/Operational.evtx
Microsoft-Windows-EapMethods-RasTls/Operational.evtx
Microsoft-Windows-EapMethods-Sim/Operational.evtx
Microsoft-Windows-EapMethods-Ttls/Operational.evtx
Microsoft-Windows-EventCollector/Operational.evtx
Microsoft-Windows-FMS/Operational.evtx
Microsoft-Windows-Fault-Tolerant-Heap/Operational.evtx
Microsoft-Windows-FeatureConfiguration/Operational.evtx
Microsoft-Windows-FileHistory-Core/WHC.evtx
Microsoft-Windows-FileHistory-Engine/BackupLog.evtx
Microsoft-Windows-Folder Redirection/Operational.evtx
Microsoft-Windows-Forwarding/Operational.evtx
Microsoft-Windows-GenericRoaming/Admin.evtx
Microsoft-Windows-GroupPolicy/Operational.evtx
Microsoft-Windows-HelloForBusiness/Operational.evtx
Microsoft-Windows-Help/Operational.evtx
Microsoft-Windows-HomeGroup Control Panel/Operational.evtx
Microsoft-Windows-HomeGroup Listener Service/Operational.evtx
Microsoft-Windows-HomeGroup Provider Service/Operational.evtx
Microsoft-Windows-HotspotAuth/Operational.evtx
Microsoft-Windows-Hyper-V-Guest-Drivers/Admin.evtx
Microsoft-Windows-Hyper-V-Hypervisor-Admin.evtx
Microsoft-Windows-Hyper-V-Hypervisor-Operational.evtx
Microsoft-Windows-Hyper-V-VID-Admin.evtx
Microsoft-Windows-IKE/Operational.evtx
Microsoft-Windows-IPxlatCfg/Operational.evtx
Microsoft-Windows-IdCtrls/Operational.evtx
Microsoft-Windows-International-RegionalOptionsControlPanel/Operational.evtx
Microsoft-Windows-Iphlpsvc/Operational.evtx
Microsoft-Windows-KdsSvc/Operational.evtx
Microsoft-Windows-Kernel-ApphelpCache/Operational.evtx
Microsoft-Windows-Kernel-Boot/Operational.evtx
Microsoft-Windows-Kernel-EventTracing/Admin.evtx
Microsoft-Windows-Kernel-IO/Operational.evtx
Microsoft-Windows-Kernel-LiveDump/Operational.evtx
Microsoft-Windows-Kernel-PnP/Configuration.evtx
Microsoft-Windows-Kernel-PnP/Driver Watchdog.evtx
Microsoft-Windows-Kernel-Power/Thermal-Operational.evtx
Microsoft-Windows-Kernel-ShimEngine/Operational.evtx
Microsoft-Windows-Kernel-StoreMgr/Operational.evtx
Microsoft-Windows-Kernel-WDI/Operational.evtx
Microsoft-Windows-Kernel-WHEA/Errors.evtx
Microsoft-Windows-Kernel-WHEA/Operational.evtx
Microsoft-Windows-Known Folders API Service.evtx
Microsoft-Windows-LanguagePackSetup/Operational.evtx
Microsoft-Windows-LiveId/Operational.evtx
Microsoft-Windows-MUI/Admin.evtx
Microsoft-Windows-MUI/Operational.evtx
Microsoft-Windows-MemoryDiagnostics-Results/Debug.evtx
Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Operational.evtx
Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Admin.evtx
Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot.evtx
Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Diagnostics.evtx
Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService.evtx
Microsoft-Windows-Mprddm/Operational.evtx
Microsoft-Windows-NCSI/Operational.evtx
Microsoft-Windows-NTLM/Operational.evtx
Microsoft-Windows-NcdAutoSetup/Operational.evtx
Microsoft-Windows-NdisImPlatform/Operational.evtx
Microsoft-Windows-NetworkLocationWizard/Operational.evtx
Microsoft-Windows-NetworkProfile/Operational.evtx
Microsoft-Windows-NetworkProvider/Operational.evtx
Microsoft-Windows-NetworkProvisioning/Operational.evtx
Microsoft-Windows-NlaSvc/Operational.evtx
Microsoft-Windows-Ntfs/Operational.evtx
Microsoft-Windows-Ntfs/WHC.evtx
Microsoft-Windows-OOBE-Machine-DUI/Operational.evtx
Microsoft-Windows-OneBackup/Debug.evtx
Microsoft-Windows-PackageStateRoaming/Operational.evtx
Microsoft-Windows-ParentalControls/Operational.evtx
Microsoft-Windows-Partition/Diagnostic.evtx
Microsoft-Windows-PerceptionRuntime/Operational.evtx
Microsoft-Windows-PerceptionSensorDataService/Operational.evtx
Microsoft-Windows-PersistentMemory-Nvdimm/Operational.evtx
Microsoft-Windows-PersistentMemory-PmemDisk/Operational.evtx
Microsoft-Windows-PersistentMemory-ScmBus/Certification.evtx
Microsoft-Windows-PersistentMemory-ScmBus/Operational.evtx
Microsoft-Windows-Policy/Operational.evtx
Microsoft-Windows-PowerShell/Admin.evtx
Microsoft-Windows-PowerShell/Operational.evtx
Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational.evtx
Microsoft-Windows-PrintService/Admin.evtx
Microsoft-Windows-Privacy-Auditing/Operational.evtx
Microsoft-Windows-Program-Compatibility-Assistant/CompatAfterUpgrade.evtx
Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin.evtx
Microsoft-Windows-Provisioning-Diagnostics-Provider/AutoPilot.evtx
Microsoft-Windows-Provisioning-Diagnostics-Provider/ManagementService.evtx
Microsoft-Windows-PushNotification-Platform/Admin.evtx
Microsoft-Windows-PushNotification-Platform/Operational.evtx
Microsoft-Windows-ReFS/Operational.evtx
Microsoft-Windows-ReadyBoost/Operational.evtx
Microsoft-Windows-ReadyBoostDriver/Operational.evtx
Microsoft-Windows-Regsvr32/Operational.evtx
Microsoft-Windows-RemoteApp and Desktop Connections/Admin.evtx
Microsoft-Windows-RemoteApp and Desktop Connections/Operational.evtx
Microsoft-Windows-RemoteAssistance/Admin.evtx
Microsoft-Windows-RemoteAssistance/Operational.evtx
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin.evtx
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational.evtx
Microsoft-Windows-RemoteDesktopServices-RemoteFX-Synth3dvsc/Admin.evtx
Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational.evtx
Microsoft-Windows-Resource-Exhaustion-Detector/Operational.evtx
Microsoft-Windows-Resource-Exhaustion-Resolver/Operational.evtx
Microsoft-Windows-RestartManager/Operational.evtx
Microsoft-Windows-RetailDemo/Admin.evtx
Microsoft-Windows-RetailDemo/Operational.evtx
Microsoft-Windows-SMBClient/Operational.evtx
Microsoft-Windows-SMBServer/Audit.evtx
Microsoft-Windows-SMBServer/Connectivity.evtx
Microsoft-Windows-SMBServer/Operational.evtx
Microsoft-Windows-SMBServer/Security.evtx
Microsoft-Windows-SMBWitnessClient/Admin.evtx
Microsoft-Windows-SMBWitnessClient/Informational.evtx
Microsoft-Windows-SearchUI/Operational.evtx
Microsoft-Windows-Security-Adminless/Operational.evtx
Microsoft-Windows-Security-Audit-Configuration-Client/Operational.evtx
Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational.evtx
Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational.evtx
Microsoft-Windows-Security-Mitigations/KernelMode.evtx
Microsoft-Windows-Security-Mitigations/UserMode.evtx
Microsoft-Windows-Security-Netlogon/Operational.evtx
Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational.evtx
Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter.evtx
Microsoft-Windows-Security-UserConsentVerifier/Audit.evtx
Microsoft-Windows-SecurityMitigationsBroker/Operational.evtx
Microsoft-Windows-SettingSync/Debug.evtx
Microsoft-Windows-SettingSync/Operational.evtx
Microsoft-Windows-SettingSync-Azure/Debug.evtx
Microsoft-Windows-SettingSync-Azure/Operational.evtx
Microsoft-Windows-SettingSync-OneDrive/Debug.evtx
Microsoft-Windows-SettingSync-OneDrive/Operational.evtx
Microsoft-Windows-Shell-ConnectedAccountState/ActionCenter.evtx
Microsoft-Windows-Shell-Core/ActionCenter.evtx
Microsoft-Windows-Shell-Core/AppDefaults.evtx
Microsoft-Windows-Shell-Core/LogonTasksChannel.evtx
Microsoft-Windows-Shell-Core/Operational.evtx
Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational.evtx
Microsoft-Windows-SmartCard-Audit/Authentication.evtx
Microsoft-Windows-SmartCard-DeviceEnum/Operational.evtx
Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin.evtx
Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational.evtx
Microsoft-Windows-SmbClient/Audit.evtx
Microsoft-Windows-SmbClient/Connectivity.evtx
Microsoft-Windows-SmbClient/Security.evtx
Microsoft-Windows-StateRepository/Operational.evtx
Microsoft-Windows-StateRepository/Restricted.evtx
Microsoft-Windows-Storage-ClassPnP/Operational.evtx
Microsoft-Windows-Storage-Storport/Health.evtx
Microsoft-Windows-Storage-Storport/Operational.evtx
Microsoft-Windows-Storage-Tiering/Admin.evtx
Microsoft-Windows-StorageManagement/Operational.evtx
Microsoft-Windows-StorageSettings/Diagnostic.evtx
Microsoft-Windows-StorageSpaces-Driver/Diagnostic.evtx
Microsoft-Windows-StorageSpaces-Driver/Operational.evtx
Microsoft-Windows-StorageSpaces-ManagementAgent/WHC.evtx
Microsoft-Windows-StorageSpaces-SpaceManager/Diagnostic.evtx
Microsoft-Windows-StorageSpaces-SpaceManager/Operational.evtx
Microsoft-Windows-Store/Operational.evtx
Microsoft-Windows-Storsvc/Diagnostic.evtx
Microsoft-Windows-SystemSettingsThreshold/Operational.evtx
Microsoft-Windows-TCPIP/Operational.evtx
Microsoft-Windows-TWinUI/Operational.evtx
Microsoft-Windows-TZSync/Operational.evtx
Microsoft-Windows-TZUtil/Operational.evtx
Microsoft-Windows-TaskScheduler/Maintenance.evtx
Microsoft-Windows-TerminalServices-ClientUSBDevices/Admin.evtx
Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational.evtx
Microsoft-Windows-TerminalServices-LocalSessionManager/Admin.evtx
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx
Microsoft-Windows-TerminalServices-PnPDevices/Admin.evtx
Microsoft-Windows-TerminalServices-PnPDevices/Operational.evtx
Microsoft-Windows-TerminalServices-Printers/Admin.evtx
Microsoft-Windows-TerminalServices-Printers/Operational.evtx
Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx
Microsoft-Windows-Time-Service/Operational.evtx
Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational.evtx
Microsoft-Windows-Troubleshooting-Recommended/Admin.evtx
Microsoft-Windows-Troubleshooting-Recommended/Operational.evtx
Microsoft-Windows-UAC/Operational.evtx
Microsoft-Windows-UAC-FileVirtualization/Operational.evtx
Microsoft-Windows-UniversalTelemetryClient/Operational.evtx
Microsoft-Windows-User Control Panel/Operational.evtx
Microsoft-Windows-User Device Registration/Admin.evtx
Microsoft-Windows-User Profile Service/Operational.evtx
Microsoft-Windows-User-Loader/Operational.evtx
Microsoft-Windows-UserPnp/ActionCenter.evtx
Microsoft-Windows-UserPnp/DeviceInstall.evtx
Microsoft-Windows-VDRVROOT/Operational.evtx
Microsoft-Windows-VHDMP-Operational.evtx
Microsoft-Windows-VPN/Operational.evtx
Microsoft-Windows-VPN-Client/Operational.evtx
Microsoft-Windows-VerifyHardwareSecurity/Admin.evtx
Microsoft-Windows-Volume/Diagnostic.evtx
Microsoft-Windows-VolumeSnapshot-Driver/Operational.evtx
Microsoft-Windows-WER-PayloadHealth/Operational.evtx
Microsoft-Windows-WFP/Operational.evtx
Microsoft-Windows-WLAN-AutoConfig/Operational.evtx
Microsoft-Windows-WMI-Activity/Operational.evtx
Microsoft-Windows-WMPNSS-Service/Operational.evtx
Microsoft-Windows-WPD-ClassInstaller/Operational.evtx
Microsoft-Windows-WPD-CompositeClassDriver/Operational.evtx
Microsoft-Windows-WPD-MTPClassDriver/Operational.evtx
Microsoft-Windows-WWAN-SVC-Events/Operational.evtx
Microsoft-Windows-Wcmsvc/Operational.evtx
Microsoft-Windows-WebAuthN/Operational.evtx
Microsoft-Windows-Win32k/Operational.evtx
Microsoft-Windows-WinINet-Config/ProxyConfigChanged.evtx
Microsoft-Windows-WinRM/Operational.evtx
Microsoft-Windows-Windows Defender/Operational.evtx
Microsoft-Windows-Windows Defender/WHC.evtx
Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity.evtx
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall.evtx
Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics.evtx
Microsoft-Windows-WindowsBackup/ActionCenter.evtx
Microsoft-Windows-WindowsSystemAssessmentTool/Operational.evtx
Microsoft-Windows-WindowsUpdateClient/Operational.evtx
Microsoft-Windows-Winlogon/Operational.evtx
Microsoft-Windows-Winsock-WS2HELP/Operational.evtx
Microsoft-Windows-Wired-AutoConfig/Operational.evtx
Microsoft-Windows-WorkFolders/Operational.evtx
Microsoft-Windows-WorkFolders/WHC.evtx
Microsoft-Windows-Workplace Join/Admin.evtx
Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel.evtx
OAlerts.evtx
OpenSSH/Admin.evtx
OpenSSH/Operational.evtx
Parameters.evtx
SMSApi.evtx
Security.evtx
Setup.evtx
System.evtx
Windows PowerShell.evtx
```

**Event viewer example,**

![Screenshot (582)](https://user-images.githubusercontent.com/43678329/190682207-aa583acb-115b-4225-ba77-588fc85b5762.png)


![Screenshot (581)](https://user-images.githubusercontent.com/43678329/190682233-e717ad18-d3f5-407f-aae3-b55e01b95e7a.png)



-----------------

## Important log files and event ids to be used for threat hunting.


#### System logs
--

![WhatsApp Image 2022-09-17 at 5 05 15 PM](https://user-images.githubusercontent.com/43678329/190854922-9e765ca9-b8ec-4956-9013-27fc54e3d637.jpeg)



![WhatsApp Image 2022-09-17 at 5 05 16 PM](https://user-images.githubusercontent.com/43678329/190854930-b32b72c3-1636-4e33-b4d3-9b21c44a0bd8.jpeg)

![WhatsApp Image 2022-09-17 at 5 05 16 PM (1)](https://user-images.githubusercontent.com/43678329/190854932-2fdf4c7e-8552-43a0-a131-6729546de72c.jpeg)


------------


#### Secuirty logs (divided as per categories)

1. WIndows dfender and firewall logs.
![WhatsApp Image 2022-09-17 at 5 06 01 PM](https://user-images.githubusercontent.com/43678329/190854975-5ed42fe0-fbde-44da-903c-14e77ef6487e.jpeg)

![WhatsApp Image 2022-09-17 at 5 08 11 PM](https://user-images.githubusercontent.com/43678329/190855123-bb75f760-c223-4b08-9460-4af6bf52719d.jpeg)



2. IP Sec logs.
![WhatsApp Image 2022-09-17 at 5 06 15 PM](https://user-images.githubusercontent.com/43678329/190854993-66b99a95-f5fc-4ba4-98e7-acde7bdfc3ca.jpeg)

3. Network share, handle objects and registry key event ids.

![WhatsApp Image 2022-09-17 at 5 06 30 PM](https://user-images.githubusercontent.com/43678329/190855003-599381ca-a962-446d-8db9-70837bceb8d9.jpeg)


4. Privelges and Process.
![WhatsApp Image 2022-09-17 at 5 06 45 PM](https://user-images.githubusercontent.com/43678329/190855043-731010cb-1bf6-4408-951f-5432dbc57a5b.jpeg)

5. User and groups related logs

![WhatsApp Image 2022-09-17 at 5 06 45 PM (1)](https://user-images.githubusercontent.com/43678329/190855080-fa97500d-0f50-4e66-9367-26f0fa4fb0fc.jpeg)

![WhatsApp Image 2022-09-17 at 5 07 05 PM](https://user-images.githubusercontent.com/43678329/190855084-7851f7dd-b8d2-4abe-a797-addf254a0fd1.jpeg)

![WhatsApp Image 2022-09-17 at 5 07 19 PM](https://user-images.githubusercontent.com/43678329/190855093-75850cfa-3198-4033-a8c1-0b9f725b14a4.jpeg)


6. Key management, certificates, encryption and crendeital manager.

![WhatsApp Image 2022-09-17 at 5 07 34 PM](https://user-images.githubusercontent.com/43678329/190855106-9802c83c-7427-4b64-9ba3-bd0321376164.jpeg)

![WhatsApp Image 2022-09-17 at 5 07 51 PM](https://user-images.githubusercontent.com/43678329/190855109-4ab8fee6-72f8-469f-94b1-7633635f30f6.jpeg)


7. Password related.
![WhatsApp Image 2022-09-17 at 5 09 05 PM](https://user-images.githubusercontent.com/43678329/190855148-3ad986a8-6959-486d-a01e-9099719b4baf.jpeg)

8. Audit related.

![WhatsApp Image 2022-09-17 at 5 09 18 PM](https://user-images.githubusercontent.com/43678329/190855164-9b38f188-754c-452b-b606-b589065c9944.jpeg)
![WhatsApp Image 2022-09-17 at 5 09 28 PM](https://user-images.githubusercontent.com/43678329/190855166-39cf5986-1ea7-459f-b8cd-6556ee175367.jpeg)

![WhatsApp Image 2022-09-17 at 5 09 44 PM](https://user-images.githubusercontent.com/43678329/190855168-a4edc89a-cf06-480a-af4e-648a788611ec.jpeg)


9. Application context.

![WhatsApp Image 2022-09-17 at 5 09 59 PM](https://user-images.githubusercontent.com/43678329/190855183-179652b5-5f96-4ec2-94c9-290ed6044a50.jpeg)


--------------

#### Category based segregation(High, medium ,low)


![WhatsApp Image 2022-09-17 at 5 08 37 PM](https://user-images.githubusercontent.com/43678329/190855228-d7b96745-640b-45fa-a70d-0136172e64a7.jpeg)

![WhatsApp Image 2022-09-17 at 5 08 50 PM](https://user-images.githubusercontent.com/43678329/190855230-f841e5c3-5318-4919-9bbd-e5598c082537.jpeg)


-----------

#### Application.evtx

![WhatsApp Image 2022-09-17 at 5 13 32 PM](https://user-images.githubusercontent.com/43678329/190855245-8225f329-6fa5-4dd9-bfb8-d7bb1eebeb8d.jpeg)


--------

#### Importnat log files to be checked for in system32/winevt/Logs/

- Importnat target files.

![WhatsApp Image 2022-09-17 at 5 11 41 PM](https://user-images.githubusercontent.com/43678329/190855268-d6437ce4-aa5b-4836-92cc-84632de92a66.jpeg)

![WhatsApp Image 2022-09-17 at 5 11 54 PM](https://user-images.githubusercontent.com/43678329/190855270-577f208e-a3d6-44e8-9922-e5ce70777e97.jpeg)

- USB logs reading,
![WhatsApp Image 2022-09-17 at 5 10 37 PM](https://user-images.githubusercontent.com/43678329/190855305-81b30374-361b-421f-b066-76519a5500e6.jpeg)

![WhatsApp Image 2022-09-17 at 5 10 49 PM](https://user-images.githubusercontent.com/43678329/190855307-b7269bbf-c0a0-45a3-9f1f-f6ad14e39b0d.jpeg)

- RDP logs

![WhatsApp Image 2022-09-17 at 5 11 05 PM](https://user-images.githubusercontent.com/43678329/190855352-e2d6d3f2-3852-4b6b-8ff8-ce12393262fb.jpeg)

![WhatsApp Image 2022-09-17 at 5 11 25 PM](https://user-images.githubusercontent.com/43678329/190855356-df45b194-58b0-42e7-bc5c-ae982923f7f8.jpeg)

- DNS and DHCP logs (these ar epresent in seperate folders, not in winevt/logs.

![WhatsApp Image 2022-09-17 at 5 11 05 PM (1)](https://user-images.githubusercontent.com/43678329/190855373-3b23a3ef-d7d1-4286-93ee-5f65272e262f.jpeg)


- bluetooth logs
![WhatsApp Image 2022-09-17 at 5 12 10 PM](https://user-images.githubusercontent.com/43678329/190855413-fe0c71a2-5af5-4d4c-b7c5-f45363f003e2.jpeg)

- WIndows defender log file.
![WhatsApp Image 2022-09-17 at 5 12 10 PM (1)](https://user-images.githubusercontent.com/43678329/190855426-49116c36-8e2f-46b5-a02b-1efb97216eb4.jpeg)
![WhatsApp Image 2022-09-17 at 5 12 25 PM](https://user-images.githubusercontent.com/43678329/190855431-23536a3c-03dc-4218-b05b-3321243b9d9e.jpeg)
![WhatsApp Image 2022-09-17 at 5 12 36 PM](https://user-images.githubusercontent.com/43678329/190855433-2785250b-d1c2-4768-ae9b-0ab01cfcb259.jpeg)


-----------------

## TO BE DONE Yet??
--

- Hardware.evtx
- Important event ids in application.evtx
- More explore on malware related threat hunting event ids. 
- VPN related logs ?? 
- Explore more on above targeted log files. 



