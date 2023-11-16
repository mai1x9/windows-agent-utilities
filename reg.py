import winreg

class REG_CONSTANTS:  # v0.1.5
    mapping = {
        0: winreg.HKEY_CLASSES_ROOT,
        1: winreg.HKEY_CURRENT_USER,  # HKC
        2: winreg.HKEY_LOCAL_MACHINE,  # HKLM
        3: winreg.HKEY_USERS,
        4: winreg.HKEY_CURRENT_CONFIG
    }


# v0.1.5
def set_reg(hive=0, reg_path='', key='', value='', type_=winreg.REG_DWORD):
    """Backup functions to call from other modules, for src, use the functions in reg.py
    """
    if not reg_path or not key:
        return None

    if hive in [0, 1, 2, 3, 4]:
        hive_path = REG_CONSTANTS.mapping[hive]  # winreg.HKEY_CURRENT_USER or winreg.HKEY_LOCAL_MACHINE etc..
        print(hive_path)
    else:
        hive_path = hive or winreg.HKEY_LOCAL_MACHINE

    try:
        winreg.CreateKey(hive_path, reg_path)  # Reg path is full path of the registry,
        # if sub folders not present, then it will be created recursively
        with winreg.OpenKey(hive_path, reg_path, 0, winreg.KEY_WRITE) as registry_key:
            winreg.SetValueEx(registry_key, key, 0, type_, value)  # winreg.REG_SZ

        return True  # If true, update is success
    
    except Exception as e0:
        return -1  # -1 is code for error
    
result = set_reg(hive=1, reg_path="SOFTWARE\Microsoft\Windows Defender", key="PassiveMode", value="2", type_=winreg.REG_DWORD)
print(result)


set_reg( 1, "SOFTWARE\Microsoft\Windows Defender" , " PassiveMode ", 2, winreg.REG_DWORD) 
set_reg( 1, "SYSTEM\CurrentControlSet\Policies\EarlyLaunch" , " DriverLoadPolicy ", 3 , winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" , " SupportedEncryptionTypes ",2147483640, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" , " DisableSmartNameResolution ",1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" , " DisableParallelAandAAAA ",1, winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" , " DisableIPSourceRouting ", 2,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" , " EnableICMPRedirect ",0, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" , " DisableIPSourceRouting ",2, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" , " SMB1 ",0, winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" , " RestrictNullSessAccess ",1, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , " EnableLUA ",1, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , " EnableVirtualization ", 1,winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" , " ConsentPromptBehaviorAdmin ", 2,winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" , " SaveZoneInformation ",2, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\Explorer" , " NoDataExecutionPrevention ", 0,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\Explorer" , " NoHeapTerminationOnCorruption ",0, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" , " AutoConnectAllowedOEM ",0 , winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" , " fMinimizeConnections ", 1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Netbt\Parameters" , " NoNameReleaseOnDemand ",1 , winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" , " allownullsessionfallback ", 0, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " LMCompatibilityLevel ",5 , winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " RestrictAnonymousSAM ", 1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " RestrictAnonymous ", 1,winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " EveryoneIncludesAnonymous ",0, winreg.REG_DWORD)

set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " RestrictRemoteSAM ", "O:BAG:BAD:(A;;RC;;;BA)",winreg.REG_SZ)

set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " UseMachineId ", 1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " LimitBlankPasswordUse ", 1, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" , " SCRemoveOption ", 2, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" , " RequireSignOrSeal ", 1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" , " SealSecureChannel ", 1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" , " SignSecureChannel ", 1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\System" , " EnableSmartScreen ", 1, winreg.REG_DWORD)

set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\System" , " ShellSmartScreenLevel ","Block", winreg.REG_SZ)

set_reg( 2, "SYSTEM\CurrentControlSet\Control\Session Manager" , " SafeDLLSearchMode ", 1,  winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Session Manager" , " ProtectionMode ", 1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" , " fAllowToGetHelp ",0, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" , " fEncryptRPCTraffic ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\Explorer" , " NoAutoplayfornonVolume ", 1 ,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" , " NoAutorun ", 1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" , " AllowUnencryptedTraffic ", 0,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" , " AllowDigest ", 0, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" , " DisableRpcOverTcp ",1, winreg.REG_DWORD)

##set_reg( 2,"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" , " DisableRemoteScmEndpoints ",1, winreg.REG_DWORD) 

set_reg( 2, "SYSTEM\CurrentControlSet\Services\mrxsmb10" , " Start ",4, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" , " AuditLevel ", 00000008 ,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " RunAsPPL ", 00000001, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" , " UseLogonCredential ", 0,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" , " AllowProtectedCreds ", 1,winreg.REG_DWORD) 


set_reg( 2, "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" , " EnhancedAntiSpoofing ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\Personalization" , " NoLockScreenCamera ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" , " LetAppsActivateWithVoiceAboveLock ",2, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" , " LetAppsActivateWithVoice ", 2,winreg.REG_DWORD)
set_reg( 1, "SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" , " EnabledV9 ",1, winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Policies\Microsoft\Windows\Installer" , " SafeForScripting ", 0,winreg.REG_DWORD) 

set_reg( 1, "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" , "FormSuggest Passwords","no" , winreg.REG_SZ )

set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\DataCollection" , " LimitEnhancedDiagnosticDataWindowsAnalytics ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\DataCollection" , " MaxTelemetryAllowed ", 1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" , " ShowedToastAtLevel ", 1,winreg.REG_DWORD) 

set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" , " Location ", "Deny",winreg.REG_SZ) 

set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\Search" , " BingSearchEnabled ",0, winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\Search" , " AllowSearchToUseLocation ",0, winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\Search" , " CortanaConsent ",0, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\System" , " PublishUserActivities ", 1, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\SettingSync" , " DisableSettingSync ",2, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" , " DisabledByGroupPolicy ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\GameDVR" , " AllowGameDVR ", 0 ,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\CloudContent" , " DisableWindowsConsumerFeatures ",1, winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" , " SystemPaneSuggestionsEnabled ",0, winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" , " SilentInstalledAppsEnabled ", 0,winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" , " PreInstalledAppsEnabled ", 0,winreg.REG_DWORD) 
set_reg( 1, "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" , " OemPreInstalledAppsEnabled ",0, winreg.REG_DWORD) 
set_reg( 2,"Control Panel\International\User Profile" , " HttpAcceptLanguageOptOut ", 1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" , " NoToastApplicationNotificationOnLockScreen ", 1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" , " ProcessCreationIncludeCmdLine_Enabled ",1, winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa" , " SCENoApplyLegacyAuditPolicy ", 1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" , " EnableModuleLogging ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" , " EnableScriptBlockLogging ",1, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "AllowCrossOriginAuthPrompt", 0, winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "AmbientAuthenticationInPrivateModesEnabled" ,0, winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "AudioSandboxEnabled" ,1, winreg.REG_DWORD) 

set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "SitePerProcess" ,1 , winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "TLS13HardeningForLocalAnchorsEnabled" ,1, winreg.REG_DWORD) 

set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa", "DisableRestrictedAdmin",00000000,winreg.REG_DWORD)      
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa", "DisableRestrictedAdminOutboundCreds",00000001,winreg.REG_DWORD)      
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "Negotiate",0,winreg.REG_DWORD)       
set_reg( 2, "System\CurrentControlSet\Services\LanmanWorkStation\Parameters","RequireSecuritySignature",1 ,winreg.REG_DWORD)      
set_reg( 2, "System\CurrentControlSet\Services\LanmanWorkStation\Parameters" , "EnableSecuritySignature",1,winreg.REG_DWORD)    
 
set_reg( 2, "System\CurrentControlSet\Services\LanmanServer\Parameters" ,"RequireSecuritySignature",1,winreg.REG_DWORD)     
 
set_reg( 2, "System\CurrentControlSet\Services\LanmanServer\Parameters" , "EnableSecuritySignature" ,1, winreg.REG_DWORD)     
 
set_reg( 2, "System\CurrentControlSet\Services\NTDS\Parameters" , "LDAPServerIntegrity" ,2, winreg.REG_DWORD)     
 
set_reg( 2, "System\CurrentControlSet\Services\ldap" , "LDAPClientIntegrity " ,1, winreg.REG_DWORD)     
 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinServerSec",537395200,winreg.REG_DWORD)       
set_reg( 2, "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinClientSec",537395200,winreg.REG_DWORD)       

set_reg( 2, "SYSTEM\CurrentControlSet\Control\Session Manager", "CWDIllegalInDllSearch",0x2,winreg.REG_DWORD)     
 
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "WpadOverride",1,winreg.REG_DWORD)       
set_reg( 1, "SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled",0,winreg.REG_DWORD)      
set_reg( 2, "SYSTEM\CurrentControlSet\services\tcpip6\parameters", "DisabledComponents",0xFF,winreg.REG_DWORD)       

  
set_reg( 2, "SOFTWARE\Policies\Microsoft\Windows\System", "DontDisplayNetworkSelectionUI",1 ,winreg.REG_DWORD)      
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun",0xff,winreg.REG_DWORD)     
  
set_reg( 1,"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun",0xff,winreg.REG_DWORD)     
  

set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced","HideFileExt",0,winreg.REG_DWORD)   
set_reg( 1,"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" ,"HideFileExt" ,0, winreg.REG_DWORD)   
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "Hidden" ,1, winreg.REG_DWORD)   
set_reg( 1,"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" , "Hidden" ,1, winreg.REG_DWORD)   
set_reg( 2, "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" ,"ShowSuperHidden" ,1, winreg.REG_DWORD)   
set_reg( 1,"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","ShowSuperHidden" ,1, winreg.REG_DWORD)   
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128", "Enabled", 0xffffffff,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56", "Enabled", 0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168", "Enabled",0,winreg.REG_DWORD) 
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384", "Enabled",0xffffffff ,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman", "Enabled", 0xffffffff,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman", "ServerMinKeyBitLength",0x00001000,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH", "Enabled", 0xffffffff,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client", "Enabled", 0,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client", "DisabledByDefault",1,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server", "Enabled", 0,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server", "DisabledByDefault",1,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client", "DisabledByDefault", 1,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server", "DisabledByDefault",1,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client", "DisabledByDefault", 1,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "DisabledByDefault", 1,winreg.REG_DWORD)    
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client", "DisabledByDefault",1,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server", "Enabled",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server", "DisabledByDefault",1,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client", "DisabledByDefault",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "DisabledByDefault",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client", "DisabledByDefault",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "DisabledByDefault",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client", "Enabled",0xffffffff,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client", "DisabledByDefault",0,winreg.REG_DWORD)     
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server", "Enabled",0xffffffff,winreg.REG_DWORD)
set_reg( 2, "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server", "DisabledByDefault", 0 ,winreg.REG_DWORD) 

set_reg( 2, "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727", "SchUseStrongCrypto",1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727", "SystemDefaultTlsVersions",1 ,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\.NETFramework\v2.0.50727", "SchUseStrongCrypto",1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Microsoft\.NETFramework\v2.0.50727", "SystemDefaultTlsVersions",1,winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto", 1,winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions",1,winreg.REG_DWORD) 

set_reg( 2, "Software\Adobe\Acrobat Reader\DC\Installer", "DisableMaintenance" ,1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bAcroSuppressUpsell",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bDisablePDFHandlerSwitching",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bDisableTrustedFolders",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bDisableTrustedSites",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bEnableFlash",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bEnhancedSecurityInBrowser",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bEnhancedSecurityStandalone",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "bProtectedMode",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "iFileAttachmentPerms",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown", "iProtectedView",2,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" , "bAdobeSendPluginToggle",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" , "iURLPerms",3,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" , "iUnknownURLPerms",2,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" ,"bToggleAdobeDocumentServices",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" ,"bToggleAdobeSign",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" , "bTogglePrefsSync",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" , "bToggleWebConnectors",1,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" ,"bUpdater",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint", "bDisableSharePointFeatures",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" , "bDisableWebmail",1,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" ,"bShowWelcomeScreen",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" , "DisableMaintenance",1,winreg.REG_DWORD)

set_reg( 2, "Software\Policies\Microsoft\Edge"  , "BackgroundModeEnabled",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" , "SitePerProcess",0x00000001,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" , "NativeMessagingUserLevelHosts",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" ,"SmartScreenEnabled",0x00000001,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge", "PreventSmartScreenPromptOverride",0x00000001,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" , "PreventSmartScreenPromptOverrideForFiles",0x00000001,winreg.REG_DWORD)
set_reg( 2, "Software\Policies\Microsoft\Edge" , "SSLErrorOverrideAllowed",0,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" , "SmartScreenPuaEnabled",0x00000001,winreg.REG_DWORD) 
set_reg( 2, "Software\Policies\Microsoft\Edge" , "AllowDeletingBrowserHistory",0x00000000,winreg.REG_DWORD)

set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "AlwaysOpenPdfExternally",0,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" , "AudioCaptureAllowed",1,winreg.REG_DWORD)
set_reg( 2, "SOFTWARE\Policies\Google\Chrome", "ScreenCaptureAllowed",1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\Policies\Google\Chrome" ,"VideoCaptureAllowed",1,winreg.REG_DWORD) 
set_reg( 2, "SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel", "MyComputer","Disabled",winreg.REG_SZ)     
set_reg( 2, "Software\Policies\Microsoft\Edge" , "SSLVersionMin",tls1.2^@, REG_SZ )
set_reg( 2, "SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel", "LocalIntranet","Disabled",winreg.REG_SZ)   
set_reg( 2, "SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel", "Internet","Disabled",winreg.REG_SZ)   

set_reg( 2, "SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel", "TrustedSites","Disabled",winreg.REG_SZ)     
set_reg( 2, "SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel", "UntrustedSites","Disabled",winreg.REG_SZ)   
set_reg( 1, "SOFTWARE\Microsoft\Windows Script Host\Settings", "ActiveDebugging",1,winreg.REG_SZ )      
set_reg( 1, "SOFTWARE\Microsoft\Windows Script Host\Settings", "DisplayLogo",1 ,winreg.REG_SZ )     
set_reg( 1, "SOFTWARE\Microsoft\Windows Script Host\Settings", "SilentTerminate",0,winreg.REG_SZ )     
set_reg( 1, "SOFTWARE\Microsoft\Windows Script Host\Settings", "UseWINSAFER", 1 ,winreg.REG_SZ)




