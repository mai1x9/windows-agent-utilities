import subprocess
from time import time

def mitigation_for_cve():

    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\" /v \"1001\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start()
    print("Rule ID: 1 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\" /v \"1001\" /t REG_DWORD /d 00000003 /f) : ", 
         out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2\" /v \"1004\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start()
    print("Rule ID: 2 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2\" /v \"1004\" /t REG_DWORD /d 00000003 /f) : ", 
         out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0\" /v \"1004\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 3 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0\" /v \"1004\" /t REG_DWORD /d 00000003 /f) : ", 
         out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\" /v \"1001\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 4 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\" /v \"1001\" /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2\" /v \"1001\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 5 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2\" /v \"1001\" /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete HKEY_CLASSES_ROOT\\ms-msdt /",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 6 Output (reg delete HKEY_CLASSES_ROOT\\ms-msdt /): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config\" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 7 Output (reg add \"HKLM\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config\" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Cryptography\\Wintrust\\Config\" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 8 Output (reg add \"HKLM\\Software\\Microsoft\\Cryptography\\Wintrust\\Config\" /v EnableCertPaddingCheck /t REG_SZ /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0\" /v \"1001\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 9 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0\" /v \"1001\" /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\" /v \"1004\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 10 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\" /v \"1004\" /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\" /v \"1004\" /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 11 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\" /v \"1004\" /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)


def create_restore_point():

    start = time()
    out, err = subprocess.Popen("powershell.exe vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 12 Output (powershell.exe vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -ExecutionPolicy Bypass -Command \"Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 13 Output (powershell.exe -ExecutionPolicy Bypass -Command \"Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 14 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\OLE /v EnableDCOM /t REG_SZ /d N /F",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 15 Output (reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\OLE /v EnableDCOM /t REG_SZ /d N /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe enable-computerrestore -drive c:\\",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 16 Output (powershell.exe enable-computerrestore -drive c:\\): ", out, "Error: ", err, " Duration: ", duration)


def google_chrome():
    
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultWebUsbGuardSetting\" /t REG_DWORD /d \"33554432\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 17 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultWebUsbGuardSetting\" /t REG_DWORD /d \"33554432\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioCaptureAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 18 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioCaptureAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"RemoteAccessHostFirewallTraversal\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 19 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"RemoteAccessHostFirewallTraversal\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"VideoCaptureAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 20 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"VideoCaptureAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowDeletingBrowserHistory\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 21 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowDeletingBrowserHistory\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"RestoreOnStartup\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 22 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"RestoreOnStartup\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowCrossOriginAuthPrompt\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 23 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowCrossOriginAuthPrompt\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportAutofillFormData\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 24 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportAutofillFormData\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"PromptForDownloadLocation\" /t REG_DWORD /d \"16777216\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 25 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"PromptForDownloadLocation\" /t REG_DWORD /d \"16777216\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AmbientAuthenticationInPrivateModesEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 26 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AmbientAuthenticationInPrivateModesEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"PasswordManagerEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 27 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"PasswordManagerEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist\" /v \"1\" /t REG_SZ /d \"cjpalhdlnbpafiamejdnhcphjbkeiagm\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 28 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist\" /v \"1\" /t REG_SZ /d \"cjpalhdlnbpafiamejdnhcphjbkeiagm\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutoFillEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 29 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutoFillEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SearchSuggestEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 30 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SearchSuggestEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"MetricsReportingEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 31 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"MetricsReportingEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DNSInterceptionChecksEnabled\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 32 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DNSInterceptionChecksEnabled\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ChromeCleanupReportingEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 33 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ChromeCleanupReportingEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultGeolocationSetting\" /t REG_DWORD /d \"33554432\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 34 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultGeolocationSetting\" /t REG_DWORD /d \"33554432\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"IncognitoModeAvailability\" /t REG_DWORD /d \"16777216\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 35 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"IncognitoModeAvailability\" /t REG_DWORD /d \"16777216\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlwaysOpenPdfExternally\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 36 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlwaysOpenPdfExternally\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlternateErrorPagesEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 37 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlternateErrorPagesEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"TLS13HardeningForLocalAnchorsEnabled\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 38 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"TLS13HardeningForLocalAnchorsEnabled\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultPluginsSetting\" /t REG_DWORD /d \"50331648\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 39 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultPluginsSetting\" /t REG_DWORD /d \"50331648\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UserFeedbackAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 40 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UserFeedbackAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsMode\" /t REG_SZ /d \"secure\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 41 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsMode\" /t REG_SZ /d \"secure\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"NetworkPredictionOptions\" /t REG_DWORD /d \"33554432\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 42 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"NetworkPredictionOptions\" /t REG_DWORD /d \"33554432\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsMode\" /t REG_SZ /d on /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 43 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsMode\" /t REG_SZ /d on /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AdvancedProtectionAllowed\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 44 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AdvancedProtectionAllowed\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UrlKeyedAnonymizedDataCollectionEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 45 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UrlKeyedAnonymizedDataCollectionEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ScreenCaptureAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 46 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ScreenCaptureAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SafeBrowsingExtendedReportingEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 47 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SafeBrowsingExtendedReportingEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Update\" /v \"AutoUpdateCheckPeriodMinutes\" /t REG_DWORD /d \"1613168640\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 48 Output (reg add \"HKLM\\Software\\Policies\\Google\\Update\" /v \"AutoUpdateCheckPeriodMinutes\" /t REG_DWORD /d \"1613168640\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowFileSelectionDialogs\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 49 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowFileSelectionDialogs\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutofillAddressEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 50 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutofillAddressEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"DownloadDirectory\" /t REG_SZ /d \"C:\\Users\\vibrio\\Desktop\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 51 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"DownloadDirectory\" /t REG_SZ /d \"C:\\Users\\vibrio\\Desktop\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioSandboxEnabled\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 52 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioSandboxEnabled\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsTemplates\" /t REG_SZ /d \"https://1.1.1.2/dns-query\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 53 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"DnsOverHttpsTemplates\" /t REG_SZ /d \"https://1.1.1.2/dns-query\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"CloudPrintProxyEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 54 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"CloudPrintProxyEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"PasswordLeakDetectionEnabled\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 55 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"PasswordLeakDetectionEnabled\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportSavedPasswords\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 56 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportSavedPasswords\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"WebRtcEventLogCollectionAllowed\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 57 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"WebRtcEventLogCollectionAllowed\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SafeBrowsingProtectionLevel\" /t REG_DWORD /d \"2\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 58 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SafeBrowsingProtectionLevel\" /t REG_DWORD /d \"2\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioCaptureAllowed\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 59 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AudioCaptureAllowed\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ImportSavedPasswords\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 60 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ImportSavedPasswords\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BackgroundModeEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 61 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BackgroundModeEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultPopupsSetting\" /t REG_DWORD /d \"33554432\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 62 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DefaultPopupsSetting\" /t REG_DWORD /d \"33554432\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UrlKeyedAnonymizedDataCollectionEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 63 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"UrlKeyedAnonymizedDataCollectionEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BlockThirdPartyCookies\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 64 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BlockThirdPartyCookies\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SavingBrowserHistoryDisabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 65 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SavingBrowserHistoryDisabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 66 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"TranslateEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 67 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"TranslateEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"SitePerProcess\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 68 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"SitePerProcess\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist\" /v \"1\" /t REG_SZ /d \"cjpalhdlnbpafiamejdnhcphjbkeiagm\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 69 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist\" /v \"1\" /t REG_SZ /d \"cjpalhdlnbpafiamejdnhcphjbkeiagm\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 70 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"DefaultDownloadDirectory\" /t REG_SZ /d \"C:\\Users\\vibrio\\Desktop\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 71 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"DefaultDownloadDirectory\" /t REG_SZ /d \"C:\\Users\\vibrio\\Desktop\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"CloudPrintSubmitEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 72 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"CloudPrintSubmitEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d tls1.1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 73 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d tls1.1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"MetricsReportingEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 74 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"MetricsReportingEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d tls1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 75 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d tls1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlwaysOpenPdfExternally\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 76 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AlwaysOpenPdfExternally\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"BlockExternalExtensions\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 77 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"BlockExternalExtensions\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AutoplayAllowed\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 78 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AutoplayAllowed\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"EnableOnlineRevocationChecks\" /t REG_DWORD /d \"16777216\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 79 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"EnableOnlineRevocationChecks\" /t REG_DWORD /d \"16777216\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"SafeBrowsingProtectionLevel\" /t REG_DWORD /d \"2\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 80 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\Recommended\" /v \"SafeBrowsingProtectionLevel\" /t REG_DWORD /d \"2\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"WebRtcEventLogCollectionAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 81 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"WebRtcEventLogCollectionAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d \"tls1.1\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 82 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"SSLVersionMin\" /t REG_SZ /d \"tls1.1\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"CloudPrintProxyEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 83 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"CloudPrintProxyEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"VideoCaptureAllowed\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 84 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"VideoCaptureAllowed\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutofillCreditCardEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 85 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"AutofillCreditCardEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\URLBlacklist\" /v \"1\" /t REG_SZ /d \"javascript://*\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 86 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\\URLBlacklist\" /v \"1\" /t REG_SZ /d \"javascript://*\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 87 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AllowOutdatedPlugins\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"EnableMediaRouter\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 88 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"EnableMediaRouter\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"RemoteDebuggingAllowed\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 89 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"RemoteDebuggingAllowed\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportAutofillFormData\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 90 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ImportAutofillFormData\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AdvancedProtectionAllowed\" /t REG_DWORD /d \"1\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 91 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AdvancedProtectionAllowed\" /t REG_DWORD /d \"1\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DownloadRestrictions\" /t REG_DWORD /d \"33554432\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 92 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"DownloadRestrictions\" /t REG_DWORD /d \"33554432\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BackgroundModeEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 93 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BackgroundModeEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BrowserGuestModeEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 94 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"BrowserGuestModeEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AlternateErrorPagesEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 95 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"AlternateErrorPagesEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ChromeCleanupEnabled\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 96 Output (reg add \"HKLM\\Software\\Policies\\Google\\Chrome\" /v \"ChromeCleanupEnabled\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ScreenCaptureAllowed\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 97 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Google\\Chrome\" /v \"ScreenCaptureAllowed\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)


def disable_autorun():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 98 Output (reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 99 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f) : ", out, "Error: ", err, " Duration: ", duration)


def strong_authentication_net():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 100 Output (reg add \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 101 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 102 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 103 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v2.0.50727\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 104 Output (reg add \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v2.0.50727\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 105 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v2.0.50727\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 106 Output (reg add \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v2.0.50727\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 107 Output (reg add \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319\" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)


def logging():
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"SAM\" /success:disable /failure:disable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 108 Output (Auditpol /set /subcategory:\"SAM\" /success:disable /failure:disable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Removable Storage\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 109 Output (Auditpol /set /subcategory:\"Removable Storage\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 110 Output (Auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Logoff\" /success:enable /failure:disable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 111 Output (Auditpol /set /subcategory:\"Logoff\" /success:enable /failure:disable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Filtering Platform Connection\" /success:enable /failure:disable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 112 Output (Auditpol /set /subcategory:\"Filtering Platform Connection\" /success:enable /failure:disable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wevtutil sl \"Microsoft-Windows-PowerShell/Operational\" /ms:1024000",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 113 Output (wevtutil  sl \"Microsoft-Windows-PowerShell/Operational\" /ms:1024000): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 114 Output (Auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wevtutil sl Security /ms:1024000", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 115 Output (wevtutil  sl Security /ms:1024000): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 116 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wevtutil sl System /ms:1024000", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 117 Output (wevtutil  sl System /ms:1024000): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Filtering Platform Policy Change\" /success:disable /failure:disable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 118 Output (Auditpol /set /subcategory:\"Filtering Platform Policy Change\" /success:disable /failure:disable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wevtutil sl \"Windows Powershell\" /ms:1024000",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 119 Output (wevtutil  sl \"Windows Powershell\" /ms:1024000): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\" /v EnableModuleLogging /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 120 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\" /v EnableModuleLogging /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"System Integrity\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 121 Output (Auditpol /set /subcategory:\"System Integrity\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Security System Extension\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 122 Output (Auditpol /set /subcategory:\"Security System Extension\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Security Group Management\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 123 Output (Auditpol /set /subcategory:\"Security Group Management\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 124 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 125 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wevtutil sl Application /ms:1024000", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 126 Output (wevtutil  sl Application /ms:1024000): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"IPsec Driver\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 127 Output (Auditpol /set /subcategory:\"IPsec Driver\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Auditpol /set /subcategory:\"Security State Change\" /success:enable /failure:enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 128 Output (Auditpol /set /subcategory:\"Security State Change\" /success:enable /failure:enable): ", out, "Error: ", err, " Duration: ", duration)


def windows_defender():
    start = time()
    out, err = subprocess.Popen("setx /M MP_FORCE_USE_SANDBOX 1", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 129 Output (setx /M MP_FORCE_USE_SANDBOX 1): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 130 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 131 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -SubmitSamplesConsent SendAllSamples",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 132 Output (powershell.exe Set-MpPreference -SubmitSamplesConsent SendAllSamples): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 133 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 134 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -CloudExtendedTimeout 50",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 135 Output (powershell.exe Set-MpPreference -CloudExtendedTimeout 50): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch\" /v DriverLoadPolicy /t REG_DWORD /d 3 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 136 Output (reg add \"HKCU\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch\" /v DriverLoadPolicy /t REG_DWORD /d 3 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 137 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -MAPSReporting Advanced",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 138 Output (powershell.exe Set-MpPreference -MAPSReporting Advanced): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 139 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 140 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 141 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 142 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Defender\" /v PassiveMode /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 143 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Defender\" /v PassiveMode /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 144 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -EnableNetworkProtection Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 145 Output (powershell.exe Set-MpPreference -EnableNetworkProtection Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 146 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 147 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 148 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 149 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 150 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 151 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -CheckForSignaturesBeforeRunningScan 1",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 152 Output (powershell.exe Set-MpPreference -CheckForSignaturesBeforeRunningScan 1): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 153 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("sc start WinDefend", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 154 Output (sc start WinDefend): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 155 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 156 Output (powershell.exe Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("\"%ProgramFiles%\"\\\"Windows Defender\"\\MpCmdRun.exe -SignatureUpdate",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 157 Output (\"%ProgramFiles%\"\\\"Windows Defender\"\\MpCmdRun.exe -SignatureUpdate): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -PUAProtection enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 158 Output (powershell.exe Set-MpPreference -PUAProtection enable): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 159 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 160 Output (powershell.exe Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("del ProcessMitigation.xml", 
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 161 Output (del ProcessMitigation.xml): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -CloudBlockLevel ZeroTolerance",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 162 Output (powershell.exe Set-MpPreference -CloudBlockLevel ZeroTolerance): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -SubmitSamplesConsent 0",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 163 Output (powershell.exe Set-MpPreference -SubmitSamplesConsent 0): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 164 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -SignatureUpdateInterval 4",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 165 Output (powershell.exe Set-MpPreference -SignatureUpdateInterval 4): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 166 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 167 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -SubmitSamplesConsent 3",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 168 Output (powershell.exe Set-MpPreference -SubmitSamplesConsent 3): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 169 Output (powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 170 Output (powershell.exe Set-MpPreference -EnableControlledFolderAccess Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 171 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 172 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -MAPSReporting 2",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 173 Output (powershell.exe Set-MpPreference -MAPSReporting 2): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 174 Output (powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 175 Output (powershell.exe Set-Processmitigation -System -Enable DEP): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -ScanAvgCPULoadFactor 25",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 176 Output (powershell.exe Set-MpPreference -ScanAvgCPULoadFactor 25): ", out, "Error: ", err, " Duration: ", duration)


def file_associations():
    start = time()
    out, err = subprocess.Popen("assoc .prn=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 177 Output (assoc .prn=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype jsefile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 178 Output (ftype jsefile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .vbs=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 179 Output (assoc .vbs=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemetadata-ms\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 180 Output (reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemetadata-ms\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .bat=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 181 Output (assoc .bat=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .ws=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 182 Output (assoc .ws=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 183 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype batfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 184 Output (ftype batfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype vbefile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 185 Output (ftype vbefile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .wsh=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 186 Output (assoc .wsh=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype vbsfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 187 Output (ftype vbsfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .vbe=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 188 Output (assoc .vbe=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wshfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 189 Output (ftype wshfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemanifest-ms\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 190 Output (reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemanifest-ms\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .slk=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 191 Output (assoc .slk=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .chm=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 192 Output (assoc .chm=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" DisableCompression -Type DWORD -Value 1 -Force",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 193 Output (powershell.exe Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" DisableCompression -Type DWORD -Value 1 -Force): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .iqy=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 194 Output (assoc .iqy=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wsffile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 195 Output (ftype wsffile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype jsfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 196 Output (ftype jsfile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .wcx=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 197 Output (assoc .wcx=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .hta=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 198 Output (assoc .hta=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .wsf=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 199 Output (assoc .wsf=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .js=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 200 Output (assoc .js=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .scr=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 201 Output (assoc .scr=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .cmd=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 202 Output (assoc .cmd=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .ps1=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 203 Output (assoc .ps1=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .rdg=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 204 Output (assoc .rdg=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .diff=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 205 Output (assoc .diff=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .wsc=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 206 Output (assoc .wsc=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .iso=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 207 Output (assoc .iso=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .deploy=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 208 Output (assoc .deploy=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype htafile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 209 Output (ftype htafile=\"%SystemRoot%\\system32\\NOTEPAD.EXE\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .reg=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 210 Output (assoc .reg=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .jse=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 211 Output (assoc .jse=txtfile): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("assoc .url=txtfile", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 212 Output (assoc .url=txtfile): ", out, "Error: ", err, " Duration: ", duration)


def privacy():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 213 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 214 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\" /v Location /t REG_SZ /d Deny /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 215 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\" /v Location /t REG_SZ /d Deny /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 216 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Control Panel\\International\\User Profile\" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 217 Output (reg add \"HKCU\\Control Panel\\International\\User Profile\" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 218 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 219 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 220 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v BingSearchEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 221 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v BingSearchEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 222 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v CortanaConsent /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 223 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v CortanaConsent /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSync /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 224 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSync /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 225 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 226 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 227 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 228 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 229 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v PublishUserActivities /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 230 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v PublishUserActivities /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 231 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)


def uninstall():
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 232 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 233 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Microsoft3DViewer'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 234 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Facebook* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 235 Output (powershell.exe -command \"Get-AppxPackage *Facebook* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 236 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 237 Output (powershell.exe -command \"Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*ActiproSoftwareLLC*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 238 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 239 Output (powershell.exe -command \"Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*CandyCrush*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 240 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.BingWeather**'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 241 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 242 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 243 Output (powershell.exe -command \"Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 244 Output (powershell.exe -command \"Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Flipboard*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 245 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Speed Test*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 246 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 247 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 248 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 249 Output (powershell.exe -command \"Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 250 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 251 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 252 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Office* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 253 Output (powershell.exe -command \"Get-AppxPackage *Office* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 254 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 255 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 256 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Speed Test* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 257 Output (powershell.exe -command \"Get-AppxPackage *Speed Test* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 258 Output (powershell.exe -command \"Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Xbox.TCUI'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 259 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Whiteboard'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 260 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 261 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.RemoteDesktop'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 262 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 263 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 264 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Minecraft*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 265 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask UsbCeip | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 266 Output (powershell.exe -command \"Get-ScheduledTask UsbCeip | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 267 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Set-WinLanguageBarOption -UseLegacyLanguageBar\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 268 Output (powershell.exe -command \"Set-WinLanguageBarOption -UseLegacyLanguageBar\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 269 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Minecraft* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 270 Output (powershell.exe -command \"Get-AppxPackage *Minecraft* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 271 Output (powershell.exe -command \"Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 272 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 273 Output (powershell.exe -command \"Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 274 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Messaging'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 275 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 276 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Advertising.Xaml'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 277 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 278 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 279 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Dolby* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 280 Output (powershell.exe -command \"Get-AppxPackage *Dolby* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 281 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 282 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 283 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Royal Revolt*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 284 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 285 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 286 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.OneConnect'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 287 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 288 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Dolby*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 289 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Whiteboard* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 290 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Whiteboard* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("taskkill /f /im OneDrive.exe", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 291 Output (taskkill /f /im OneDrive.exe): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 292 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Spotify*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 293 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 294 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingNews'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 295 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxTCUI'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 296 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 297 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Twitter* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 298 Output (powershell.exe -command \"Get-AppxPackage *Twitter* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 299 Output (powershell.exe -command \"Get-AppxPackage *Disney* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 300 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *netflix* | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 301 Output (powershell.exe -command \"Get-AppxPackage *netflix* | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 302 Output (powershell.exe -command \"Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 303 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 304 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 305 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 306 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 307 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*BubbleWitch3Saga*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 308 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 309 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"$env:SystemRoot\\SysWOW64\\OneDriveSetup.exe /uninstall\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 310 Output (powershell.exe -command \"$env:SystemRoot\\SysWOW64\\OneDriveSetup.exe /uninstall\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *CandyCrush* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 311 Output (powershell.exe -command \"Get-AppxPackage *CandyCrush* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Lens* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 312 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Lens* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Royal Revolt* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 313 Output (powershell.exe -command \"Get-AppxPackage *Royal Revolt* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask Consolidator | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 314 Output (powershell.exe -command \"Get-ScheduledTask Consolidator | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 315 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Disney'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 316 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Sway* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 317 Output (powershell.exe -command \"Get-AppxPackage *Sway* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.StorePurchaseApp'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 318 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 319 Output (powershell.exe -command \"Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Spotify* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 320 Output (powershell.exe -command \"Get-AppxPackage *Spotify* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 321 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*PandoraMediaInc*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 322 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 323 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 324 Output (powershell.exe -command \"Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 325 Output (powershell.exe -command \"Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.OneNote'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 326 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask DmClient | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 327 Output (powershell.exe -command \"Get-ScheduledTask DmClient | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.News* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 328 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.News* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 329 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 330 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.People* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 331 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 332 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 333 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Wunderlist*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 334 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 335 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 336 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *PandoraMediaInc* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 337 Output (powershell.exe -command \"Get-AppxPackage *PandoraMediaInc* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *ZuneVideo* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 338 Output (powershell.exe -command \"Get-AppxPackage *ZuneVideo* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 339 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 340 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *ActiproSoftwareLLC* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 341 Output (powershell.exe -command \"Get-AppxPackage *ActiproSoftwareLLC* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxSpeechToTextOverlay'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 342 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*AdobeSystemsIncorporated.AdobePhotoshopExpress*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 343 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Duolingo-LearnLanguagesforFree*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 344 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Todo.List'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 345 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 346 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.RemoteDesktop* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 347 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.RemoteDesktop* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Wunderlist* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 348 Output (powershell.exe -command \"Get-AppxPackage *Wunderlist* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*EclipseManager*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 349 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 350 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *BubbleWitch3Saga* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 351 Output (powershell.exe -command \"Get-AppxPackage *BubbleWitch3Saga* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 352 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Duolingo-LearnLanguagesforFree* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 353 Output (powershell.exe -command \"Get-AppxPackage *Duolingo-LearnLanguagesforFree* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Todo.List* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 354 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Todo.List* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 355 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Sway'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 356 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 357 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 358 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 359 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.NetworkSpeedTest'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 360 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Office.Lens'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 361 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 362 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 363 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 364 Output (powershell.exe -command \"Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage Microsoft.549981C3F5F10 -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 365 Output (powershell.exe -command \"Get-AppxPackage Microsoft.549981C3F5F10 -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.StorePurchaseApp* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 366 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.StorePurchaseApp* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Print3D'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 367 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Facebook*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 368 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Sway*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 369 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.NetworkSpeedTest* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 370 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.NetworkSpeedTest* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 371 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 372 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 373 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 374 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.News'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 375 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen(
        "powershell.exe -command \"Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*Twitter*'} | Remove-AppxProvisionedPackage -Online\"", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 376 Output (): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.XboxTCUI* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 377 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.XboxTCUI* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Flipboard* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 378 Output (powershell.exe -command \"Get-AppxPackage *Flipboard* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -command \"Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 379 Output (powershell.exe -command \"Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage\"): ", out, "Error: ", err, " Duration: ", duration)


def ms_office():
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 380 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Excel\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 381 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Excel\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 382 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 383 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Security\" /v markinternalasunsafe /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 384 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Security\" /v markinternalasunsafe /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 385 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 386 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Security\" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 387 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Security\" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 388 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 389 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 390 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 391 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 392 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 393 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 394 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 395 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 396 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 397 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 398 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 399 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Common\\Security\" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 400 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Common\\Security\" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 401 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 402 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 403 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 404 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 405 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 406 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 407 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 408 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 409 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Word\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 410 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Word\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 411 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 412 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 413 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 414 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 415 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 416 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 417 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 418 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 419 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 420 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Options\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\Common\\Security\" /v DisableAllActiveX /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 421 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\Common\\Security\" /v DisableAllActiveX /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 422 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 423 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 424 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Options\\DontUpdateLinks\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 425 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 426 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 427 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 428 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 429 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 430 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 431 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 432 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 433 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v AllowDDE /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 434 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 435 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 436 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Security\\FileBlock\" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 437 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 438 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 439 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Options\\WordMail\" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 440 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Onenote\\options\" /v disableembeddedfiles /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 441 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 442 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\PowerPoint\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 443 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 444 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 445 Output (reg add \"HKCU\\Software\\Microsoft\\Office\\15.0\\Word\\Security\\FileBlock\" /v RtfFiles /t REG_DWORD /d 00000002 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 446 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\15.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Options\\vpref\\fNoCalclinksOnopen_90_1\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 447 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\12.0\\Word\\Options\\vpref\\fNoCalclinksOnopen_90_1\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Excel\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 448 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Excel\\Security\" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 449 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Word\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Outlook\\Security\" /v markinternalasunsafe /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 450 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Outlook\\Security\" /v markinternalasunsafe /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 451 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\12.0\\Publisher\\Security\" /v vbawarnings /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 452 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Office\\14.0\\Excel\\Security\" /v PackagerPrompt /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 453 Output (reg add \"HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Onenote\\options\\embeddedfileopenoptions\" /v blockedextensions /t REG_SZ /d \".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps\" /f) : ", out, "Error: ", err, " Duration: ", duration)


def notepad():
    start = time()
    out, err = subprocess.Popen("ftype wscfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 454 Output (ftype wscfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype sctfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 455 Output (ftype sctfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype cmdfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 456 Output (ftype cmdfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemetadata-ms\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 457 Output (reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemetadata-ms\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype slkfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 458 Output (ftype slkfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype vbsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 459 Output (ftype vbsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete \"HKCR\\SettingContent\\Shell\\Open\\Command\" /v DelegateExecute /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 460 Output (reg delete \"HKCR\\SettingContent\\Shell\\Open\\Command\" /v DelegateExecute /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype deployfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 461 Output (ftype deployfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 462 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype chmfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 463 Output (ftype chmfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCR\\SettingContent\\Shell\\Open\\Command\" /v DelegateExecute /t REG_SZ /d \"\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 464 Output (reg add \"HKCR\\SettingContent\\Shell\\Open\\Command\" /v DelegateExecute /t REG_SZ /d \"\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype prnfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 465 Output (ftype prnfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemanifest-ms\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 466 Output (reg delete \"HKLM\\SOFTWARE\\Classes\\.devicemanifest-ms\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wshfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 467 Output (ftype wshfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype vbefile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 468 Output (ftype vbefile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype iqyfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 469 Output (ftype iqyfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wsffile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 470 Output (ftype wsffile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype urlfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 471 Output (ftype urlfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype htafile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 472 Output (ftype htafile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype mscfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 473 Output (ftype mscfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 474 Output (ftype wsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype jsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 475 Output (ftype jsfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype diffile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 476 Output (ftype diffile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype wcxfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 477 Output (ftype wcxfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype applicationfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 478 Output (ftype applicationfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype jsefile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 479 Output (ftype jsefile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype rdgfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 480 Output (ftype rdgfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype regfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 481 Output (ftype regfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("ftype batfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 482 Output (ftype batfile=\"%systemroot%\\system32\\notepad.exe\" \"%1\"): ", out, "Error: ", err, " Duration: ", duration)


def general_os_hardening():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v UntrustedSites /t REG_SZ /d \"Disabled\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 483 Output (reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v UntrustedSites /t REG_SZ /d \"Disabled\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowStatusBar\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 484 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowStatusBar\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v ProtectionMode /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 485 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v ProtectionMode /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v TrustedSites /t REG_SZ /d \"Disabled\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 486 Output (reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v TrustedSites /t REG_SZ /d \"Disabled\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SCRemoveOption /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 487 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SCRemoveOption /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v EnableSmartScreen /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 488 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v EnableSmartScreen /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableVirtualization /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 489 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableVirtualization /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\" /v RequireSecuritySignature /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 490 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\" /v RequireSecuritySignature /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkStation\\Parameters\" /v \"EnableSecuritySignature\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 491 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkStation\\Parameters\" /v \"EnableSecuritySignature\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 492 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 493 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 494 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 495 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 496 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowRecent\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 497 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowRecent\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 498 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 499 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\" /v AllowProtectedCreds /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 500 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\" /v AllowProtectedCreds /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v ShellSmartScreenLevel /t REG_SZ /d Block /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 501 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v ShellSmartScreenLevel /t REG_SZ /d Block /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v LocalIntranet /t REG_SZ /d \"Disabled\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 502 Output (reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v LocalIntranet /t REG_SZ /d \"Disabled\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictRemoteSAM /t REG_SZ /d \"O:BAG:BAD:(A;;RC;;;BA)\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 503 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictRemoteSAM /t REG_SZ /d \"O:BAG:BAD:): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 504 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 505 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("net start WinRM", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 506 Output (net start WinRM): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 507 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad\" /v WpadOverride /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 508 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad\" /v WpadOverride /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 509 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v ActiveDebugging /t REG_SZ /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 510 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v ActiveDebugging /t REG_SZ /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 511 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 512 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 513 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 514 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 515 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\" /v AddPrinterDrivers /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 516 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\" /v AddPrinterDrivers /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 517 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 518 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v IGMPLevel /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 519 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v IGMPLevel /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v RequireSignOrSeal /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 520 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v RequireSignOrSeal /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 521 Output (reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v MinEncryptionLevel /t REG_DWORD /d 00000003 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 522 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v MinEncryptionLevel /t REG_DWORD /d 00000003 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 523 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 524 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v ShowFrequent /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 525 Output (reg add \"HKLU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v ShowFrequent /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 526 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"AlwaysShowMenus\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 527 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"AlwaysShowMenus\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\" /v AllowDigest /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 528 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\" /v AllowDigest /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 529 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v UseMachineId /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 530 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v UseMachineId /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v ShowRecent /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 531 Output (reg add \"HKLU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v ShowRecent /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v FilterAdministratorToken /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 532 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v FilterAdministratorToken /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 533 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("net stop WinRM", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 534 Output (net stop WinRM): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 535 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v SilentTerminate /t REG_SZ /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 536 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v SilentTerminate /t REG_SZ /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SignSecureChannel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 537 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SignSecureChannel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 538 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 539 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\" /v allownullsessionfallback /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 540 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\" /v allownullsessionfallback /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Main\" /v DisableFirstRunCustomize /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 541 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Main\" /v DisableFirstRunCustomize /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKEY_CLASSES_ROOT\\Windows.IsoFile\\shell\\mount\" /v ProgrammaticAccessOnly /t REG_SZ /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 542 Output (reg add \"HKEY_CLASSES_ROOT\\Windows.IsoFile\\shell\\mount\" /v ProgrammaticAccessOnly /t REG_SZ /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 543 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v EnableSecuritySignature /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 544 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" /v EnableSecuritySignature /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 545 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 546 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 547 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 548 Output (reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkStation\\Parameters\" /v \"RequireSecuritySignature\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 549 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkStation\\Parameters\" /v \"RequireSecuritySignature\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 00000001 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 550 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 00000001 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 551 Output (wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 552 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 553 Output (reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 554 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 555 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v SecurityLayer /t REG_DWORD /d 00000002 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 556 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v SecurityLayer /t REG_DWORD /d 00000002 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 557 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v EnableICMPRedirect /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 558 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v EnableICMPRedirect /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 559 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\\" /v DODownloadMode /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 560 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\\" /v DODownloadMode /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DontPrettyPath\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 561 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DontPrettyPath\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 562 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v Internet /t REG_SZ /d \"Disabled\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 563 Output (reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v Internet /t REG_SZ /d \"Disabled\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NavPaneShowAllFolders\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 564 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NavPaneShowAllFolders\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NavPaneShowAllFolders\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 565 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NavPaneShowAllFolders\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 566 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 567 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 568 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v ACSettingIndex /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 569 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v ACSettingIndex /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\\" /v DODownloadMode /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 570 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\\" /v DODownloadMode /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v UseWINSAFER /t REG_SZ /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 571 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v UseWINSAFER /t REG_SZ /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 572 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe\" /v AuditLevel /t REG_DWORD /d 00000008 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 573 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe\" /v AuditLevel /t REG_DWORD /d 00000008 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"506\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 574 Output (reg add \"HKCU\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"506\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\ldap\" /v \"LDAPClientIntegrity \" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 575 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\ldap\" /v \"LDAPClientIntegrity \" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideIcons\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 576 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideIcons\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 577 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"LaunchTo\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 578 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"LaunchTo\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 579 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fDisableCdm /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 580 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fDisableCdm /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 581 Output (wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKEY_CLASSES_ROOT\\Windows.VhdFile\\shell\\mount\" /v ProgrammaticAccessOnly /t REG_SZ /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 582 Output (reg add \"HKEY_CLASSES_ROOT\\Windows.VhdFile\\shell\\mount\" /v ProgrammaticAccessOnly /t REG_SZ /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 583 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("BCDEDIT /set nointegritychecks OFF", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 584 Output (BCDEDIT /set nointegritychecks OFF): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 585 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\" /v Start /t REG_DWORD /d 4 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 586 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\" /v Start /t REG_DWORD /d 4 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 587 Output (powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v \"HubMode\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 588 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v \"HubMode\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 589 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v DisplayLogo /t REG_SZ /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 590 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v DisplayLogo /t REG_SZ /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 591 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v \"EnableSecuritySignature\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 592 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v \"EnableSecuritySignature\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\" /v fMinimizeConnections /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 593 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\" /v fMinimizeConnections /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v \"RequireSecuritySignature\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 594 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v \"RequireSecuritySignature\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v MyComputer /t REG_SZ /d \"Disabled\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 595 Output (reg add \"HKLM\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\" /v MyComputer /t REG_SZ /d \"Disabled\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SignSecureChannel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 596 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SignSecureChannel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 597 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\" /v SaveZoneInformation /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 598 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\" /v SaveZoneInformation /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"SeparateProcess\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 599 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"SeparateProcess\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v \"LDAPServerIntegrity\" /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 600 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v \"LDAPServerIntegrity\" /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("setx __PSLockdownPolicy \"4\" /M", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 601 Output (setx __PSLockdownPolicy \"4\" /M): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Start_TrackDocs\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 602 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Start_TrackDocs\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1 /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 603 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1 /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v DCSettingIndex /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 604 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" /v DCSettingIndex /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SealSecureChannel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 605 Output (reg add \"HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SealSecureChannel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoAutorun /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 606 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoAutorun /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fAllowToGetHelp /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 607 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\" /v fAllowToGetHelp /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 608 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 609 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 610 Output (reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SealSecureChannel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 611 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\" /v SealSecureChannel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 612 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 613 Output (reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\" /v DisableAutoplay /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 614 Output (reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\" /v DisableAutoplay /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("wmic /interactive:off nicconfig where (TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1) call SetTcpipNetbios 2",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 615 Output (wmic /interactive:off nicconfig where ): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 616 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v Negotiate /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 617 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v Negotiate /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\tcpip6\\parameters\" /v DisabledComponents /t REG_DWORD /d 0xFF /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 618 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\tcpip6\\parameters\" /v DisabledComponents /t REG_DWORD /d 0xFF /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"AutoCheckSelect\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 619 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"AutoCheckSelect\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 620 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)


def biometrics():
    start = time()
    out, err = subprocess.Popen("fsutil behavior set disable8dot3 1", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 621 Output (fsutil behavior set disable8dot3 1): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("fsutil behavior set disablelastaccess 0",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 622 Output (fsutil behavior set disablelastaccess 0): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\" /v NoLockScreenCamera /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 623 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\" /v NoLockScreenCamera /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 624 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 625 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 626 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)


def disable_weak_tls_ssl_protocols_ciphers():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 627 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 628 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 629 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 40/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 630 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 40/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA384\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 631 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA384\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 632 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 633 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 128/128\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 634 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 128/128\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 635 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 636 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\MD5\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 637 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\MD5\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 638 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 639 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 640 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\ECDH\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 641 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\ECDH\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 642 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 643 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 644 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA256\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 645 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA256\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 646 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 647 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\PKCS\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 648 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\PKCS\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 649 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Server\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 650 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 56/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 651 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 56/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 652 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 653 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 654 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\" /v EccCurves /t REG_MULTI_SZ /d NistP384): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Client\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 655 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Client\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 656 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 64/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 657 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 64/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\" /v Functions /t REG_SZ /d \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256\" /f", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 658 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\" /v Functions /t REG_SZ /d \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 659 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 56/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 660 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 56/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 128/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 661 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC2 128/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Server\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 662 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Server\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 663 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\Multi-Protocol Unified Hello\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 664 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 40/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 665 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 40/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 666 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 667 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 668 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 669 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 670 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 256/256\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 671 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\AES 256/256\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman\" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 672 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman\" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 673 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\PCT 1.0\\Client\" /v DisabledByDefault /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 674 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168\" /v Enabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 675 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168\" /v Enabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA512\" /v Enabled /t REG_DWORD /d 0xffffffff /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 676 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\SHA512\" /v Enabled /t REG_DWORD /d 0xffffffff /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 677 Output (reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client\" /v DisabledByDefault /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)


def firewall():
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\system32\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 678 Output (netsh advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\system32\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block regasm.exe netconns\" program=\"%systemroot%\\system32\\regasm.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 679 Output (netsh advfirewall firewall add rule name=\"Block regasm.exe netconns\" program=\"%systemroot%\\system32\\regasm.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\SysWOW64\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 680 Output (netsh advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\SysWOW64\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block scriptrunner.exe netconns\" program=\"%systemroot%\\system32\\scriptrunner.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 681 Output (netsh advfirewall firewall add rule name=\"Block scriptrunner.exe netconns\" program=\"%systemroot%\\system32\\scriptrunner.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\system32\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 682 Output (Netsh.exe  advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\system32\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block appvlp.exe netconns\" program=\"C:\\Program Files (x86)\\Microsoft Office\\root\\client\\AppVLP.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 683 Output (netsh advfirewall firewall add rule name=\"Block appvlp.exe netconns\" program=\"C:\\Program Files ): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 684 Output (netsh advfirewall set publicprofile firewallpolicy blockinboundalways): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\SysWOW64\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 685 Output (netsh advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\SysWOW64\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block pcalua.exe netconns\" program=\"%systemroot%\\SysWOW64\\pcalua.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 686 Output (netsh advfirewall firewall add rule name=\"Block pcalua.exe netconns\" program=\"%systemroot%\\SysWOW64\\pcalua.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\system32\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 687 Output (Netsh.exe  advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\system32\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block nltest.exe netconns\" program=\"%systemroot%\\system32\\nltest.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 688 Output (netsh advfirewall firewall add rule name=\"Block nltest.exe netconns\" program=\"%systemroot%\\system32\\nltest.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\SysWOW64\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 689 Output (netsh advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\SysWOW64\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\system32\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 690 Output (netsh advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\system32\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block expand.exe netconns\" program=\"%systemroot%\\SysWOW64\\expand.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 691 Output (netsh advfirewall firewall add rule name=\"Block expand.exe netconns\" program=\"%systemroot%\\SysWOW64\\expand.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\system32\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 692 Output (netsh advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\system32\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block certutil.exe netconns\" program=\"%systemroot%\\system32\\certutil.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 693 Output (netsh advfirewall firewall add rule name=\"Block certutil.exe netconns\" program=\"%systemroot%\\system32\\certutil.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block odbcconf.exe netconns\" program=\"%systemroot%\\SysWOW64\\odbcconf.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 694 Output (netsh advfirewall firewall add rule name=\"Block odbcconf.exe netconns\" program=\"%systemroot%\\SysWOW64\\odbcconf.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block certutil.exe netconns\" program=\"%systemroot%\\SysWOW64\\certutil.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 695 Output (netsh advfirewall firewall add rule name=\"Block certutil.exe netconns\" program=\"%systemroot%\\SysWOW64\\certutil.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block cmstp.exe netconns\" program=\"%systemroot%\\system32\\cmstp.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 696 Output (netsh advfirewall firewall add rule name=\"Block cmstp.exe netconns\" program=\"%systemroot%\\system32\\cmstp.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block print.exe netconns\" program=\"%systemroot%\\SysWOW64\\print.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 697 Output (netsh advfirewall firewall add rule name=\"Block print.exe netconns\" program=\"%systemroot%\\SysWOW64\\print.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\system32\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 698 Output (Netsh.exe  advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\system32\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe Set-MpPreference -EnableNetworkProtection Enabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 699 Output (powershell.exe Set-MpPreference -EnableNetworkProtection Enabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\system32\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 700 Output (netsh advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\system32\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block esentutl.exe netconns\" program=\"%systemroot%\\system32\\esentutl.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 701 Output (netsh advfirewall firewall add rule name=\"Block esentutl.exe netconns\" program=\"%systemroot%\\system32\\esentutl.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("NetSh Advfirewall set allprofiles state on",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 702 Output (netsh Advfirewall set allprofiles state on): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block SyncAppvPublishingServer.exe netconns\" program=\"%systemroot%\\SysWOW64\\SyncAppvPublishingServer.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 703 Output (netsh advfirewall firewall add rule name=\"Block SyncAppvPublishingServer.exe netconns\" program=\"%systemroot%\\SysWOW64\\SyncAppvPublishingServer.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block cmstp.exe netconns\" program=\"%systemroot%\\SysWOW64\\cmstp.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 704 Output (netsh advfirewall firewall add rule name=\"Block cmstp.exe netconns\" program=\"%systemroot%\\SysWOW64\\cmstp.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block odbcconf.exe netconns\" program=\"%systemroot%\\system32\\odbcconf.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 705 Output (netsh advfirewall firewall add rule name=\"Block odbcconf.exe netconns\" program=\"%systemroot%\\system32\\odbcconf.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\system32\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 706 Output (Netsh.exe  advfirewall firewall add rule name=\"Block mshta.exe netconns\" program=\"%systemroot%\\system32\\mshta.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block esentutl.exe netconns\" program=\"%systemroot%\\SysWOW64\\esentutl.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 707 Output (netsh advfirewall firewall add rule name=\"Block esentutl.exe netconns\" program=\"%systemroot%\\SysWOW64\\esentutl.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block scriptrunner.exe netconns\" program=\"%systemroot%\\SysWOW64\\scriptrunner.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 708 Output (netsh advfirewall firewall add rule name=\"Block scriptrunner.exe netconns\" program=\"%systemroot%\\SysWOW64\\scriptrunner.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block wmic.exe netconns\" program=\"%systemroot%\\system32\\wbem\\wmic.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 709 Output (netsh advfirewall firewall add rule name=\"Block wmic.exe netconns\" program=\"%systemroot%\\system32\\wbem\\wmic.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block regasm.exe netconns\" program=\"%systemroot%\\SysWOW64\\regasm.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 710 Output (netsh advfirewall firewall add rule name=\"Block regasm.exe netconns\" program=\"%systemroot%\\SysWOW64\\regasm.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\SysWOW64\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 711 Output (netsh advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\SysWOW64\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh Advfirewall set allprofiles state on",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 712 Output (netsh Advfirewall set allprofiles state on): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block extrac32.exe netconns\" program=\"%systemroot%\\SysWOW64\\extrac32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 713 Output (netsh advfirewall firewall add rule name=\"Block extrac32.exe netconns\" program=\"%systemroot%\\SysWOW64\\extrac32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block nltest.exe netconns\" program=\"%systemroot%\\SysWOW64\\nltest.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 714 Output (netsh advfirewall firewall add rule name=\"Block nltest.exe netconns\" program=\"%systemroot%\\SysWOW64\\nltest.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block wmic.exe netconns\" program=\"%systemroot%\\SysWOW64\\wbem\\wmic.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 715 Output (netsh advfirewall firewall add rule name=\"Block wmic.exe netconns\" program=\"%systemroot%\\SysWOW64\\wbem\\wmic.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block findstr.exe netconns\" program=\"%systemroot%\\SysWOW64\\findstr.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 716 Output (netsh advfirewall firewall add rule name=\"Block findstr.exe netconns\" program=\"%systemroot%\\SysWOW64\\findstr.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall set currentprofile logging filename %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 717 Output (netsh advfirewall set currentprofile logging filename %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 718 Output (netsh advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\SysWOW64\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 719 Output (netsh advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\SysWOW64\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block replace.exe netconns\" program=\"%systemroot%\\system32\\replace.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 720 Output (netsh advfirewall firewall add rule name=\"Block replace.exe netconns\" program=\"%systemroot%\\system32\\replace.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 721 Output (Netsh.exe  advfirewall firewall add rule name=\"Block Notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block replace.exe netconns\" program=\"%systemroot%\\SysWOW64\\replace.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 722 Output (netsh advfirewall firewall add rule name=\"Block replace.exe netconns\" program=\"%systemroot%\\SysWOW64\\replace.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\SysWOW64\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 723 Output (netsh advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\SysWOW64\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\SysWOW64\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 724 Output (netsh advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\SysWOW64\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block rundll32.exe netconns\" program=\"%systemroot%\\SysWOW64\\rundll32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 725 Output (netsh advfirewall firewall add rule name=\"Block rundll32.exe netconns\" program=\"%systemroot%\\SysWOW64\\rundll32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block rpcping.exe netconns\" program=\"%systemroot%\\SysWOW64\\rpcping.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 726 Output (netsh advfirewall firewall add rule name=\"Block rpcping.exe netconns\" program=\"%systemroot%\\SysWOW64\\rpcping.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block appvlp.exe netconns\" program=\"C:\\Program Files\\Microsoft Office\\root\\client\\AppVLP.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 727 Output (netsh advfirewall firewall add rule name=\"Block appvlp.exe netconns\" program=\"C:\\Program Files\\Microsoft Office\\root\\client\\AppVLP.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\system32\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 728 Output (netsh advfirewall firewall add rule name=\"Block calc.exe netconns\" program=\"%systemroot%\\system32\\calc.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block notepad.exe netconns\" program=\"%systemroot%\\SysWOW64\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 729 Output (netsh advfirewall firewall add rule name=\"Block notepad.exe netconns\" program=\"%systemroot%\\SysWOW64\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block SyncAppvPublishingServer.exe netconns\" program=\"%systemroot%\\system32\\SyncAppvPublishingServer.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 730 Output (netsh advfirewall firewall add rule name=\"Block SyncAppvPublishingServer.exe netconns\" program=\"%systemroot%\\system32\\SyncAppvPublishingServer.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block findstr.exe netconns\" program=\"%systemroot%\\system32\\findstr.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 731 Output (netsh advfirewall firewall add rule name=\"Block findstr.exe netconns\" program=\"%systemroot%\\system32\\findstr.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block makecab.exe netconns\" program=\"%systemroot%\\SysWOW64\\makecab.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 732 Output (netsh advfirewall firewall add rule name=\"Block makecab.exe netconns\" program=\"%systemroot%\\SysWOW64\\makecab.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\system32\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 733 Output (Netsh.exe  advfirewall firewall add rule name=\"Block cscript.exe netconns\" program=\"%systemroot%\\system32\\cscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall set currentprofile logging maxfilesize 4096",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 734 Output (netsh advfirewall set currentprofile logging maxfilesize 4096): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\system32\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 735 Output (Netsh.exe  advfirewall firewall add rule name=\"Block hh.exe netconns\" program=\"%systemroot%\\system32\\hh.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block msiexec.exe netconns\" program=\"%systemroot%\\SysWOW64\\msiexec.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 736 Output (netsh advfirewall firewall add rule name=\"Block msiexec.exe netconns\" program=\"%systemroot%\\SysWOW64\\msiexec.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 737 Output (netsh advfirewall firewall add rule name=\"Block notepad.exe netconns\" program=\"%systemroot%\\system32\\notepad.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("Netsh.exe advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\system32\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 738 Output (Netsh.exe  advfirewall firewall add rule name=\"Block runscripthelper.exe netconns\" program=\"%systemroot%\\system32\\runscripthelper.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\system32\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 739 Output (netsh advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\system32\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block expand.exe netconns\" program=\"%systemroot%\\system32\\expand.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 740 Output (netsh advfirewall firewall add rule name=\"Block expand.exe netconns\" program=\"%systemroot%\\system32\\expand.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block extrac32.exe netconns\" program=\"%systemroot%\\system32\\extrac32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 741 Output (netsh advfirewall firewall add rule name=\"Block extrac32.exe netconns\" program=\"%systemroot%\\system32\\extrac32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block msiexec.exe netconns\" program=\"%systemroot%\\system32\\msiexec.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 742 Output (netsh advfirewall firewall add rule name=\"Block msiexec.exe netconns\" program=\"%systemroot%\\system32\\msiexec.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\system32\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 743 Output (netsh advfirewall firewall add rule name=\"Block regsvr32.exe netconns\" program=\"%systemroot%\\system32\\regsvr32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block print.exe netconns\" program=\"%systemroot%\\system32\\print.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 744 Output (netsh advfirewall firewall add rule name=\"Block print.exe netconns\" program=\"%systemroot%\\system32\\print.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block pcalua.exe netconns\" program=\"%systemroot%\\system32\\pcalua.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 745 Output (netsh advfirewall firewall add rule name=\"Block pcalua.exe netconns\" program=\"%systemroot%\\system32\\pcalua.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block makecab.exe netconns\" program=\"%systemroot%\\system32\\makecab.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 746 Output (netsh advfirewall firewall add rule name=\"Block makecab.exe netconns\" program=\"%systemroot%\\system32\\makecab.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block rundll32.exe netconns\" program=\"%systemroot%\\system32\\rundll32.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 747 Output (netsh advfirewall firewall add rule name=\"Block rundll32.exe netconns\" program=\"%systemroot%\\system32\\rundll32.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh int tcp set global timestamps=disabled",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 748 Output (netsh int tcp set global timestamps=disabled): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\SysWOW64\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 749 Output (netsh advfirewall firewall add rule name=\"Block wscript.exe netconns\" program=\"%systemroot%\\SysWOW64\\wscript.exe\" protocol=tcp dir=out enable=yes action=block profile=any): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("netsh advfirewall set currentprofile logging droppedconnections enable",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 750 Output (netsh advfirewall set currentprofile logging droppedconnections enable): ", out, "Error: ", err, " Duration: ", duration)


def adobe_reader():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"iFileAttachmentPerms\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 751 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"iFileAttachmentPerms\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleAdobeSign\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 752 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleAdobeSign\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnhancedSecurityInBrowser\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 753 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnhancedSecurityInBrowser\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWelcomeScreen\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 754 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWelcomeScreen\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisableTrustedSites\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 755 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisableTrustedSites\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /v \"iUnknownURLPerms\" /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 756 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /v \"iUnknownURLPerms\" /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer\" /v \"DisableMaintenance\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 757 Output (reg add \"HKLM\\Software\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer\" /v \"DisableMaintenance\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnableFlash\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 758 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnableFlash\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Adobe\\Acrobat Reader\\DC\\Installer\" /v \"DisableMaintenance\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 759 Output (reg add \"HKLM\\Software\\Adobe\\Acrobat Reader\\DC\\Installer\" /v \"DisableMaintenance\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisablePDFHandlerSwitching\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 760 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisablePDFHandlerSwitching\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bProtectedMode\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 761 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bProtectedMode\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"iProtectedView\" /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 762 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"iProtectedView\" /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 763 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnhancedSecurityStandalone\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 764 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bEnhancedSecurityStandalone\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /v \"iURLPerms\" /t REG_DWORD /d 3 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 765 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms\" /v \"iURLPerms\" /t REG_DWORD /d 3 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisableTrustedFolders\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 766 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bDisableTrustedFolders\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cCloud\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 767 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cCloud\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 768 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cSharePoint\" /v \"bDisableSharePointFeatures\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 769 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cSharePoint\" /v \"bDisableSharePointFeatures\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleAdobeDocumentServices\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 770 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleAdobeDocumentServices\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleWebConnectors\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 771 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bToggleWebConnectors\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWelcomeScreen\" /v \"bShowWelcomeScreen\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 772 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWelcomeScreen\" /v \"bShowWelcomeScreen\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWebmailProfiles\" /v \"bDisableWebmail\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 773 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWebmailProfiles\" /v \"bDisableWebmail\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cCloud\" /v \"bAdobeSendPluginToggle\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 774 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cCloud\" /v \"bAdobeSendPluginToggle\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bTogglePrefsSync\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 775 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bTogglePrefsSync\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWebmailProfiles\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 776 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cWebmailProfiles\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bAcroSuppressUpsell\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 777 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\" /v \"bAcroSuppressUpsell\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cSharePoint\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 778 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cSharePoint\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bUpdater\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 779 Output (reg add \"HKLM\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices\" /v \"bUpdater\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)


def show_hidden_files():
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 780 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 781 Output (reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideFileExt\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 782 Output (reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideFileExt\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"HiberbootEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 783 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"HiberbootEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powershell.exe -Command \"$PhysAdapter = Get-NetAdapter -Physical;$PhysAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses '1.1.1.1','8.8.8.8'\"",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 784 Output (powershell.exe -Command \"$PhysAdapter = Get-NetAdapter -Physical;$PhysAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses '1.1.1.1'): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("fsutil behavior set disable8dot3 1", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 785 Output (fsutil behavior set disable8dot3 1): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideFileExt\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 786 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"HideFileExt\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 787 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 788 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\" /v Location /t REG_SZ /d Deny /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 789 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\" /v Location /t REG_SZ /d Deny /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 790 Output (reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 791 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\Control Panel\\International\\User Profile\" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 792 Output (reg add \"HKCU\\Control Panel\\International\\User Profile\" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 793 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 794 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 795 Output (reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v BingSearchEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 796 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v BingSearchEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("fsutil behavior set disablelastaccess 0",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 797 Output (fsutil behavior set disablelastaccess 0): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 798 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 799 Output (reg add \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v CortanaConsent /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 800 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v CortanaConsent /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSync /t REG_DWORD /d 2 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 801 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v DisableSettingSync /t REG_DWORD /d 2 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 802 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("powercfg -h off", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 803 Output (powercfg -h off): ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 804 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search\" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 805 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 806 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 807 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v PublishUserActivities /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 808 Output (reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v PublishUserActivities /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 809 Output (reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)


def edge():
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" /v EnabledV9 /t REG_DWORD /d 1 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 810 Output (reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" /v EnabledV9 /t REG_DWORD /d 1 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\"  /v \"BackgroundModeEnabled\" /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 811 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\"  /v \"BackgroundModeEnabled\" /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 812 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\1\" /t REG_SZ /d \"odfafepnkmbhccpbejgmiehpchacaeak\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 813 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallAllowlist\\1\" /t REG_SZ /d \"odfafepnkmbhccpbejgmiehpchacaeak\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"AllowDeletingBrowserHistory\" /t REG_DWORD /d \"0x00000000\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 814 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"AllowDeletingBrowserHistory\" /t REG_DWORD /d \"0x00000000\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"PreventSmartScreenPromptOverrideForFiles\" /t REG_DWORD /d \"0x00000001\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 815 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"PreventSmartScreenPromptOverrideForFiles\" /t REG_DWORD /d \"0x00000001\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v SafeForScripting /t REG_DWORD /d 0 /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 816 Output (reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v SafeForScripting /t REG_DWORD /d 0 /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SitePerProcess\" /t REG_DWORD /d \"0x00000001\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 817 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SitePerProcess\" /t REG_DWORD /d \"0x00000001\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SSLVersionMin\" /t REG_SZ /d \"tls1.2^@\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 818 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SSLVersionMin\" /t REG_SZ /d \"tls1.2^@\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SmartScreenPuaEnabled\" /t REG_DWORD /d \"0x00000001\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 819 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SmartScreenPuaEnabled\" /t REG_DWORD /d \"0x00000001\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist\\1\" /t REG_SZ /d \"odfafepnkmbhccpbejgmiehpchacaeak\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 820 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist\\1\" /t REG_SZ /d \"odfafepnkmbhccpbejgmiehpchacaeak\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"PreventSmartScreenPromptOverride\" /t REG_DWORD /d \"0x00000001\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 821 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"PreventSmartScreenPromptOverride\" /t REG_DWORD /d \"0x00000001\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SSLErrorOverrideAllowed\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 822 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SSLErrorOverrideAllowed\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"NativeMessagingUserLevelHosts\" /t REG_DWORD /d \"0\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 823 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"NativeMessagingUserLevelHosts\" /t REG_DWORD /d \"0\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\" /v \"FormSuggest Passwords\" /t REG_SZ /d no /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 824 Output (reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\" /v \"FormSuggest Passwords\" /t REG_SZ /d no /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SmartScreenEnabled\" /t REG_DWORD /d \"0x00000001\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 825 Output (reg add \"HKLM\\Software\\Policies\\Microsoft\\Edge\" /v \"SmartScreenEnabled\" /t REG_DWORD /d \"0x00000001\" /f) : ", out, "Error: ", err, " Duration: ", duration)
    start = time()
    out, err = subprocess.Popen("reg add \"HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Edge\\Extensions\\odfafepnkmbhccpbejgmiehpchacaeak\" /v \"update_url\" /t REG_SZ /d \"https://edge.microsoft.com/extensionwebstorebase/v1/crx\" /f",
                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    duration = time() - start
    print("Rule ID: 826 Output (reg add \"HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Edge\\Extensions\\odfafepnkmbhccpbejgmiehpchacaeak\" /v \"update_url\" /t REG_SZ /d \"https://edge.microsoft.com/extensionwebstorebase/v1/crx\" /f) : ", out, "Error: ", err, " Duration: ", duration)
