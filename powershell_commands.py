import subprocess
import sys

def powershell(cmd):
    try:
        p = subprocess.Popen(["powershell.exe"] + cmd, stdout=sys.stdout)
        p.communicate()
    except Exception as e:
        print("error: ", e)
        pass

app1 = [
    "*Microsoft.XboxGameOverlay*",
    "*Microsoft.Microsoft3DViewer*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.MixedReality.Portal*",
    "*Microsoft.Office.OneNote*",
    "*Microsoft.WebMediaExtensions*",
    "*Microsoft.WebpImageExtension*",
    "*Microsoft.WindowsMaps*",
    "*Microsoft.WindowsSoundRecorder*",
    "*Microsoft.Xbox.TCUI*",
    "*Microsoft.XboxApp*",
    "*Microsoft.XboxGameOverlay*",
    "*Microsoft.XboxGamingOverlay*",
    "*Microsoft.XboxIdentityProvider*",
    "*Microsoft.XboxSpeechToTextOverlay*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*Microsoft.Services.Store.Engagement*",
    "*Microsoft.NET.Native.Framework.1.*",
    "*Microsoft.BingWeather*",
    "*Microsoft.GetHelp*",
    "*Microsoft.Getstarted*",
    "*Microsoft.Messaging*",
    "*Microsoft.OneConnect*",
    "*Microsoft.Print3D*",
    "*Microsoft.SkypeApp*",
    "*Microsoft.WindowsAlarms*",
    "*Microsoft.WindowsCamera*",
    "*microsoft.windowscommunicationsapps*",
    "*Microsoft.WindowsFeedbackHub*",
    "*Microsoft.YourPhone*",
    "*Microsoft.WindowsFeedback*",
    "*Windows.ContactSupport*",
    "*PandoraMedia*",
    "*AdobeSystemIncorporated. AdobePhotoshop*",
    "*Duolingo*",
    "*Microsoft.BingNews*",
    "*Microsoft.Office.Sway*",
    "*Microsoft.Advertising.Xaml*",
    "*ActiproSoftware*",
    "*EclipseManager*",
    "*SpotifyAB.SpotifyMusic*",
    "*king.com.*",
    "*Microsoft.MicrosoftNotes*"
    # "*netflix*",
]

# Removing AppxPackages
for app in app1:
    powershell(["-command", f"Get-AppxPackage {app} -AllUsers | Remove-AppxPackage"])

app2 = [
    "Microsoft.BingWeather",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.WindowsMaps",
    "Microsoft.XboxApp",
    "Microsoft.XboxTCUI",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVedio",
    "Microsoft.Getstarted",
    "Microsoft.WindowsAlarms",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.YourPhone"
]

# Removing Provisioned AppxPackages
for app in app2:
    powershell(["-command", f"Get-AppxProvisionedPackage -Online | Where-Object {{$_.DisplayName -eq '{app}'}} | Remove-AppxProvisionedPackage -Online"])
