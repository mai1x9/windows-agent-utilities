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


# v0.1.5
def get_reg(hive='', reg_path='', name=''):
    """Backup functions to call from other modules, for src, use the functions in reg.py
    """
    if not reg_path or not name:
        #  raise Exception("Provide Proper registry path/name/.")
        return None, None

    if hive in [0, 1, 2, 3, 4]:
        hive_path = REG_CONSTANTS.mapping[hive]  # winreg.HKEY_CURRENT_USER or winreg.HKEY_LOCAL_MACHINE etc..
    else:
        hive_path = hive or winreg.HKEY_LOCAL_MACHINE

    try:
        with winreg.OpenKey(hive_path, reg_path, 0, winreg.KEY_READ) as registry_key:
            value, regtype = winreg.QueryValueEx(registry_key, name)

        return value, regtype
    except Exception as e0:
        return '', ''


# v0.1.5
def del_reg(hive='', reg_path='', name=''):
    if not reg_path or not name:
        return None

    if hive in [0, 1, 2, 3, 4]:
        hive_path = REG_CONSTANTS.mapping[hive]  # winreg.HKEY_CURRENT_USER or winreg.HKEY_LOCAL_MACHINE etc..
    else:
        hive_path = hive or winreg.HKEY_LOCAL_MACHINE

    try:
        with winreg.OpenKey(hive_path, reg_path, 0, winreg.KEY_ALL_ACCESS) as registry_key:
            winreg.DeleteValue(registry_key, name)
        return True
    except Exception as e0:
        return False



# reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
"""
HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch

HIVE \ PATH REG PATH 

HKCU, HKLM are 2 main hives
Reg path= "SYSTEM\CurrentControlSet\Policies\EarlyLaunch"

Sub key or just a key:  (/v)
DriverLoadPolicy


/t is rtype: 
REG_DWORD


/d is nothing but the value.


set_reg(hive=0, reg_path='', key='', value='', type_=winreg.REG_DWORD):


set_reg(1, "SYSTEM\CurrentControlSet\Policies\EarlyLaunch", "DriverLoadPolicy", 3, winreg.REG_DWORD)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f


set_reg(2, "SYSTEM\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM", "O:BAG:BAD:(A;;RC;;;BA)", winreg.REG_SZ)
"""


# rnning powershell commands from python.

"""
import subprocess

p = subprocess.Popen(
    ["powershell.exe", "Get-ADComputer " + computer_name+ " | Select-Object Name"],
    stdout=sys.stdout)

p.communicate()




# Eg:
# powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"

# Above is your powershell script, below is the list of powershell commanbd to be passed to python subvprocess
cmd = ["powershell.exe", "-command", "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"]
p = subprocess.Popen(cmd,stdout=sys.stdout)
p.communicate()

"""

# recommnended way
def powershell(cmd):
    try:
        p = subprocess.Popen(["powershell.exe"] + cmd, stdout=sys.stdout)
        p.communicate()
    except Exception as e:
        print("ewrror: ", e)
        pass

powershell([ "-command", "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"])



# not recommended way due to shell injections
def powershell2(cmd):
    try:
        p = subprocess.Popen("powershell.exe " + cmd, stdout=sys.stdout, shell=True)
        p.communicate()
    except Exception as e:
        print("ewrror: ", e)
        pass


powershell2('-command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"')

