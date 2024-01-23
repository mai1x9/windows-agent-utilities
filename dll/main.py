import os
import win32con
import win32api
import win32process
import win32security
import collections

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

def adjust_privilege(name, attr=win32security.SE_PRIVILEGE_ENABLED):
    if isinstance(name, str):
        state = (win32security.LookupPrivilegeValue(None, name), attr)
    else:
        state = name
    hToken = win32security.OpenProcessToken(win32process.GetCurrentProcess(),
                win32security.TOKEN_ALL_ACCESS)
    return win32security.AdjustTokenPrivileges(hToken, False, [state])

def get_process_modules(hProcess):
    imagepath = win32process.GetModuleFileNameEx(hProcess, None)
    imagepath_upper = imagepath.upper()
    modules = []
    for hModule in win32process.EnumProcessModulesEx(hProcess,
                        win32process.LIST_MODULES_ALL):
        modulepath = win32process.GetModuleFileNameEx(hProcess, hModule)
        if modulepath.upper() != imagepath_upper:
            modules.append(modulepath)
    return imagepath, sorted(modules)

Process = collections.namedtuple('Process', 'name path pid modules')

def list_processes():
    prev_state = adjust_privilege(win32security.SE_DEBUG_NAME)
    try:
        for pid in win32process.EnumProcesses():
            hProcess = None
            path = ''
            modules = []
            if pid == 0:
                name = 'System Idle Process'
            elif pid == 4:
                name = 'System'
            else:
                try:
                    hProcess = win32api.OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION |
                        win32con.PROCESS_VM_READ,
                        False, pid)
                except win32api.error:
                    try:
                        hProcess = win32api.OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION,
                            False, pid)
                    except win32api.error as e:
                        pass
                if hProcess:
                    try:
                        path, modules = get_process_modules(hProcess)
                    except win32process.error:
                        pass
                name = os.path.basename(path)
            yield Process(name, path, pid, modules)
    finally:
        if prev_state:
            adjust_privilege(prev_state[0])

def main():
    for process in list_processes():
        print(f"Process Name: {process.name}")
        print(f"Path: {process.path}")
        print(f"PID: {process.pid}")
        print(f"Modules: {process.modules}")
        print("-------------------------------")

if __name__ == "__main__":
    main()
