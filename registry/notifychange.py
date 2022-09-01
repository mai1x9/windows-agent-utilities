import win32api
import win32event
import win32con

def registry_wait():
    watchflags = win32api.REG_NOTIFY_CHANGE_NAME | win32api.REG_NOTIFY_CHANGE_LAST_SET
    if_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
    if_evt = win32event.CreateEvent(None, 0, 0, None)
    win32api.RegNotifyChangeKeyValue(if_key, True, watchflags, if_evt, True)
    
    dnsada_key = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters')
    dnsada_evt = win32event.CreateEvent(None, 0, 0, None)
    win32api.RegNotifyChangeKeyValue(dnsada_key, True, watchflags, dnsada_evt, True)
    while True:
        ret_code = win32event.WaitForMultipleObjects([if_evt, dnsada_evt], False, win32event.INFINITE)
        if ret_code == win32con.WAIT_OBJECT_0 + 0:
            print('IP address info changed') # do something
            win32event.ResetEvent(if_evt)
            win32api.RegNotifyChangeKeyValue(if_key, True, watchflags, if_evt, True)
        elif ret_code == win32con.WAIT_OBJECT_0 + 1:
            print('Adapter info changed') # do something else
            win32event.ResetEvent(dnsada_evt)
            win32api.RegNotifyChangeKeyValue(dnsada_key, True, watchflags, dnsada_evt, True)
        else:
            break # set a timeout in WaitForMultipleObjects above
    win32api.RegCloseKey(dnsada_key)
    win32api.RegCloseKey(if_key


                         )
registry_wait()









