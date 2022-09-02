REG_NOTIFY_CHANGE_NAME :  Notify the caller if a subkey is added or deleted.

REG_NOTIFY_CHANGE_LAST_SET : Notify the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.

RegOpenKey : The RegOpenKey function uses the default security access mask to open a key. If opening the key requires a different access right, the function fails,     returning ERROR_ACCESS_DENIED. An application should use the RegOpenKeyEx function to specify an access mask in this situation.

CreateEvent : Creates or opens a named or unnamed event object.To specify an access mask for the object, use the CreateEventEx function.

WaitForMultipleObjects : Waits until one or all of the specified objects are in the signaled state or the time-out interval elapses.

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
    win32api.RegCloseKey(if_key)
registry_wait()
    
output:    
C:\pythonprograms\windowsregistry>python notifychange.py
IP address info changed
IP address info changed
IP address info changed
IP address info changed
IP address info changed
IP address info changed
IP address info changed
IP address info changed

When the wifi/network is changed or if i restart network the ip address info is changed 

I worked on using wifi adapter cable connecting it to device to check if adapter changes occurs or not but unfortunately i didnt get any results.
