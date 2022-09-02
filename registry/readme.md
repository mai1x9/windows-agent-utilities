REG_NOTIFY_CHANGE_NAME :  Notify the caller if a subkey is added or deleted.

REG_NOTIFY_CHANGE_LAST_SET : Notify the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.

RegOpenKey : The RegOpenKey function uses the default security access mask to open a key. If opening the key requires a different access right, the function fails,     returning ERROR_ACCESS_DENIED. An application should use the RegOpenKeyEx function to specify an access mask in this situation.

CreateEvent : Creates or opens a named or unnamed event object.To specify an access mask for the object, use the CreateEventEx function.

WaitForMultipleObjects : Waits until one or all of the specified objects are in the signaled state or the time-out interval elapses.

Output:    
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

I worked on using wifi adapter cable connecting it to device to check if adapter changes occurs or not but  i didnt get any results.
