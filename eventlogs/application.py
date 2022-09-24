import win32evtlog # requires pywin32 pre-installed
import re
import traceback
import string
import sys
import win32api
import winerror
import win32evtlogutil
import win32security
import win32con
import time
import datetime


    
server = 'localhost' # name of the target computer to get event logs
logtype = 'Application' # 'Application' # 'Security' 'System'


dict_1 = {"8194":["system restore","Access is Denied"],
          "8216":["system restore","Unable to write to map cache file"],
          "8300":["system restore","This event indicates that the Active Directory Connector (ADC) is unable to find the HOME SERVER attribute"],
          "8301":["system restore","While replicating a connector object from the Exchange 5.5 directory to Active Directory, Active Directory Connector (ADC) was not able to determine the correct target routing group for the connector, and failed to replicate the object."],
          "8302":["system restore","It will be retried after the checking interval 600 seconds. "],
          "6416":["usb logs","A new external device was recognized by the System"],
	  "6419":["usb logs","This event is generated if a user attempts to disable a device on the system"],
	  "6420":["usb logs","A device was disabled"],
	  "6421":["usb logs","A request was made to enable a device"],
	  "6422":["usb logs","This event is generated when a user successfully enables a device"],
	  "6423":["usb logs","The installation of this device is forbidden by system policy."],
	  "6424":["usb logs","The installation of this device was allowed, after having previously been forbidden by policy."],
          "2003":["usb logs","This event is logged when a Windows Firewall setting in the profile has changed."],
          "2004":["usb logs","This event is logged when windows successfully diagnosed a low virtual memory condition."],
          "2006":["usb logs","This event is logged when unable to read Server Queue performance data from the Server service."],
          "2010":["usb logs","This event is logged when Network profile changed on an interface"],
          "2100":["usb logs","Entered the TDICollectPerformanceData routine"],
          "2101":["usb logs","A Null TDI device handle was encountered in the Collect routine. The TDI file was probably not opened in the Open routine"],
          "2102":["usb logs","A USB mass storage device yields a lot of artifacts when connected to a system"],
          "2103":["usb logs","The Active Directory database has been restored using an unsupported restoration procedure"],
          "2105":["usb logs","This event is logged when successful data request from the TDI device."],
          "2106":["usb logs","The buffer passed to CollectTDIPerformanceData was too small to receive the data."],
          "21":["rdp logs","This event is logged when the event logging service encountered a configuration-related error for channel."],
          "23":["rdp logs","This event is logged when the event logging service encountered an error while initializing logging resources for channel"],
          "24":["rdp logs","This event is logged when no valid response has been received from domain controller after 8 attempts to contact it."],
          "25":["rdp logs","This event is logged when Automatic Updates Agent failed to check for updates with error."],
          "39":["rdp logs","Network connection is identified as normal."],
          "40":["rdp logs","The event logging service encountered an error when attempting to apply one or more policy settings."],
          "4624":["rdp logs","An account was successfully logged on."],
          "1000":["windows defender","Corrupted system files"],
          "1001":["windows defender","Windows Error Reporting"],
          "1002":["windows defender","Application Hang error in Windows "],
          "1006":["windows defender","The processing of Group Policy failed"],
          "1007":["windows defender","This event is logged when the world wide web publishing service did not register the url"],
          "1008":["windows defender","System is unable to find the file specified on the particular operation"],
          "1009":["windows defender","Errors flood Application log for lagged database copies in Exchange Server"],
          "1011":["windows defender","The Microsoft Service for DRDA cannot connect to SQL Server."],
          "1013":["windows defender","Windows Search Service stopped normally."],
          "1015":["windows defender","This event is logged when critical system process failed with status code."],
          "1116":["windows defender","The antimalware platform detected malware or other potentially unwanted software"],
          "1117":["windows defender","The antimalware platform performed an action to protect your system from malware or other potentially unwanted software."],
          "1118":["windows defender","The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed."],
          "1119":["windows defender","The antimalware platform encountered a critical error when trying to take action on malware or other potentially unwanted software. There are more details in the event message."],
          "1120":["windows defender","Microsoft Defender Antivirus has deduced the hashes for a threat resource."],
          "2000":["windows defender","The antimalware definitions updated successfully."],
          "2001":["windows defender","The security intelligence update failed."],
          "2002":["windows defender","The antimalware engine updated successfully."],
          "2003":["windows defender","The antimalware engine update failed."],
          "2004":["windows defender","There was a problem loading antimalware definitions. The antimalware engine will attempt to load the last-known good set of definitions."],
          "2007":["windows defender","The platform will soon be out of date. Download the latest platform to maintain up-to-date protection."],
          "3000":["windows defender","This event is logged when real time protection agents have started."],
          "5001":["windows defender","This event is logged when real time protection scanning was disabled in windows defender."],
          "5004":["windows defender","This event is logged when real time protection agent configuration has changed in Windows defender."],

         }

dict_2={1 :"Error_type",
        2 :"Warning_type",
        4 :"Information_type",
        8 :"Success_audit",
        16:"Success_failure"
        }

"""
    @Event Levels:
        Error_type = 1
        Warning_type = 2
        Information_type = 4
        Success_audit = 8
        Success_failure =16
"""


def date2sec(evt_date):
    '''
    This function converts dates with format
    '12/23/99 15:54:09' to seconds since 1970.
    '''
##    print(evt_date)
    _,month,day,_,year = evt_date.split(" ")
    month_number = datetime.datetime.strptime(month, '%b').month
    dt = datetime.datetime(year =int(year), month=int(month_number), day=int(day))
    sec=time.mktime(dt.timetuple())
##    print(sec)
    return sec



def main():
    max_log_level =16
    count = 0
    hand = win32evtlog.OpenEventLog(server,logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    last_x_days = 5
    yesterday = datetime.date.today() - datetime.timedelta(last_x_days)
    ##print(type(yesterday))
    begin_sec= time.mktime((yesterday.year, yesterday.month,yesterday.day, 0, 0, 0, 0, 0, 0))
    ##print(begin_sec)
    begin_time=time.strftime('%H:%M:%S  ',time.localtime(begin_sec))
    ##print(begin_time)
    #open event log 
    print(logtype,' events found in the last 8 hours since:',begin_time)
    while True:
        events = win32evtlog.ReadEventLog(hand, flags,0)
        all_data = []
        if events:
            for event in events:
                count+= 1
                the_time=event.TimeGenerated.Format() 
                seconds=date2sec(the_time)
                if(begin_sec - seconds) > 0:
                    break 
                evt_id=str(winerror.HRESULT_CODE(event.EventID))
                data = event.StringInserts
                if data:
                    msg=str(win32evtlogutil.SafeFormatMessage(event, logtype))
                if event.EventType > max_log_level:
                    continue 
                if evt_id in dict_1:
                    json_responce = {"Count" : count,
                                     "Event_Id" : event.EventID,
                                     "source" : event.SourceName,
                                     "eventdata" : data,
                                     "recordnumber" : event.RecordNumber,
                                     "Level" : event.EventType,
                                     "message" : msg,
                                     "log_category" : dict_1[evt_id][0],
                                     "Level_name" : dict_2[event.EventType],
                                     "Time" : the_time
                                    }
                    all_data.append(json_responce)
                    print(all_data)
            if (begin_sec - seconds) > 0:
                break
main()





































