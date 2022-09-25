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
import pprint
from lxml import objectify



    


dict_1 = {"4624":["auth","A user successfully logged on to a computer (user login time)"],
          "4625":["auth","Logon failure. A logon attempt was made with an unknown user name or a known user name with a bad password. (wrong password)"],
          "4634":["auth","The logoff process was completed for a user. (logout time)"],
          "4648":["auth","A logon was attempted using explicit credentials"],
          "4672" :["auth","Special Privileges Assigned To New Logon."],
          "1149" :["rdpsession","Network Connection connects user’s RDP client with the Windows server. (Network Connection)"],
          "4657" :["registry","A registry value was modified"],
          "4698" :["taskshcedule","A scheduled task was created."],
          "4699" :["taskshcedule","A scheduled task was deleted."],
          "4700" :["taskshcedule","A scheduled task was enabled."],
          "4701" :["taskshcedule","A scheduled task was disabled."],
          "4702":["taskshcedule","A scheduled task was updated."],
          "1000" :["defender","An antimalware scan started."],
          "1001" :["defender","An antimalware scan finished."],
          "1002":["defender","An antimalware scan was stopped before it finished."],
          "1005":["defender","An antimalware scan failed."],
          "1006":["defender","The antimalware engine found malware or other potentially unwanted software."],
          "1008":["defender","The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed."],
          "1015":["defender","The antimalware platform detected suspicious behavior."],
          "1116":["defender","The antimalware platform detected malware or other potentially unwanted software."],
          "1118":["defender","The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed."],
          "1119":["defender","The antimalware platform encountered a critical error when trying to act on malware or other potentially unwanted software. "],
          "2001":["defender","The security intelligence update failed."],
          "2003":["defender","The antimalware engine update failed."],
          "2006":["defender","The platform update failed."],
          "2040":["defender","Antimalware support for this operating system version will soon end."],
          "2041":["defender","Antimalware support for this operating system has ended. You must upgrade the operating system for continued support."],
          "2042":["defender","Antimalware support for this operating system has ended. You must upgrade the operating system for continued support."],
          "5008":["defender","The antimalware engine encountered an error and failed."],
          "5010":["defender","Scanning for malware and other potentially unwanted software is disabled. "],
          "5012":["defender","Scanning for viruses is disabled."],
          "5100":["defender","The antimalware platform will expire soon."],
          "5101":["defender","The antimalware platform is expired."],
          "4608":["system","Windows is starting up"],
          "5382":["system","Vault credentials were read"],
          "4616":["system","The system time was changed."],
          "5059":["system"," Key migration operation"],
          "5379":["system","Credential Manager credentials were read"],
          "5381":["system","Vault credentials were read"],
          "5058":["system","Key file operation"],
          "5061":["system","Cryptographic operation"],
          "5024":["system","The Windows Firewall Service has started successfully"],
          "5033":["system","The Windows Firewall Driver has started successfully"],
          "4946":["firewall","A change has been made to Windows Firewall exception list. A rule was added"],
          "4947":["firewall","A change has been made to Windows Firewall exception list. A rule was modified"],
          "4948":["firewall","A change has been made to Windows Firewall exception list. A rule was deleted"],
          "4950":["firewall","A Windows Firewall setting has changed"],
          "5025":["firewall","The Windows Firewall Service has been stopped"],
          "5031":["firewall","The Windows Firewall Service blocked an application from accepting incoming connections on the network"],
          
          "4660":["fileaccess","An Object Was Deleted"],
          "4663":["fileaccess","Attempt made to access object"],
          "4670":["fileaccess","Permissions on an object were changed"],
          "5136":["fileaccess","A directory service object was modified."]
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

server = 'localhost' # name of the target computer to get event logs
logtype = 'Application' # 'Application' # 'Security' 'System'
event_context = { "info": "this object is always passed to your callback" }


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



def main(reason, context, evt):
    max_log_level =16
    count = 0
    hand = win32evtlog.OpenEventLog(server,logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    # Just print some information about the event
    print ('reason', reason, 'context', context, 'event handle', evt)
    # Render event to xml, maybe there's a way of getting an object but I didn't find it
    xml_content = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
    print('Rendered event:', xml_content, type(xml_content),type(evt),dir(evt))
    import xml.etree.ElementTree as ET
    xml = ET.fromstring(xml_content)
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    print(xml)


    last_x_days = 1
    yesterday = datetime.date.today() - datetime.timedelta(last_x_days)

    begin_sec= time.mktime((yesterday.year, yesterday.month,yesterday.day, 0, 0, 0, 0, 0, 0))
 
    begin_time=time.strftime('%H:%M:%S  ',time.localtime(begin_sec))

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
                    continue 
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
                continue
        if events:
            for xml in events:
                event_id = xml.find(f'.//{ns}EventID')
                computer = xml.find(f'.//{ns}Computer').text
                channel = xml.find(f'.//{ns}Channel').text
                execution = xml.find(f'.//{ns}Execution')
                process_id = execution.get('ProcessID')
                thread_id = execution.get('ThreadID')
                level = xml.find(f'.//{ns}Level').text
                time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
                event_data = f'Time: {time_created}, Computer: {computer}, Event Id: {event_id}, Channel: {channel}, Process Id: {process_id}, Thread Id: {thread_id}'
##                    print(event_data)
                user_data = xml.find(f'.//{ns}UserData')

    print(" - ")
    sys.stdout.flush()
    return 0



subscription = win32evtlog.EvtSubscribe(logtype, win32evtlog.EvtSubscribeToFutureEvents, None, Callback=main, Context=event_context, Query=None)
from time import sleep
print(subscription)
while 1:
     sleep(10)



##main()































