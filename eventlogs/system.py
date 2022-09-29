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



dict_1 = {"1" :["process creation","The system time has changed"],
          "42":["The system is entering sleep"],
          "44":["windows defender","Windows Update Service started downloading an update"],
          "43":["windows defender","Installation Started Windows Update or Definition Update for Windows Defender started"],
          "19":["windows defender","Installation Successful Windows update or Definition Update for Windows Defender completed successfully"],
          "20":["windows defender","installation failed"],
          "26":["systemlog","This event is logged when Automatic Updates Agent sucessfully found updates."],
          "8194":["systemrestore","create system restore"],
          "6008":["systemlog","The previous system shutdown at Time on Date was unexpected"],
          "6009":["systemlog","restart the system"],
          "1074":["systemlog","System has been shutdown by a process/user."],
          "1001":["systemlog","Memory dump performed"],
          "4000":["networking","The DNS server was unable to open Active Directory."],
          "4001":["networking","This event is logged when the DNS server was unable to open zone in the Active Directory."],
          "4003":["networking","The Windows logon process has failed to switch the desktop"],
          "4377":["networking","This event gets generated when a system or user process installs a Microsoft hotfix."],
          "6100":["networking","A uniprocessor-specific driver was loaded on a multiprocessor system. The driver could not load."],
          "6006":["systemlog","The event is logged at boot time noting that the Event Log service was stopped."],
          "6013":["systemlog","System uptime"],
          "100":["systemlog","Windows has started up and degradation has been detected."],
          "20001":["usb log","The device driver installed successfully"],
          "20003":["usb log","The message provides the service name of the service being installed and the error code with which the service install process exits."],
          "24576":["wpd log","Restart the chat server. If you have extensions installed, uninstall the extensions and contact the extension vendor."],
          "24577":["wpd log","This event is logged when Encryption of volume started."],
          "24578":["wpd log","This event is logged when Encryption of volume stopped."],
          "24579":["wpd log"," This event is logged when Encryption of volume completed."]
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
logtype = 'System' # 'Application' # 'Security' 'System'
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



def main():
    max_log_level =16
    count = 0
    hand = win32evtlog.OpenEventLog(server,logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    last_x_days = 1
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
                    json_responce = {"time" : event.TimeGenerated,
                                     "Count" : count,
                                     "Event_Id" : event.EventID,
                                     "source" : event.SourceName,
                                     "eventdata" : data,
                                     "recordnumber" : event.RecordNumber,
                                     "Level" : event.EventType,
                                     "message" : msg,
                                     "log_category" : dict_1[evt_id][0],
                                     "Level_name" : dict_2[event.EventType]
                                    }
                    all_data.append(json_responce)
                    print(all_data)
            if (begin_sec - seconds) > 0:
                break
main()



def new_log_events(reason, context, evt):
    """
      Called when new events are logged.
      reason - reason the event was logged?
      context - context the event handler was registered with
      evt - event handle
    """
    data=[]
    # Just print some information about the event
    print ('reason', reason, 'context', context, 'event handle', evt)
    # Render event to xml, maybe there's a way of getting an object but I didn't find it
    xml_content = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
    print('Rendered event:', xml_content, type(xml_content),type(evt),dir(evt))


    
    import xml.etree.ElementTree as ET
    xml = ET.fromstring(xml_content)

    # xml namespace, root element has a xmlns definition, so we have to use the namespace
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    print(xml)
    
    event_id = xml.find(f'.//{ns}EventID')
    computer = xml.find(f'.//{ns}Computer').text
    channel = xml.find(f'.//{ns}Channel').text
##    sourcename = xml.find(f'.//{ns}SourceName')
    eventdata = xml.find(f'.//{ns}EventData').text
    recordnumber =  xml.find(f'.//{ns}RecordNumber')
    eventcategory = xml.find(f'.//{ns}EventCategory')
    sourcename = xml.find(f'.//{ns}SourceName')
    execution = xml.find(f'.//{ns}Execution')
    process_id = execution.get('ProcessID')
    thread_id = execution.get('ThreadID')
    time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
    data_name = xml.findall('.//EventData')
    #substatus = data_name.get('Data')
    #print(substatus)
    json_responce = {"time" : time_created,
                     "computer" : computer,
                     "Event_Id" : event_id,
                     "Channel" : channel,
                     "execution": execution,
                     "source" : sourcename,
                     "eventdata" : eventdata,
                     "recordnumber" : recordnumber,
                     "eventcategory" : eventcategory,
                     "Process_Id" : process_id,
                     "Thread_Id" : thread_id,
                     "data" : data_name
                     }
    data.append(json_responce)
    return print(data)


    user_data = xml.find(f'.//{ns}UserData')
    print(user_data)
    # user_data has possible any data
    # empty line to separate logs
    print(' - ')

    # Make sure all printed text is actually printed to the console now
    sys.stdout.flush()

    return 0

## Subscribe to future events
subscription = win32evtlog.EvtSubscribe(logtype , win32evtlog.EvtSubscribeToFutureEvents, None, Callback=new_log_events, Context=event_context, Query=None)
from time import sleep
print(subscription)
while 1:
     sleep(10)


































