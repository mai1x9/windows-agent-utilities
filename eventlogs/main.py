import win32evtlog
import pprint
import sys
from lxml import objectify

## Subscribes to and logs 'application' events
## To manually fire a new event, open an admin console and type: (replace 125 with any other ID that suits you)
##eventcreate.exe /L "application" /t warning /id 125 /d "This is a test warning"

##event_context can be `None` if not required, this is just to demonstrate how it works
event_context = { "info": "this object is always passed to your callback" }
##Event log source to listen to

event_source = 'System'

all_data = []


def new_logs_event_handler(reason, context, evt):
    """
      Called when new events are logged.
      reason - reason the event was logged?
      context - context the event handler was registered with
      evt - event handle
    """
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
##    substatus = xml[1][9].text
    
    event_id = xml.find(f'.//{ns}EventID').text
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
                     "source" : sourcename,
                     "eventdata" : eventdata,
                     "recordnumber" : recordnumber,
                     "eventcategory" : eventcategory,
                     "Process_Id" : process_id,
                     "Thread_Id" : thread_id
                     }
    all_data.append(json_responce)
    return print(all_data)
##    event_data = f'Time: {time_created}, Computer: {computer},Event Id: {event_id}, Channel: {channel},source: {sourcename},eventdata: {eventdata},recordnumber: {recordnumber},eventcategory: {eventcategory},Process Id: {process_id}, Thread Id: {thread_id}'
##    print(event_data)

    user_data = xml.find(f'.//{ns}UserData')
    print(user_data)
    # user_data has possible any data
    # empty line to separate logs
    print(' - ')

    # Make sure all printed text is actually printed to the console now
    sys.stdout.flush()

    return 0

## Subscribe to future events
subscription = win32evtlog.EvtSubscribe('Application', win32evtlog.EvtSubscribeToFutureEvents, None, Callback=new_logs_event_handler, Context=event_context, Query=None)
subscription2 = win32evtlog.EvtSubscribe('System'  , win32evtlog.EvtSubscribeToFutureEvents, None, Callback=new_logs_event_handler, Context=event_context, Query=None)
##subscription = win32evtlog.EvtSubscribe('Security', win32evtlog.EvtSubscribeToFutureEvents, None, Callback=new_logs_event_handler, Context=event_context, Query=None)

import win32evtlog
import win32evtlogutil
import win32security
import win32con
import winerror
import time
import datetime
import re
import string
import sys
import traceback

def date2sec(evt_date):
     '''
     This function converts dates with format
     '12/23/99 15:54:09' to seconds since 1970.
     '''

     _,month,day,_,year = evt_date.split(" ")
     month_number = datetime.datetime.strptime(month, '%b').month
     dt = datetime.datetime(year =int(year), month=int(month_number), day=int(day))
     sec=time.mktime(dt.timetuple())
##    print(sec)
     return sec

##Main program
#initialize variables
flags = win32evtlog.EVENTLOG_BACKWARDS_READ|\
		win32evtlog.EVENTLOG_SEQUENTIAL_READ
#This dict converts the event type into a human readable form
evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'EVENTLOG_AUDIT_FAILURE',\
		  win32con.EVENTLOG_AUDIT_SUCCESS:'EVENTLOG_AUDIT_SUCCESS',\
		  win32con.EVENTLOG_INFORMATION_TYPE:'EVENTLOG_INFORMATION_TYPE',\
		  win32con.EVENTLOG_WARNING_TYPE:'EVENTLOG_WARNING_TYPE',\
		  win32con.EVENTLOG_ERROR_TYPE:'EVENTLOG_ERROR_TYPE'}

def last_x_time(days=1):
     yesterday = datetime.date.today() - datetime.timedelta(days)
     print(yesterday)
     begin_sec= time.mktime((yesterday.year, yesterday.month,yesterday.day, 0, 0, 0, 0, 0, 0))
     return begin_sec


     
#open event log

def last_x_days_logs(computer="localhost",logtype="System",begin_sec = 0):
##     all_logs=[]
     
     hand=win32evtlog.OpenEventLog(computer,logtype)
##     print(logtype,' events found in the last x hours since:',begin_time)
     try:
          events=1
          while events:
               events=win32evtlog.ReadEventLog(hand,flags,0)
               for ev_obj in events:
                    the_time=ev_obj.TimeGenerated.Format() 
                    seconds=date2sec(the_time)
##                    print(seconds)
                    if(begin_sec - seconds) > 0:
                         break 
                    computer=str(ev_obj.ComputerName)
                    cat=str(ev_obj.EventCategory)
                    src=str(ev_obj.SourceName)
                    record=str(ev_obj.RecordNumber)
                    evt_id=str(winerror.HRESULT_CODE(ev_obj.EventID))
                    evt_type=str(ev_obj.EventType)
                    msg = str(win32evtlogutil.SafeFormatMessage(ev_obj, logtype))
                    json_response={"time": the_time,
                                   "computer" : computer,
                                   "sourcename" : src,
                                   "event_category" : cat,
                                   "recordnumber" : record,
                                   "event_id" : evt_id,
                                   "event_type" : evt_type,
                                   "message" : msg[0:15]
                                   }
                    all_logs.append(json_response)
                    
               if (begin_sec - seconds) > 0:
                    break
##                    return all_logs
          win32evtlog.CloseEventLog(hand) 
     except:
          print(traceback.print_exc(sys.exc_info()))
     return all_logs
begin_sec= last_x_time(0)   
y = last_x_days_logs(begin_sec=begin_sec)
print(y)



from time import sleep
print(subscription)
while 1:
     sleep(10)




