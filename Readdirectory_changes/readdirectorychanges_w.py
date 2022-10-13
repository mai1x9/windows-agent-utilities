import os
import win32file
import win32con
import threading
import queue
import traceback


q = queue.Queue()
buffer_size = 10240
recursive = True

ACTIONS ={
    1 : "Created",
    2 : "Deleted",
    3 : "Updated",
    4 : "Renamed from something",
    5 : "Renamed to something"
}
FILE_LIST_DIRECTORY =0x0001
FILE_NOTIFY_CHANGE_LAST_ACCESS =0x00000020

path_to_watch = "C:\pythonprograms"


def init():
    hDir = win32file.CreateFile(
  path_to_watch,
  FILE_LIST_DIRECTORY,
  win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
  None,
  win32con.OPEN_EXISTING,
  win32con.FILE_FLAG_BACKUP_SEMANTICS,
  None
)
    return hDir
    pass 

def readchanges(hDir,buffer_size =102400,recursive = True):
    count = 0
    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                buffer_size, # Buffer size for storing events
                recursive,  # Watch sub-directories as well
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                FILE_NOTIFY_CHANGE_LAST_ACCESS,
                None, None
            )
            print(results)
            for action, filename in results:
                q.put(os.path.join(path_to_watch, filename))
            for path in os.listdir(path_to_watch):
                if os.path.isfile(os.path.join(path_to_watch,path)):
                    count += 1
            print(count)  
        except Exception:
            traceback.print_exc()
        
hDir = init()
t = threading.Thread(target=readchanges, args=(hDir,buffer_size,recursive))
t.start()

