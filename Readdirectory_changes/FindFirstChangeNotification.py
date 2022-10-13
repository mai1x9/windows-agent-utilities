import os
import win32file
import win32event
import win32con

path_to_watch = os.path.abspath ("C:\python programs")
change_handle = win32file.FindFirstChangeNotification (
  path_to_watch,
  0,
  win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
  win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES 
)

try:
  old_path_contents = dict([(f, None) for f in os.listdir(path_to_watch)])
  while 1:
    result = win32event.WaitForSingleObject(change_handle, 500)

    # If the WaitFor... returned because of a notification (as
    #  opposed to timing out or some error) then look for the
    #  changes in the directory contents.
 
    if result == win32con.WAIT_OBJECT_0:
      new_path_contents = dict([(f, None) for f in os.listdir (path_to_watch)])
      added = [f for f in new_path_contents if not f in old_path_contents]
      deleted = [f for f in old_path_contents if not f in new_path_contents]
      if added: 
         print("Added: ", ", ".join (added))
      if deleted: 
         print("Deleted: ", ", ".join (deleted))
      old_path_contents = new_path_contents
      win32file.FindNextChangeNotification(change_handle)
finally:
  win32file.FindCloseChangeNotification(change_handle)
