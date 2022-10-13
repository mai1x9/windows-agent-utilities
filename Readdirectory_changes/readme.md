# pywin32
This is the readme for the Python for Win32 (pywin32) extensions, which provides access to many of the Windows APIs from Python.
Only Python 3 is supported. If you want Python 2 support, you want build 228.
# Binaries
By far the easiest way to use pywin32 is to grab binaries from the most recent release.
# Installing via PIP
You can install pywin32 via pip:
 pip install pywin32
If you encounter any problems when upgrading (eg, "module not found" errors or similar), you should execute:
 python Scripts/pywin32_postinstall.py -install
This will make some small attempts to cleanup older conflicting installs.
Note that if you want to use pywin32 for "system wide" features, such as registering COM objects or implementing Windows Services, then you must run that command from an elevated (ie, "Run as Administrator) command prompt.
# The specified procedure could not be found / Entry-point not found Errors?
A very common report is that people install pywin32, but many imports fail with errors similar to the above.
In almost all cases, this tends to mean there are other pywin32 DLLs installed in your system, but in a different location than the new ones. This sometimes happens in environments that come with pywin32 pre-shipped (eg, anaconda?).
The possible solutions are:
   Run the "post_install" script documented above.
   Otherwise, find and remove all other copies of pywintypesXX.dll and pythoncomXX.dll (where XX is the Python version - eg, "39").
