import os
import subprocess as s
s.check_output("icacls C:\pythonprograms\example /deny Everyone:(OI)(IO)(F)")
s.call("icacls C:\pythonprograms\example /deny Everyone:(OI)(IO)(F)")
s.check_output("icacls C:\pythonprograms\example /grant Everyone:(OI)(IO)(F)")
s.call("icacls C:\pythonprograms\example /grant Everyone:(OI)(IO)(F)")
