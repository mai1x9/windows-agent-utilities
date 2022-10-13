import os
import subprocess as s
s.check_output("icacls C:\pythonprograms\example /deny Everyone:(CI)(IO)(F)")
s.call("icacls C:\pythonprograms\example /deny Everyone:(CI)(IO)(F)")
s.check_output("icacls C:\pythonprograms\example /grant Everyone:(CI)(IO)(F)")
s.call("icacls C:\pythonprograms\example /grant Everyone:(CI)(IO)(F)")
