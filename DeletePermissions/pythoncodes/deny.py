import os
import subprocess as s
s.check_output("icacls C:\pythonprograms\example /deny Everyone:(CI)(OI)(DE)")
s.call("icacls C:\pythonprograms\example /deny Everyone:(CI)(OI)(DE)")



