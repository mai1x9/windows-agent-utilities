import os
import subprocess as s
s.check_output("icacls C:\pythonprograms\example /grant Everyone:(CI)(OI)(DE)")
s.call("icacls C:\pythonprograms\example /grant Everyone:(CI)(OI)(DE)")
s.check_output("icacls C:\pythonprograms\example /grant Everyone:(CI)(OI)(DC)")
s.call("icacls C:\pythonprograms\example /grant Everyone:(CI)(OI)(DC)")

