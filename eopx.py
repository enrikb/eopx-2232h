import sys
import os
from eopx_2232h import eopx

os.chdir('C:\\Program Files\\EnOcean\\DolphinStudio')
sys.argv[0] = 'C:\\Program Files\\EnOcean\\DolphinStudio\\eopx.exe'
app = eopx.EOPX(sys.argv)
app.run()
