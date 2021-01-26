import sys
import os
from eopx_2232h import eopx

os.chdir('c:\\program files\\enocean\\dolphinview')
sys.argv[0] = 'C:\\Program Files\\EnOcean\\DolphinView\\DolphinView.exe'
app = eopx.EOPX(sys.argv)
app.run()
