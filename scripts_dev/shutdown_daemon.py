import os
import sys
import time
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(Path(__file__).parent.absolute(), '..')))

from bitchan_client import DaemonCom

daemon_com = DaemonCom()
try:
    daemon_com.shutdown_daemon()
    time.sleep(5)
    print("Success")
except Exception as err:
    print(f"Fail: {err}")
