"""Entry point for raptr_im.exe

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
"""

import logging
import logging.handlers
import os
import sys
from PyQt4 import QtCore, QtNetwork
from PyQt4.QtCore import SIGNAL

from heliotrope import purple_base
from heliotrope import purple_server


log = logging.getLogger()
  
def main():
  handler = logging.StreamHandler()
  log.setLevel(logging.DEBUG)
    
  # Always log to file:
  handler = logging.handlers.RotatingFileHandler(
    os.path.join(purple_base.get_dataroot_dir(), 
                 purple_base.PYPURPLE_LOG_FILENAME),
    maxBytes=purple_base.LOG_SIZE_PER_FILE,
    backupCount=purple_base.LOG_FILE_COUNT)
  
  if not log.handlers:
    formatter = logging.Formatter('%(asctime)s: %(levelname)s: ' +
                                  '%(threadName)s: %(message)s',
                                  '%Y/%m/%d %H:%M:%S')
    handler.setFormatter(formatter)
    log.addHandler(handler)
  
  # Redirect stdout/stderr to the logging module
  w = purple_base.Writer().get_instance()
  sys.stdout = w
  sys.stderr = w
  
  app = QtCore.QCoreApplication(sys.argv)
  server = purple_server.PurpleServer()
  server.start()
  try:
    sys.exit(app.exec_())
  except:
    sys.exit(0)
  
  
  
if __name__ == '__main__':
  main()
