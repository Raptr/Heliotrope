"""Python Purple base class.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
"""

import locale
import logging
import os
import pickle
import struct
import sys
from PyQt4 import QtCore, QtNetwork
from PyQt4.QtCore import SIGNAL

log = logging.getLogger()
PACKET_LEN = struct.calcsize('H')  # 2 bytes
writer_instance = None

# Various constants
PYPURPLE_UNIQUE_KEY = 'pypurple-single-instance-check'
SHARED_MEMORY_SIZE_BYTES = 10240  # 10KB
PYPURPLE_LOG_FILENAME = 'raptr_im.log'
LOG_SIZE_PER_FILE = 1024*1024*10  # 10MB
LOG_FILE_COUNT = 5


class Writer:
  def __init__(self):
    # Remember whether anything has been written to stdout/stderr
    self.written = False
    
  def get_instance(self):
    """Return a singleton instance of this class"""
    global writer_instance
    if writer_instance is None:
      writer_instance = Writer()
    return writer_instance
    
  def write(self, message):
    self.written = True
    log.error(message)


class PurpleBaseRpc:
  def __init__(self):
    # Temporary variables to handle partially read messages
    self.is_partial_message = False
    self.previous_packet_len = 0
    self.msg_buffer = ''
    
    # Messages in the outgoing queue
    self.messages = []
    self.messages_lock = QtCore.QMutex()
    
    # Timeout in reading/writing from/to named pipe
    self.timeout = 2000
    
  def receiveMessage(self):
    """Parse incoming message from local socket.
    Returns:
      List of messages
    """
    bytes_available = self.local_socket.bytesAvailable()
    bytes_read = 0
    messages = []
    while bytes_read < bytes_available:
      if not self.is_partial_message:
        # Parse complete message
        if self.local_socket.peek(PACKET_LEN).length() < PACKET_LEN:
          log.debug('PurpleBaseRpc::receiveMessage(): ' + 
                    'Fewer than %d bytes available to read.' % PACKET_LEN)
          return messages
          
        msg_bytes = self.local_socket.read(PACKET_LEN)
        bytes_read += len(msg_bytes)
        packet_len = struct.unpack('H', msg_bytes)[0]
        msg_bytes = self.local_socket.read(packet_len)
        bytes_read += len(msg_bytes)
      else:
        # Reassemble partial message from previous round.
        partial_packet_len = self.previous_packet_len - len(self.msg_buffer)
        msg_bytes = self.local_socket.read(partial_packet_len)
        bytes_read += len(msg_bytes)
        packet_len = self.previous_packet_len
        msg_bytes = self.msg_buffer + msg_bytes
        self.msg_buffer = ''
      
      if len(msg_bytes) == packet_len:
        # Received complete packet
        self.is_partial_message = False
        self.msg_buffer = ''
      else:
        # Received partial packet
        self.is_partial_message = True
        self.msg_buffer += msg_bytes
        self.previous_packet_len = packet_len
        return messages

      message = pickle.loads(msg_bytes)
      messages.append(message)
    
    return messages
  
  def resetMessages(self):
    """Reset the message queue"""
    self.messages_lock.lock()
    try:
      self.messages = []
    finally:
      self.messages_lock.unlock()
  
  def queueMessage(self, message):
    """Place outgoing message onto the queue"""
    self.messages_lock.lock()
    try:
      self.messages.append(message)
    finally:
      self.messages_lock.unlock()
      
  def sendMessage(self):
    """Send message via the local_socket."""
    self.shared_memory.lock()
    try:
      self.messages_lock.lock()
      try:
        while self.messages:
          msg = self.messages.pop(0)
          if type(msg) is dict:
            if msg.has_key('func') and msg['func'] == 'login':
              log.debug('PurpleBaseRpc::sendMessage(): ' + 
                        'Sending login to account: %s' % msg['args'][0])
            elif msg.has_key('callback') and msg.has_key('msg'):
              log.debug('PurpleBaseRpc::sendMessage(): ' +
                        'Sending callback: %s: %s' % 
                        (msg['callback'], msg['msg']))
          else:
            log.debug('PurpleBaseRpc::sendMessage(): ' +
                      'Sending msg=%s' % msg)
          msg_bytes = pickle.dumps(msg, pickle.HIGHEST_PROTOCOL)
          msg_len = len(msg_bytes)
          packet = struct.pack('H', msg_len)
          self.local_socket.write(packet)
          self.local_socket.write(msg_bytes)
        self.messages = []
      finally:
        self.messages_lock.unlock()
    finally:
      self.shared_memory.unlock()
      
    if not self.local_socket.waitForBytesWritten(self.timeout):
      log.error('PurpleBaseRpc::sendMessage(): Failed to write: %s' %
                self.local_socket.errorString().toLatin1())
      return


def get_dataroot_dir():
  """Return the directory where all data files are stored"""
  if sys.platform == 'win32':
    if not os.environ.has_key('APPDATA'):
      os.environ['APPDATA'] = os.path.join(os.environ['USERPROFILE'], 
                                           'Application data')
    dir = os.path.join(os.environ['APPDATA'], 'Raptr')
  elif sys.platform == 'darwin':
    dir = os.path.join(os.environ['HOME'],
                       'Library', 'Application Support', 'Raptr')
  else:
    raise NotImplementedError, 'Unsupport platform'

  if not os.path.isdir(dir):
    try:
      os.makedirs(dir)
    except IOError, e:
      log.error('Unable to create %s: %s' % (dir, e))

  encoding = locale.getpreferredencoding()
  if not encoding:
    encoding = 'utf-8'
  return unicode(dir, encoding)
