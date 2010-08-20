"""Python Purple Client class.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
"""

import ctypes
import ctypes.util
import logging
import pickle
import struct
import subprocess
import sys
from PyQt4 import QtCore, QtNetwork
from PyQt4.QtCore import SIGNAL

from heliotrope import purple_base
from heliotrope import pypurple

log = logging.getLogger()
PACKET_LEN = struct.calcsize('H')  # 2 bytes
CLIB = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))


class PurpleClient(QtCore.QThread, purple_base.PurpleBaseRpc):
  """Python Purple Client"""
  def __init__(self):
    QtCore.QThread.__init__(self)
    purple_base.PurpleBaseRpc.__init__(self)
    self.vars = vars
    self.unique_key = purple_base.PYPURPLE_UNIQUE_KEY
    self.shared_memory = QtCore.QSharedMemory(self.unique_key)
    self.shared_data = {}
    self.blocking_sleep_ms = 100
    self.local_server = None
    self.local_socket = None

    # Account connection status (values have to match heliotrope/pypurple.py)
    # TODO(koyao): Merge these values into a common base class.
    self.CONNECTING = 0
    self.CONNECTED = 1
    self.DISCONNECTING = 2
    self.DISCONNECTED = 3
    self.ERROR = 4
    self.state = self.DISCONNECTED
        
    if self.shared_memory.attach():
      result = self.killServer()
      if not result:
        log.debug('PurpleClient::__init__(): Failed to kill server')
        self.state = self.ERROR
        return
      
    if not self.shared_memory.create(purple_base.SHARED_MEMORY_SIZE_BYTES,
                                     QtCore.QSharedMemory.ReadWrite):
      log.error('Unable to create singleton instance of PurpleClient')
      self.state = self.ERROR
      return
      
    # Initialize shared memory with empty data
    data_bytes = pickle.dumps({}, pickle.HIGHEST_PROTOCOL)
    data_len = len(data_bytes)
    self.shared_memory.lock()
    try:
      CLIB.memcpy(int(self.shared_memory.data()), data_bytes, data_len)
    finally:
      self.shared_memory.unlock()

    # IMHandler callbacks are invoked on a separate thread, to avoid deadlock.
    self.imhandler_callbacks = []
    self.imhandler_callbacks_lock = QtCore.QMutex()
    self.callback_thread = PurpleClientCallbackThread(self)
    self.callback_thread.start()
    
  def receiveNewConnection(self):
    """Parse message from a new connection."""
    self.local_socket = self.local_server.nextPendingConnection()
    if not self.local_socket.waitForReadyRead(self.timeout):
      log.error('PurpleClient::receiveNewConnection(): Failed to read: %s' %
                self.local_socket.errorString().toLatin1())
      return
    
    packet_len = struct.unpack('H', self.local_socket.read(PACKET_LEN))[0]
    msg_bytes = self.local_socket.read(packet_len)
    message = pickle.loads(msg_bytes)
    
    log.debug('PurpleClient::receiveNewConnection(): message=%s' % message)
    if message == 'HELLO':
      self.state = self.CONNECTED
      
    self.connect(self.local_socket, SIGNAL('readyRead()'), self.receiveMessage,
                 QtCore.Qt.DirectConnection)
    
  def receiveMessage(self):
    """Parse incoming message from PurpleServer"""
    self.readSharedMemory()
    messages = purple_base.PurpleBaseRpc.receiveMessage(self)
    self.imhandler_callbacks_lock.lock()
    try:
      self.imhandler_callbacks += messages
    finally:
      self.imhandler_callbacks_lock.unlock()
    
  def sendMessage(self):
    """Send message back to PurpleClient"""
    if not self.local_socket or not self.messages:
      return
    purple_base.PurpleBaseRpc.sendMessage(self)      
      
  def killServer(self):
    """Attempt to kill the running raptr_im.exe process.
    Returns:
      True, if the process was killed
      False, otherwise
    """
    # TODO(koyao): Implement this, if deemed necessary.
    return False
    
  def launchServer(self):
    log.info('Launching PurpleServer')
    if sys.argv[0].endswith('.py'):
      subprocess.Popen('python heliotrope/raptr_im.py', close_fds=True)
    else:
      subprocess.Popen('raptr_im.exe', close_fds=True)
   
  def register_callback(self, callback, func):
    """Route callback registration to the PurpleCallbackThread thread
    Arguments:
      callback: String,
      func: Python callable
    """
    self.callback_thread.register_callback(callback, func)
    
  def run(self):
    log.debug('PurpleClient::run(): Starting...')

    # Setup local server
    self.local_server = QtNetwork.QLocalServer()
    result = self.local_server.listen(self.unique_key)
    if not result:
      log.error('Failed to listen: %s, %s' % (
        self.local_server.errorString(), self.local_server.fullServerName()))
      self.state = self.ERROR
      return
    log.debug('PurpleClient: Listening on: %s' %
              self.local_server.fullServerName())
    self.state = self.CONNECTING
    self.connect(self.local_server, SIGNAL('newConnection()'),
                 self.receiveNewConnection, QtCore.Qt.DirectConnection)
        
    # Send messages in a separate thread
    self.queued_message_timer = QtCore.QTimer()                 
    self.connect(self.queued_message_timer, SIGNAL('timeout()'),
                 self.sendMessage, QtCore.Qt.DirectConnection)
    self.queued_message_timer.start(500)

    # Update shared memory every now and then
    self.shared_memory_timer = QtCore.QTimer()
    self.connect(self.shared_memory_timer, SIGNAL('timeout()'),
                 self.readSharedMemory, QtCore.Qt.DirectConnection)
    self.shared_memory_timer.start(1000)                 
    
    self.launchServer()
    
    message = {
      'func': 'start',
      'args': None,
    }
    self.queueMessage(message)
    self.exec_()
    
  def readSharedMemory(self):
    """Read shared memory"""
    self.shared_memory.lock()
    try:
      data = self.shared_memory.data()
      self.shared_data = pickle.loads(data.asstring())
    finally:
      self.shared_memory.unlock()
    
# ----- Start of RPC functions
  
  def enable_debug(self, flag):
    """Send RPC"""
    message = {
      'func': 'enable_debug',
      'args': [flag],
    }
    self.queueMessage(message)
    
  def set_avatar_dir(self, dir):
    """Send RPC"""
    message = {
      'func': 'set_avatar_dir',
      'args': [dir],
    }
    self.queueMessage(message)
    
  def set_plugin_dir(self, dir):
    """Send RPC"""
    message = {
      'func': 'set_plugin_dir',
      'args': [dir],
    }
    self.queueMessage(message)
    
  def set_ca_cert_dirs(self, dirs):
    """Send RPC"""
    message = {
      'func': 'set_ca_cert_dirs',
      'args': [dirs],
    }
    self.queueMessage(message)
    
  def set_config_dir(self, dir):
    """Send RPC"""
    message = {
      'func': 'set_config_dir',
      'args': [dir],
    }
    self.queueMessage(message)
   
  def purple_blist_load(self):
    """Send RPC"""
    message = {
      'func': 'purple_blist_load',
      'args': None
    }
    self.queueMessage(message)
  
  def login(self, account, password, server):
    """RPC"""
    message = {
      'func': 'login',
      'args': [account, password, server],
    }
    self.queueMessage(message)
  
  def is_connected(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    if not self.shared_data['account_status'].has_key(account):
      return False
    return self.shared_data['account_status'][account] == self.CONNECTED
  
  def is_connecting(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    if not self.shared_data['account_status'].has_key(account):
      return False
    return self.shared_data['account_status'][account] == self.CONNECTING

  def is_disconnecting(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    if not self.shared_data['account_status'].has_key(account):
      return False
    return self.shared_data['account_status'][account] == self.DISCONNECTING

  def is_disconnected(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    if not self.shared_data['account_status'].has_key(account):
      return False
    return self.shared_data['account_status'][account] == self.DISCONNECTED
    
  def has_error(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    if not self.shared_data['account_status'].has_key(account):
      return False
    return self.shared_data['account_status'][account] == self.ERROR

  def has_status(self, account):
    """Check shared memory for account status"""
    if not self.shared_data.has_key('account_status'):
      return False
    return self.shared_data['account_status'].has_key(account)
    
  def get_accounts(self):
    """Return list of accounts"""
    if not self.shared_data.has_key('account_status'):
      return []
    return self.shared_data['account_status']
    
  def get_errmsg(self, account):
    """Return account error message from shared memory"""
    if not self.shared_data.has_key('account_errmsg'):
      return ''
    if not self.shared_data['account_errmsg'].has_key(account):
      return ''
    return self.shared_data['account_errmsg'][account]
 
  def set_custom_status(self, presence, status):
    """RPC"""
    message = {
      'func': 'set_custom_status',
      'args': [presence, status],
    }
    self.queueMessage(message)
  
  def send_message(self, account, recipient, message):
    """RPC"""
    message = {
      'func': 'send_message',
      'args': [account, recipient, message],
    }
    self.queueMessage(message)
    
  def send_typing_notification(self, account, recipient, first):
    """RPC"""
    message = {
      'func': 'send_typing_notification',
      'args': [account, recipient, first],
    }
    self.queueMessage(message)
    
  def send_typing_stopped_notification(self, account, recipient):
    """RPC"""
    message = {
      'func': 'send_typing_stopped_notification',
      'args': [account, recipient],
    }
    self.queueMessage(message)

  def disconnect(self):
    """RPC.  Note that this shadows the QObject.disconnect() function"""
    message = {
      'func': 'disconnect',
      'args': None,
    }
    self.queueMessage(message)

  def reset_buddy_list(self):
    """RPC"""
    message = {
      'func': 'reset_buddy_list',
      'args': None,
    }
    self.queueMessage(message)
  
  def offline(self, account):
    """RPC"""
    message = {
      'func': 'offline',
      'args': [account],
    }
    self.queueMessage(message)
  
  def remove_buddy(self, account, buddy):
    """RPC"""
    message = {
      'func': 'remove_buddy',
      'args': [account, buddy],
    }
    self.queueMessage(message)
    
  def add_buddy(self, account, buddy, group="Buddies", alias=None):
    """RPC"""
    message = {
      'func': 'add_buddy',
      'args': [account, buddy, group, alias],
    }
    self.queueMessage(message)
    
  def accept_request(self, account, buddy):
    """RPC"""
    message = {
      'func': 'accept_request',
      'args': [account, buddy],
    }
    self.queueMessage(message)
    
  def deny_request(self, account, buddy):
    """RPC"""
    message = {
      'func': 'deny_request',
      'args': [account, buddy],
    }
    self.queueMessage(message)
    
  def rename_buddy(self, account, buddy, name):
    """RPC"""
    message = {
      'func': 'rename_buddy',
      'args': [account, buddy, name],
    }
    self.queueMessage(message)
  
  def list_transfers(self):
    """Return list of file transfers from shared memory."""
    if not self.shared_data.has_key('transfers'):
      return []
    return self.shared_data['transfers']
    
  def send_file(self, account, buddy, local_filename):
    """RPC"""
    message = {
      'func': 'send_file',
      'args': [account, buddy, local_filename],
    }
    self.queueMessage(message)
    
  def cancel_transfer(self, account, username, filename, local_filename):
    """RPC"""
    message = {
      'func': 'cancel_transfer',
      'args': [account, username, filename, local_filename],
    }
    self.queueMessage(message)
    
   
class PurpleClientCallbackThread(QtCore.QThread):
  def __init__(self, parent):
    QtCore.QThread.__init__(self, parent)
    self.parent = parent
    
    # Callbacks
    self.callbacks = {
      'buddy-typing': [],
      'buddy-typing-stopped': [],
      'buddy-typed': [],
      'buddy-signed-off': [],
      'buddy-signed-on': [],
      'buddy-status-changed': [],
      'blist-node-aliased': [],
      'received-im-msg': [],
      'request-authorization': [],
      'signed-on': [],
      'signed-off': [],
      'signing-on': [],
      'signing-off': [],
      'connection-error': [],
      'buddy-icon-changed': [],
      'buddy-added': [],
      'displaying-userinfo': [],
      'file-recv-request': [],
      'file-recv-accept': [],
      'file-recv-start': [],
      'file-recv-cancel': [],
      'file-recv-complete': [],
      'file-send-accept': [],
      'file-send-start': [],
      'file-send-cancel': [],
      'file-send-complete': [],
    }

  def run(self):
    log.debug('PurpleClientCallbackThread::run(): Starting...')
    while True:
      self.parent.imhandler_callbacks_lock.lock()
      try:
        while self.parent.imhandler_callbacks:
          message = self.parent.imhandler_callbacks.pop(0)
          callback = message['callback']
          msg = message['msg']
          if self.callbacks.has_key(callback):
            for func in self.callbacks[callback]:
              try:
                func(msg)
              except Exception, e:
                # Use wildcard exception because we don't want this thread to
                # die due to errors in the Client.
                log.exception('PurpleClientCallbackThread::run(): %s' % e)
                
          else:
            log.warn('PurpleClientCallbackThread::run(): Invalid callback %s' %
                     callback)
      finally:
        self.parent.imhandler_callbacks_lock.unlock()
      self.msleep(500)
      
  def register_callback(self, callback, func):
    """Remember callbacks locally, so that they can be matched when PurpleServer
    responds.
    Arguments:
      callback: String,
      func: Python callable
    """
    if callback not in self.callbacks:
      log.warn('PurpleClientCallbackThread::register_callback(): ' + 
               'Invalid callback: %s' % callback)
      return
    if func not in self.callbacks[callback]:
      self.callbacks[callback].append(func)
    
