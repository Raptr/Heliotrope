"""Python Purple Server class.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
"""

import ctypes
import ctypes.util
import logging
import os
import pickle
from PyQt4 import QtCore, QtNetwork
from PyQt4.QtCore import SIGNAL

from heliotrope import purple_base
from heliotrope import pypurple

log = logging.getLogger()
CLIB = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))


class PurpleServer(QtCore.QThread, purple_base.PurpleBaseRpc):
  """Python Purple Server, in charge of controlling libpurple client"""
  def __init__(self):
    QtCore.QThread.__init__(self)
    purple_base.PurpleBaseRpc.__init__(self)
    self.unique_key = purple_base.PYPURPLE_UNIQUE_KEY
    self.shared_memory = QtCore.QSharedMemory(self.unique_key)
  
    if not self.shared_memory.attach():
      log.error('PurpleServer::__init__(): Purple Client is not running')
      QtCore.QTimer.singleShot(0, QtCore.QCoreApplication.quit)
      return
        
    self.cl = pypurple.Client()
    
    self.cl.register_callback('buddy-typing', self.buddy_typing_cb)
    self.cl.register_callback('buddy-typing-stopped', 
                              self.buddy_typing_stopped_cb)
    self.cl.register_callback('buddy-typed', self.buddy_typed_cb)
    self.cl.register_callback('buddy-signed-off', self.buddy_signed_off_cb)
    self.cl.register_callback('buddy-signed-on', self.buddy_signed_on_cb)
    self.cl.register_callback('buddy-status-changed', 
                              self.buddy_status_changed_cb)
    self.cl.register_callback('blist-node-aliased', self.blist_node_aliased_cb)
    self.cl.register_callback('received-im-msg', self.received_im_msg_cb)
    self.cl.register_callback('signed-on', self.signed_on_cb)
    self.cl.register_callback('signed-off', self.signed_off_cb)
    self.cl.register_callback('signing-on', self.signing_on_cb)
    self.cl.register_callback('signing-off', self.signing_off_cb)
    self.cl.register_callback('connection-error', self.connection_error_cb)
    self.cl.register_callback('buddy-icon-changed', self.buddy_icon_changed_cb)
    self.cl.register_callback('buddy-added', self.buddy_added_cb)
    self.cl.register_callback('request-authorization',
                              self.request_authorization_cb)
    self.cl.register_callback('displaying-userinfo',
                              self.displaying_userinfo_cb)
    self.cl.register_callback('file-recv-request', self.file_recv_request_cb)
    self.cl.register_callback('file-recv-accept', self.file_recv_accept_cb)
    self.cl.register_callback('file-recv-start', self.file_recv_start_cb)
    self.cl.register_callback('file-recv-cancel', self.file_recv_cancel_cb)
    self.cl.register_callback('file-recv-complete', self.file_recv_complete_cb)
    self.cl.register_callback('file-send-accept', self.file_send_accept_cb)
    self.cl.register_callback('file-send-start', self.file_send_start_cb)
    self.cl.register_callback('file-send-cancel', self.file_send_cancel_cb)
    self.cl.register_callback('file-send-complete', self.file_send_complete_cb)

  def run(self):
    log.debug('PurpleServer::run(): Starting...')
  
    self.handshake()
    
    # Send messages in a separate thread
    self.queued_message_timer = QtCore.QTimer()
    self.connect(self.queued_message_timer, SIGNAL('timeout()'),
                 self.sendMessage, QtCore.Qt.DirectConnection)
    self.queued_message_timer.start(500)
    
    # Update shared memory every now and then
    self.shared_memory_timer = QtCore.QTimer()
    self.connect(self.shared_memory_timer, SIGNAL('timeout()'),
                 self.writeSharedMemory, QtCore.Qt.DirectConnection)
    self.shared_memory_timer.start(1000)
    
    self.exec_()

  def handshake(self):
    """Say Hello to Purple Client"""
    self.local_socket = QtNetwork.QLocalSocket()
    self.local_socket.connectToServer(self.unique_key)
    if not self.local_socket.waitForConnected(self.timeout):
      log.error('PurpleServer::handshake(): Failed to connect: %s' %
                self.local_socket.errorString().toLatin1())
      return

    self.connect(self.local_socket, SIGNAL('readyRead()'),
                 self.receiveMessage, QtCore.Qt.DirectConnection)
    self.connect(self.local_socket, 
                 SIGNAL('stateChanged(QLocalSocket::LocalSocketState)'),
                 self.stateChangedCB, QtCore.Qt.DirectConnection)
      
    message = 'HELLO'
    self.queueMessage(message)
    
  def sendMessage(self):
    """Send message back to PurpleClient"""
    if not self.local_socket or not self.messages:
      return
    self.writeSharedMemory()
    purple_base.PurpleBaseRpc.sendMessage(self)
          
  def writeSharedMemory(self):
    """Update shared memory segment"""
    data = {
      'account_status': self.cl.account_status,
      'account_errmsg': self.cl.account_errmsg,
      'transfers': self.cl.list_transfers(),
    }
    data_bytes = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
    data_len = len(data_bytes)
    
    self.shared_memory.lock()
    try:
      CLIB.memcpy(int(self.shared_memory.data()), data_bytes, data_len)
    finally:
      self.shared_memory.unlock()
      
  def receiveMessage(self):
    """Process incoming message from PurpleClient"""
    for message in purple_base.PurpleBaseRpc.receiveMessage(self):
      if message['func'] == 'login':
        log.debug('PurpleServer::receiveMessage(): func="%s", account="%s"' %
                  (message['func'], message['args'][0]))
      else:
        log.debug('PurpleServer::receiveMessage(): func="%s", args="%s"' % 
                  (message['func'], message['args']))
    
      func = message['func']
      args = message['args']
      if not hasattr(self.cl, func):
        log.warn('PurpleServer::receiveMessage(): Client does not have "%s" ' + 
                 'function defined. Ignorning...')
        return
    
      if args:
        getattr(self.cl, func)(*args)
      else:
        getattr(self.cl, func)()
      
  def stateChangedCB(self, state):
    """Handle state changes in the named pipe
    Arguments:
      state: QLocalSocket.LocalSocketState
    """
    if state == self.local_socket.UnconnectedState:
      log.info('Purple Client disconnected; exiting...')
      QtCore.QCoreApplication.quit()
    elif state == self.local_socket.ConnectingState:
      pass
    elif state == self.local_socket.ConnectedState:
      pass
    elif state == self.local_socket.ClosingState:
      pass
    else:
      log.warn('PurpleServer::stateChangedCB(): Unknown state: %s' % state)
  
  def proxyCallback(self, callback, msg):
    """Porxy callback to PurpleClient
    Arguments:
      callback: Callback name
      msg: Python dictionary
    """
    message = {
      'callback': callback,
      'msg': msg,
    }
    self.queueMessage(message)

  # ---- Start of libpurple callbacks
      
  def buddy_typing_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-typing', msg)

  def buddy_typing_stopped_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-typing-stopped', msg)

  def buddy_typed_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-typed', msg)    
  
  def buddy_signed_off_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-signed-off', msg)

  def buddy_signed_on_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-signed-on', msg)

  def buddy_status_changed_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-status-changed', msg)

  def blist_node_aliased_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('blist-node-aliased', msg)
    
  def received_im_msg_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('received-im-msg', msg)
    
  def signed_on_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('signed-on', msg)

  def signed_off_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('signed-off', msg)
    
  def signing_on_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('signing-on', msg)
    
  def signing_off_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('signing-off', msg)
    
  def connection_error_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('connection-error', msg)
    
  def buddy_icon_changed_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-icon-changed', msg)

  def buddy_added_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('buddy-added', msg)

  def request_authorization_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('request-authorization', msg)

  def displaying_userinfo_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('displaying-userinfo', msg)
    
  def file_recv_request_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-request', msg)
    
  def file_recv_accept_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-accept', msg)
    
  def file_recv_start_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-start', msg)    
    
  def file_recv_cancel_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-cancel', msg)
    
  def request_authorization_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('request-authorization', msg)

  def displaying_userinfo_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('displaying-userinfo', msg)
    
  def file_recv_request_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-request', msg)
    
  def file_recv_accept_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-accept', msg)
    
  def file_recv_start_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-start', msg)    
    
  def file_recv_complete_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-recv-complete', msg)
  
  def file_send_accept_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-send-accept', msg)
    
  def file_send_start_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-send-start', msg)

  def file_send_cancel_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-send-cancel', msg)
  
  def file_send_complete_cb(self, msg):
    """Proxy callback to PurpleClient
    Arguments:
      msg: Python dictionary
    """
    self.proxyCallback('file-send-complete', msg)
    
