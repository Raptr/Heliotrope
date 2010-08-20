"""Libpurple to Python translation layer.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
"""

import gobject
import logging
import os
import re
import sys
import threading
import time

from heliotrope import purple

log = logging.getLogger()

PIDGIN = 'c:/atomdep/pidgin/2.7.1'
LIBPURPLE_PLUGIN_DIR = PIDGIN + '/win32-install-dir/plugins'
CA_CERT_DIRS = [PIDGIN + '/share/ca-certs']
CONFIG_DIR = 'config'
AVATAR_DIR = 'config/icons'

gobject.threads_init()


class Client(threading.Thread):
  
  def __init__(self):
    """Initialize purple environment."""
    threading.Thread.__init__(self)

    # Register this application with libpurple
    self.appname = 'purplexmpp'

    # Start GTK mainloop
    self.loop = gobject.MainLoop()
    self.loop.quit()

    # Callback functions to invoke when receiving Pidgin signals
    # Refer to http://developer.pidgin.im/doxygen/dev/html/pages.html
    # for a comprehensive list of signals.
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

    # Keep track of all pending authorizations
    # key is (PurpleAccount, remote_user)
    self.pending_authorizations = {}

    # Account connection status (has to match PurpleClient)
    # TODO(koyao): Merge these values into a common base class.
    self.CONNECTING = 0
    self.CONNECTED = 1
    self.DISCONNECTING = 2
    self.DISCONNECTED = 3
    self.ERROR = 4

    # Keep track of account connection status
    self.account_status = {}
    self.account_errmsg = {}

    # Allow user to override various directories
    self.config_dir = CONFIG_DIR
    self.plugin_dir = LIBPURPLE_PLUGIN_DIR
    self.ca_cert_dirs = CA_CERT_DIRS
    self.avatar_dir = AVATAR_DIR

    # Disable logging by default
    purple.set_heliotrope_print_debug_cb(self.null)
    purple.purple_debug_set_ui_ops(purple.heliotrope_debug_get_ui_ops())
    purple.purple_debug_set_enabled(False)

    # Set notification ui ops
    purple.purple_notify_set_ui_ops(purple.heliotrope_get_notify_ui_ops())
    
    # Set blist ui ops
    purple.purple_blist_set_ui_ops(purple.heliotrope_get_blist_ui_ops())
    
  def enable_debug(self, enable):
    """Whether to enable debug logging
    Arguments:
      enable: Boolean
    """
    if enable:
      purple.set_heliotrope_print_debug_cb(log.debug)
    else:
      purple.set_heliotrope_print_debug_cb(self.null)

  def null(self, message):
    """Helper function to silence libpurple logging"""
    pass
      
  def set_config_dir(self, directory):
    """Set libpurple config dir:
    Arguments:
      directory: String, config dir to add
    """
    directory = directory.encode('utf-8')
    self.config_dir = directory
    purple.purple_util_set_user_dir(self.config_dir)
    
  def set_plugin_dir(self, directory):
    """Set libpurple plugin dir:
    Arguments:
      directory: String, dir to add
    """
    directory = directory.encode('utf-8')
    self.plugin_dir = directory

  def set_ca_cert_dirs(self, directories):
    """Set libpurple ca cert dir:
    Arguments:
      directories: List of directories to search for certs
    """
    directories = [x.encode('utf-8') for x in directories]
    self.ca_cert_dirs = directories

  def set_avatar_dir(self, directory):
    """Set avatar dir:
    Arguments:
      directory: String, dir to add
    """
    directory = directory.encode('utf-8')
    self.avatar_dir = directory
    
  def register_callback(self, callback, func):
    """Register function callbacks
    Arguments:
      callback: String, Pidgin signal
      func: Python function
    """
    if callback not in self.callbacks:
      log.warn('Invalid callback: %s' % callback)
      return

    if func not in self.callbacks[callback]:
      self.callbacks[callback].append(func)

  def received_im_msg_cb(self, p_account, sender, message, p_conv, flags):
    """Received IM message:
    Arguments:
      p_account: pointer to PurpleAccount object
      sender: String, sender
      message: String, message
      p_conv: pointer to PurpleConversation object
      flags: int, IM conversation flags
    """
    acct = purple.to_account(p_account)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(sender),
           'message': message.decode('utf-8')}
    for func in self.callbacks['received-im-msg']:
      func(msg)

  def received_buddy_typing_cb(self, p_account, sender):
    """Received typing notification:
    Arguments:
      p_account: pointer to PurpleAccount object
      sender: String, sender
    """
    acct = purple.to_account(p_account)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(sender)}
    for func in self.callbacks['buddy-typing']:
      func(msg)

  def received_buddy_typing_stopped_cb(self, p_account, sender):
    """Received typing notification:
    Arguments:
      p_account: pointer to PurpleAccount object
      sender: String, sender
    """
    acct = purple.to_account(p_account)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(sender)}
    for func in self.callbacks['buddy-typing-stopped']:
      func(msg)

  def received_buddy_typed_cb(self, p_account, sender):
    """Received typing notification:
    Arguments:
      p_account: pointer to PurpleAccount object
      sender: String, sender
    """
    acct = purple.to_account(p_account)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(sender)}
    for func in self.callbacks['buddy-typed']:
      func(msg)

  def received_buddy_signed_off_cb(self, p_buddy):
    """Received buddy signed off notification:
    Arguments:
      p_buddy: pointer to PurpleBuddy object
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(purple.purple_buddy_get_name(b))}
    for func in self.callbacks['buddy-signed-off']:
      func(msg)

  def received_buddy_signed_on_cb(self, p_buddy):
    """Received buddy signed on notification:
    Arguments:
      p_buddy: pointer to PurpleBuddy object
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)

    status_id, status_msg = self.get_buddy_status(
      '%s|%s' % (acct.protocol_id, acct.username.lower()),
      str_normalize(purple.purple_buddy_get_name(b)))

    if status_id == 'offline':
      return
      
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(purple.purple_buddy_get_name(b)),
           'status_id': status_id,
           'status_msg': status_msg,
          }
    for func in self.callbacks['buddy-signed-on']:
      func(msg)

    if acct.protocol_id == 'prpl-xfire':
      log.debug("Fetching avatar for: %s" %
                str_normalize(purple.purple_buddy_get_name(b)))
      purple.heliotrope_xfire_tooltip_text(b)

  def buddy_added_cb(self, p_buddy):
    """Received buddy added notification
    Arguments:
      p_buddy: pointer to PurpleBuddy object
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)

    # In case of a very large buddy list, it could take quite some time
    # for the 'signed-on' signal to arrive.  Thus, we set account to CONNECTED
    # as soon as we received the first buddy.
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    
    if not self.account_status.has_key(account):
      return
    
    if self.account_status[account] == self.CONNECTING:
      self.account_status[account] = self.CONNECTED

    alias = purple.purple_buddy_get_alias(b).decode('utf-8')
    group = purple.purple_buddy_get_group(b)
    name = str_normalize(purple.purple_buddy_get_name(b).decode('utf-8'))

    if name.startswith('msn/'):
      # MSN buddy on Yahoo network
      sender = name
      alias = alias.replace('msn/', '')
    else:
      # Remove Jabber resource from the sender
      sender = re.sub('/.*', '', name)

    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': sender,
           'alias': alias,
           'group': group.name,
          }
    for func in self.callbacks['buddy-added']:
      func(msg)

  def received_buddy_status_changed_cb(self, p_buddy, p_old_status, p_status):
    """Received buddy status changed notification:
    Arguments:
      p_buddy: pointer to PurpleBuddy object
      p_old_status: pointer to PurpleStatus object
      p_status: pointer to PurpleStatus object
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)
    status = purple.to_status(p_status)
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(purple.purple_buddy_get_name(b)),
           'status_id': purple.purple_status_get_id(status),
           'status_msg': purple.purple_status_get_attr_string(status, 'message')
          }
    for func in self.callbacks['buddy-status-changed']:
      func(msg)

  def blist_node_aliased_cb(self, p_buddy, old_alias):
    """Received blist alias changed notification:
    Arguments:
      p_buddy: pointer to PurpleBuddy object
      old_alias: String, old alias
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)
    sender = str_normalize(purple.purple_buddy_get_name(b).decode('utf-8'))
    alias = purple.purple_buddy_get_alias(b).decode('utf-8')

    if sender.startswith('msn/'):
      # MSN buddy on Yahoo network
      alias = alias.replace('msn/', '')

    group = purple.purple_buddy_get_group(b)
    group_name = None
    if group:
      group_name = group.name

    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': sender,
           'old_alias': old_alias,
           'alias': alias,
           'group': group_name,
          }
    for func in self.callbacks['blist-node-aliased']:
      func(msg)

  def request_authorize_cb(self, p_account, remote_user, id, alias, message,
    on_list, request_auth_cb, request_deny_cb, user_data):
    """Store the authorization request and invoke the callback.
    Arguments:
      p_account: pointer to PurpleAccount
      remote_user: String, remote user requesting authorization
      id: String, not used
      message: String, invitation mesage
      on_list: Boolean, whether the remote user is already on the buddylist
      request_auth_cb: Pointer to the authorized callback.
      request_deny_cb: Pointer to the denied callback.
      user_data: Pointer to the data to be passed to callback func.
    """
    acct = purple.to_account(p_account)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())

    sender = str_normalize(remote_user)

    if not sender.startswith('msn/'):
      # Remove Jabber resource from the sender
      sender = re.sub('/.*', '', sender)

    key = (account, sender)
    if self.pending_authorizations.has_key(key):
      # We could get duplicate authorization requests from other sources.
      # Just discard it silently.
      log.debug('In Client::request_authorize_cb(): Ignoring duplicate auth')
      return
      
    # Record the callback functions and user_data so that we can act upon it
    # when user makes a decision to accept/deny this auth request.
    self.pending_authorizations[key] = \
      (request_auth_cb, request_deny_cb, user_data)

    msg = {'account': account,
           'from': sender,
           'id': id,
           'alias': alias,
           'message': message,
           'on_list': on_list,
          }
    for func in self.callbacks['request-authorization']:
      func(msg)

  def signed_on_cb(self, p_connection):
    """Callback function when an account has signed on
    Arguments:
      p_connection: pointer to PurpleConnection
    """
    gc = purple.to_connection(p_connection)
    acct = purple.purple_connection_get_account(gc)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    self.account_status[account] = self.CONNECTED
    self.account_errmsg[account] = ''

    msg = {'account': account}
    for func in self.callbacks['signed-on']:
      func(msg)

  def signed_off_cb(self, p_connection):
    """Callback function when an account has signed off
    Arguments:
      p_connection: pointer to PurpleConnection
    """
    gc = purple.to_connection(p_connection)
    acct = purple.purple_connection_get_account(gc)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    self.account_status[account] = self.DISCONNECTED

    # Remove any pending authorizations that belong to the account going offline.
    for t_account, t_buddy in self.pending_authorizations.keys():
      if t_account == account:
        del self.pending_authorizations[(t_account, t_buddy)]

    msg = {'account': account}
    for func in self.callbacks['signed-off']:
      func(msg)

  def signing_on_cb(self, p_connection):
    """Callback function when an account is about to sign on
    Arguments:
      p_connection: pointer to PurpleConnection
    """
    gc = purple.to_connection(p_connection)
    acct = purple.purple_connection_get_account(gc)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    self.account_status[account] = self.CONNECTING

    msg = {'account': account}
    for func in self.callbacks['signing-on']:
      func(msg)
      
  def signing_off_cb(self, p_connection):
    """Callback function when an account is about to sign off
    Arguments:
      p_connection: pointer to PurpleConnection
    """
    gc = purple.to_connection(p_connection)
    acct = purple.purple_connection_get_account(gc)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    self.account_status[account] = self.DISCONNECTING

    msg = {'account': account}
    for func in self.callbacks['signing-off']:
      func(msg)

  def connection_error_cb(self, p_connection, p_connection_error, desc):
    """Callback function when an account goes into connection error.
    Arguments:
      p_connection: pointer to PurpleConnection
      p_connection_error: pointer to PurpleConnectionError
      desc: String, a description of the error
    """
    gc = purple.to_connection(p_connection)
    acct = purple.purple_connection_get_account(gc)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    self.account_status[account] = self.ERROR
    self.account_errmsg[account] = desc
    
    msg = {'account': account, 'error': desc}
    for func in self.callbacks['connection-error']:
      func(msg)

  def buddy_icon_changed_cb(self, p_buddy):
    """Callback function when an buddy icon got updated
    Arguments:
      p_buddy: pointer to PurpleBuddy
    """
    b = purple.to_buddy(p_buddy) 
    acct = purple.purple_buddy_get_account(b)
    buddy = purple.purple_buddy_get_name(b)
    buddy_icon = purple.purple_buddy_icons_find(acct, buddy)
    if buddy_icon:
      avatar = purple.purple_buddy_icon_get_full_path(buddy_icon)
    else:
      avatar = None
    
    msg = {'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
           'from': str_normalize(buddy),
           'avatar': avatar,
          }
    for func in self.callbacks['buddy-icon-changed']:
      func(msg)

  def run(self):
    """Start purple main loop in a separate thread."""

    # Setup eventloop
    eventloop_ops = purple._PurpleEventLoopUiOps()
    eventloop_ops.timeout_add = purple.g_timeout_add_cb
    eventloop_ops.timeout_remove = purple.g_source_remove_cb
    eventloop_ops.input_add = purple.gnt_input_add_cb
    eventloop_ops.input_remove = purple.g_source_remove_cb
    eventloop_ops.timeout_add_seconds = purple.g_timeout_add_seconds_cb
    purple.purple_eventloop_set_ui_ops(eventloop_ops)

    # Setup PurpleAccountUiOps
    account_ops = purple._PurpleAccountUiOps()
    purple.set_request_authorize_cb(self.request_authorize_cb)
    account_ops.request_authorize = purple.request_authorize_cb
    purple.purple_accounts_set_ui_ops(account_ops)

    # Setup a bunch of paths:
    purple.purple_plugins_add_search_path(self.plugin_dir)
    for dir in self.ca_cert_dirs:
      purple.purple_certificate_add_ca_search_path(dir)
    purple.purple_buddy_icons_set_cache_dir(self.avatar_dir)
    
    log.debug("plugin_dir=%s" % self.plugin_dir)
    log.debug("config_dir=%s" % self.config_dir)
    log.debug("ca_cert_dirs=%s" % self.ca_cert_dirs)
    log.debug("avatar_dir=%s" % self.avatar_dir)

    r = purple.purple_core_init(self.appname)

    # Disable libpurple chat/im logging
    purple.purple_prefs_set_bool("/purple/logging/log_ims", False)
    purple.purple_prefs_set_bool("/purple/logging/log_chats", False)

    # Disable libpurple idle reporting
    purple.purple_prefs_set_string("/purple/away/idle_reporting", "")
    purple.purple_prefs_set_bool("/purple/away/away_when_idle", False)

    # Initialize buddy list
    purple.purple_set_blist(purple.purple_blist_new())

    # Register callbacks
    handle = purple.purple_plugin_new(True, None)
    purple.set_received_im_msg(handle, self.received_im_msg_cb)
    purple.set_buddy_typing(handle, self.received_buddy_typing_cb)
    purple.set_buddy_typing_stopped(handle,
      self.received_buddy_typing_stopped_cb)
    purple.set_buddy_typed(handle, self.received_buddy_typed_cb)
    purple.set_buddy_signed_off(handle, self.received_buddy_signed_off_cb)
    purple.set_buddy_signed_on(handle, self.received_buddy_signed_on_cb)
    purple.set_buddy_status_changed(handle,
      self.received_buddy_status_changed_cb)
    purple.set_blist_node_aliased(handle, self.blist_node_aliased_cb)
    purple.set_signed_on(handle, self.signed_on_cb)
    purple.set_signed_off(handle, self.signed_off_cb)
    purple.set_signing_on(handle, self.signing_on_cb)
    purple.set_signing_off(handle, self.signing_off_cb)
    purple.set_connection_error(handle, self.connection_error_cb)
    purple.set_buddy_icon_changed(handle, self.buddy_icon_changed_cb)
    purple.set_buddy_added(handle, self.buddy_added_cb)
    purple.set_displaying_userinfo(handle, self.displaying_userinfo_cb)
    purple.set_file_recv_request(handle, self.file_recv_request_cb)
    purple.set_file_recv_accept(handle, self.file_recv_accept_cb)
    purple.set_file_recv_start(handle, self.file_recv_start_cb)
    purple.set_file_recv_cancel(handle, self.file_recv_cancel_cb)
    purple.set_file_recv_complete(handle, self.file_recv_complete_cb)
    purple.set_file_send_accept(handle, self.file_send_accept_cb)
    purple.set_file_send_start(handle, self.file_send_start_cb)
    purple.set_file_send_cancel(handle, self.file_send_cancel_cb)
    purple.set_file_send_complete(handle, self.file_send_complete_cb)

    # Start the main loop
    self.loop.run()

  def is_connecting(self, account):
    """Convenience routine: is the specified account in the CONNECTING state?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists and is CONNECTING, False otherwise
    """
    return (account in self.account_status and \
            self.account_status[account] == self.CONNECTING)

  def is_connected(self, account):
    """Convenience routine: is the specified account in the CONNECTED state?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists and is CONNECTED, False otherwise
    """
    return (account in self.account_status and \
            self.account_status[account] == self.CONNECTED)

  def is_disconnecting(self, account):
    """Convenience routine: is the specified account in the DISCONNECTING
       state?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists and is DISCONNECTING, False otherwise
    """
    return (account in self.account_status and \
            self.account_status[account] == self.DISCONNECTING)

  def is_disconnected(self, account):
    """Convenience routine: is the specified account in the DISCONNECTED state?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists and is DISCONNECTED, False otherwise
    """
    return (account in self.account_status and \
            self.account_status[account] == self.DISCONNECTED)

  def has_error(self, account):
    """Convenience routine: is the specified account in the ERROR state?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists and is ERROR, False otherwise
    """
    return (account in self.account_status and \
            self.account_status[account] == self.ERROR)

  def has_status(self, account):
    """Convenience routine: does the specified account exist?
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      True if the account-status exists
    """
    return (account in self.account_status)

  def get_accounts(self):
    """Return list of accounts"""
    return self.account_status.keys()
    
  def get_errmsg(self, account):
    """Return error message of the specified account
    Arguments:
      account: String, protocol and username (e.g. "prpl-jabber|you@example.com")
    Returns:
      String, if the error message exists
      False, if the error message doesn't exist
    """
    if account not in self.account_errmsg:
      return ''
    else:
      return self.account_errmsg[account]
  
  def disconnect(self):
    """Disable all accounts."""
    for acct in purple.purple_accounts_get_all_active():
      account = '%s|%s' % (acct.protocol_id, acct.username.lower())
      log.info("Client::disconnect(): Disconnecting account: %s" % account)
      gobject.timeout_add(0,
        purple.purple_account_set_enabled,
        acct, self.appname, False)
    
  def reset_buddy_list(self):
    """Remove everybody in the buddy list"""
    for buddy in purple.purple_blist_get_buddies():
      purple.purple_blist_remove_buddy(buddy)
    
  def purple_blist_load(self):
    """Load the buddy list from disk"""
    gobject.timeout_add(0, purple.purple_blist_load)
    
  def login(self, account, password, server=None, int_keys={}):
    """Login to an IM account using libpurple.
    Arguments:
      account: String, full IM account (eg. 'prpl-jabber|username@domain)
      password: String, password
      server: String, if specified, use that server instead of the domain
              in username.
      int_keys: Dictionary, a key/value pair of integer values
    """
    log.debug("Inside client::login()")
    log.info("Login to: account=%s, server=%s" % (account, server))

    if not account:
      log.warn('Client::login(): Missing account')
      return

    if not password:
      log.warn('Missing password')
      return

    account = account.encode('utf-8')
    password = password.encode('utf-8')
    if server:
      server = server.encode('utf-8')

    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    # Create the account
    acct = purple.purple_account_new(username, protocol)
    if server:
      gobject.timeout_add(0,
                          purple.purple_account_set_string,
                          acct, 'connect_server', server)
    else:
      gobject.timeout_add(0,
                          purple.purple_account_remove_setting,
                          acct, 'connect_server')

    for k, v in int_keys.items():
      gobject.timeout_add(0,
                          purple.purple_account_set_int,
                          acct, k, v)

    gobject.timeout_add(0,
                        purple.purple_account_set_bool,
                        acct, 'auth_plain_in_clear', True)
    gobject.timeout_add(0,
                        purple.purple_account_set_bool,
                        acct, 'require_tls', False)
    gobject.timeout_add(0,
                        purple.purple_account_set_remember_password,
                        acct, False)
    gobject.timeout_add(0,
                        purple.purple_account_set_password,
                        acct, password)

    if protocol == 'prpl-xfire':
      gobject.timeout_add(0,
                          purple.purple_account_set_bool,
                          acct, 'ingamedetectionnorm', False)

    if protocol in ['prpl-aim', 'prpl-icq']:
      # Disable clientlogin for Oscar protocol
      # See http://developer.pidgin.im/ticket/11142
      gobject.timeout_add(0,
                          purple.purple_account_set_bool,
                          acct, 'use_clientlogin', False)

    gobject.timeout_add(0,
                        purple.purple_accounts_add,
                        acct)

    # Login
    gobject.timeout_add(0,
                        purple.purple_savedstatus_activate_for_account,
                        purple.purple_savedstatus_get_default(), acct)
    gobject.timeout_add(0,
                        purple.purple_account_set_enabled,
                        acct, self.appname, True)
      
  def set_custom_status(self, new_status_id=None, new_status_message=None):
    """Broadcast custom status to all IM accounts.
    Arguments:
      new_status_message: String, custom status message.
                          If not set, keep the current status.
      new_status_id: String, (see status_primitive_map in status.c)
    """
    status_id = new_status_id
    status_message = new_status_message
    for acct in purple.purple_accounts_get_all_active():
      status = purple.purple_account_get_active_status(acct)
      if new_status_id is None:
        status_id = purple.purple_status_get_id(status)
      if new_status_message is None:
        status_message = purple.purple_status_get_attr_string(status, 'message')

      purple.heliotrope_account_set_status(acct, status_id, True, status_message)

  def offline(self, account):
    """Go offline on an IM account
    Arguments:
      account: String, full account (eg. prpl-jaber|username@domain)
    """
    if not account:
      log.warn('Client::offline(): Missing account')
      return

    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Client::offline(): Cannot find account: %s' % account)
      return
      
    # Don't attempt to logout if the account is about to be disconnected,
    # or if we're already disconnected.
    if self.account_status.has_key(account) and \
       self.account_status[account] in [self.DISCONNECTING, self.DISCONNECTED]:
      return

    log.info("Client::offline(): Disabling account: %s" % account)
    gobject.timeout_add(0,
                        purple.purple_account_set_enabled,
                        acct, self.appname, False)

  def send_message(self, account, recipient, message):
    """Send an IM to recipient
    Arguments:
      account: String, full account (eg. prpl-jaber|username@domain)
      recipient: String, recipient's username
      message: String, message to send
    """
    if not account or not recipient or not message:
      log.warn('Missing parameters for Client::send_message()')
      return

    account = account.encode('utf-8')
    recipient = recipient.encode('utf-8')
    message = message.encode('utf-8')

    protocol, username = account.split('|')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    conv = purple.purple_find_conversation_with_account(
      purple.PURPLE_CONV_TYPE_IM, recipient, acct)
    if not conv:
      conv = purple.purple_conversation_new(purple.PURPLE_CONV_TYPE_IM,
                                            acct, recipient)
    
    conv_im = purple.purple_conversation_get_im_data(conv)

    gobject.timeout_add(0,
                        purple.purple_conv_im_send,
                        conv_im, message)   

  def send_typing_notification(self, account, recipient, first):
    """Send typing notification to recipient
    Arguments:
      account: String, full account (eg. prpl-jaber|username@domain)
      recipient: String, recipient's username
      first: Boolean, whether this is the first character of the sentence
    """
    if not account or not recipient:
      log.warn('Missing parameters for Client::send_typing_notification()')
      return

    account = account.encode('utf-8')
    recipient = recipient.encode('utf-8')

    protocol, username = account.split('|')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    conv = purple.purple_find_conversation_with_account(
      purple.PURPLE_CONV_TYPE_IM, recipient, acct)
    if not conv:
      conv = purple.purple_conversation_new(purple.PURPLE_CONV_TYPE_IM,
                                            acct, recipient)
    
    conv_im = purple.purple_conversation_get_im_data(conv)
    
    gobject.timeout_add(0,
                        purple.purple_conv_im_stop_send_typed_timeout,
                        conv_im)
    gobject.timeout_add(0,
                        purple.purple_conv_im_start_send_typed_timeout,
                        conv_im)

    # Check if we need to send another PURPLE_TYPING message
    type_again_ts = purple.purple_conv_im_get_type_again(conv_im)
    if first or (type_again_ts > 0 and time.time() > type_again_ts):
      # TODO(koyao): Figure out how to wrap this logic around
      # gobject.timeout_add(0, ...)
      timeout = purple.serv_send_typing(
                  purple.purple_conversation_get_gc(conv),
                  purple.purple_conversation_get_name(conv),
                  purple.PURPLE_TYPING)
      purple.purple_conv_im_set_type_again(conv_im, timeout)

  def send_typing_stopped_notification(self, account, recipient):
    """Send stop typing notification
    Arguments:
      account: String, full account (eg. prpl-jaber|username@domain)
      recipient: String, recipient's username
    """
    if not account or not recipient:
      log.warn('Missing parameters for Client::send_typing_stopped_notification()')
      return

    account = account.encode('utf-8')
    recipient = recipient.encode('utf-8')

    protocol, username = account.split('|')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    conv = purple.purple_find_conversation_with_account(
      purple.PURPLE_CONV_TYPE_IM, recipient, acct)
    if not conv:
      conv = purple.purple_conversation_new(purple.PURPLE_CONV_TYPE_IM,
                                            acct, recipient)
    
    conv_im = purple.purple_conversation_get_im_data(conv)

    gobject.timeout_add(0,
                        purple.purple_conv_im_stop_send_typed_timeout,
                        conv_im)
    gobject.timeout_add(0,
                        purple.serv_send_typing,
                        purple.purple_conversation_get_gc(conv),
                        purple.purple_conversation_get_name(conv),
                        purple.PURPLE_NOT_TYPING)
  
  def avatar(self, account, buddy):
    """Return the avatar path of a given account:
    Arguments:
      account: String, full account (eg. prpl-jaber|username@domain)
      buddy: String, username of the owner of the avatar
    Returns:
      icon_path: String, absolute path to the icon
    """
    if not account:
      log.warn('Client::avatar(): Missing account')
      return

    if not buddy:
      log.warn('Missing buddy')
      return

    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return

    buddy = buddy.encode('utf-8') 
    buddy_icon = purple.purple_buddy_icons_find(acct, buddy)
    if not buddy_icon:
      return
    icon_path = purple.purple_buddy_icon_get_full_path(buddy_icon)

    return icon_path

  def add_buddy(self, account, buddy, group="Buddies", alias=None):
    """Add a buddy to the contact list, and server-side contact list.
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to add
      group: String, optional group to be added to
      alias: String, optional alias for this buddy
    """
    if not account:
      log.warn('Client::add_buddy(): Missing account')
      return

    if not buddy:
      log.warn('Missing buddy')
      return

    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return

    if purple.purple_find_buddy(acct, buddy):
      log.warn('Buddy already in the contact list')
      return

    if group:
      group = purple.purple_group_new(group)

    new_buddy = purple.purple_buddy_new(acct, buddy, alias)
    gobject.timeout_add(0,
                        purple.purple_blist_add_buddy,
                        new_buddy, None, group, None)
    gobject.timeout_add(0,
                        purple.purple_account_add_buddy,
                        acct, new_buddy)
    
  def remove_buddy(self, account, buddy):
    """Remove buddy from contact list, and server-side contact list.
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to remove
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return

    buddy = buddy.encode('utf-8')  
    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    g = purple.purple_buddy_get_group(b)

    gobject.timeout_add(0,
                        purple.purple_account_remove_buddy,
                        acct, b, g)
    gobject.timeout_add(0,
                        purple.purple_blist_remove_buddy,
                        b)

  def accept_request(self, account, buddy):
    """Accept authorization request
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to add
    """
    if not self.pending_authorizations.has_key((account, buddy)):
      log.warn('No pending request for %s %s' % (account, buddy))
      return

    request_auth_cb, request_deny_cb, user_data = \
      self.pending_authorizations[(account, buddy)]
    gobject.timeout_add(0,
                        purple.invoke,
                        request_auth_cb, user_data)

    del self.pending_authorizations[(account, buddy)]

    self.add_buddy(account, buddy)

  def deny_request(self, account, buddy):
    """Deny authorization request
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to add
    """
    if not self.pending_authorizations.has_key((account, buddy)):
      log.warn('No pending request for %s %s' % (account, buddy))
      return

    request_auth_cb, request_deny_cb, user_data = \
      self.pending_authorizations[(account, buddy)]
    gobject.timeout_add(0,
                        purple.invoke,
                        request_deny_cb, user_data)

    del self.pending_authorizations[(account, buddy)]

  def rename_buddy(self, account, buddy, name):
    """Rename a buddy in the contact list
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to add
      name: String, new name to rename to.
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return

    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    if not name:
      log.warn('New name cannot be empty')
      return

    gobject.timeout_add(0,
                        purple.purple_blist_alias_buddy,
                        b, name)

  def get_buddy_status(self, account, buddy):
    """Query a buddy's IM status
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username to add
    Returns:
      (status_id, status_msg)
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return

    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    status = purple.purple_presence_get_active_status(b.presence)
    status_id = purple.purple_status_get_id(status)
    status_msg = purple.purple_status_get_attr_string(status, "message")

    return (status_id, status_msg)
    
  def get_server(self, account):
    """Return the connect_server of an IM account
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
    Returns:
      String, the 'connect_server' value
      None, if 'connect_server' was not found
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    return purple.purple_account_get_string(acct, 'connect_server', None)
    
  def send_file(self, account, buddy, local_filename):
    """Initiates file transfer
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, buddy's username
      local_filename: String, full path to a local file
    Returns:
      True, if file transfer was started
      None, on error
    """
    if not os.path.isfile(local_filename):
      log.warn('File not found: %s' % local_filename)
      return

    local_filename = local_filename.encode('utf-8')

    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    buddy = buddy.encode('utf-8')  
    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    c = purple.purple_account_get_connection(acct)
    if not c:
      log.warn('Connection not found: %s' % c)
      return

    purple.serv_send_file(c, buddy, local_filename)

  def list_transfers(self):
    """Return list of all file transfers."""
    transfers = []
    for xfer in purple.purple_xfers_get_all():
      acct = purple.purple_xfer_get_account(xfer)
      name = purple.purple_xfer_get_remote_user(xfer)
      if name.startswith('msn/'):
        # MSN buddy on Yahoo network
        sender = name
      else:
        # Remove Jabber resource from the sender
        sender = re.sub('/.*', '', name)

      transfers.append({
        'account': '%s|%s' % (acct.protocol_id, acct.username.lower()),
        'who': sender,
        'transfer_type': purple.purple_xfer_get_type(xfer),
        'filename': purple.purple_xfer_get_filename(xfer),
        'local_filename': purple.purple_xfer_get_local_filename(xfer),
        'size': purple.purple_xfer_get_size(xfer),
        'bytes_sent': purple.purple_xfer_get_bytes_sent(xfer),
        'bytes_remaining': purple.purple_xfer_get_bytes_remaining(xfer),
        'status': purple.purple_xfer_get_status(xfer),
      })
    return transfers

  def displaying_userinfo_cb(self, p_account, sender, p_user_info):
    """Callback function when a libpurple plugin wants to display userinfo
    Arguments:
      p_account: Pointer to a PurpleAccount object
      sender: String
      p_user_info: Pointer to a PurpleNotifyUserInfo object
    """
    acct = purple.to_account(p_account)
    user_info = purple.to_user_info(p_user_info)

    account = '%s|%s' % (acct.protocol_id, acct.username.lower())

    entries = []
    for entry in purple.purple_notify_user_info_get_entries(user_info):
      label = purple.purple_notify_user_info_entry_get_label(entry)
      value = purple.purple_notify_user_info_entry_get_value(entry)
      entry_type = purple.purple_notify_user_info_entry_get_type(entry)
      if entry_type == purple.PURPLE_NOTIFY_USER_INFO_ENTRY_PAIR:
        entries.append((label, value))

    msg = {
      'account': account,
      'sender': str_normalize(sender),
      'entries': entries,
    }
    for func in self.callbacks['displaying-userinfo']:
      func(msg)

  def _get_xfer_data(self, p_xfer):
    """Get File Transfer data from a pointer to a PurpleXfer object
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    Returns:
      msg: Python dictionary
    """
    xfer = purple.to_xfer(p_xfer)
    acct = purple.purple_xfer_get_account(xfer)
    account = '%s|%s' % (acct.protocol_id, acct.username.lower())
    transfer_type = purple.purple_xfer_get_type(xfer)
    filename = purple.purple_xfer_get_filename(xfer)
    local_filename = purple.purple_xfer_get_local_filename(xfer)
    filesize = purple.purple_xfer_get_size(xfer)

    name = purple.purple_xfer_get_remote_user(xfer)
    if name.startswith('msn/'):
      # MSN buddy on Yahoo network
      sender = name
    else:
      # Remove Jabber resource from the sender
      sender = re.sub('/.*', '', name)

    msg = {
      'account': account,
      'who': sender,
      'transfer_type': transfer_type,
      'filename': filename,
      'local_filename': local_filename,
      'filesize': filesize,
    }
    return msg

  def accept_transfer(self, account, buddy, filename, local_filename):
    """Accept incoming file transfer
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, who is sending the incoming file
      filename: String, remote filename
      local_filename: String, local filename
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')

    filename = filename.encode('utf-8')
    local_filename = local_filename.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    xfer = self._find_xfer(account, buddy, filename,
                           statuses=[purple.PURPLE_XFER_STATUS_UNKNOWN,
                                     purple.PURPLE_XFER_STATUS_NOT_STARTED])
    if not xfer:
      log.warn('Could not find matching incoming file transfer')
      return

    purple.purple_xfer_request_accepted(xfer, local_filename)

  def deny_transfer(self, account, buddy, filename):
    """Deny incoming file transfer
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      buddy: String, who is sending the incoming file
      filename: String, remote filename
    """
    protocol, username = account.split('|')
    protocol = protocol.encode('utf-8')
    username = username.encode('utf-8')
    filename = filename.encode('utf-8')

    acct = purple.purple_accounts_find(username, protocol)
    if not acct:
      log.warn('Cannot find account: %s' % account)
      return
    
    b = purple.purple_find_buddy(acct, buddy)
    if not b:
      log.warn('Buddy not found: %s' % buddy)
      return

    xfer = self._find_xfer(account, buddy, filename)
    if not xfer:
      log.warn('Could not find matching incoming file transfer')
      return

    purple.purple_xfer_request_denied(xfer)

  def _find_xfer(self, account, username, filename, local_filename=None,
                 statuses=[]):
    """Find a matching incoming file transfer
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      username: String, who is sending the incoming file
      filename: String, remote filename
      local_filename: String, local filename
      statuses: List, optionally restrict match to these statuses
    Return:
      A PurpleXfer object, or None if no match found
    """
    found = False
    for xfer in purple.purple_xfers_get_all():
      t_acct = purple.purple_xfer_get_account(xfer)
      t_account = '%s|%s' % (t_acct.protocol_id, t_acct.username.lower())
      name = purple.purple_xfer_get_remote_user(xfer)
      if name.startswith('msn/'):
        # MSN buddy on Yahoo network
        t_username = name
      else:
        # Remove Jabber resource from the sender
        t_username = re.sub('/.*', '', name)
        
      t_filename = purple.purple_xfer_get_filename(xfer)
      t_local_filename = purple.purple_xfer_get_local_filename(xfer)
      t_status = purple.purple_xfer_get_status(xfer)

      if (t_account == account and
          t_username == username and
          t_filename == filename):

        if local_filename and t_local_filename != local_filename:
          continue

        if statuses and t_status not in statuses:
          continue

        # All criterias match
        found = True
        break

    if found:
      return xfer

  def file_recv_request_cb(self, p_xfer):
    """Callback function when an incoming file transfer arrives
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-recv-request']:
      func(msg)

  def file_recv_accept_cb(self, p_xfer):
    """Callback function when an incoming file transfer was accepted
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-recv-accept']:
      func(msg)

  def file_recv_start_cb(self, p_xfer):
    """Callback function when an incoming file transfer has started
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-recv-start']:
      func(msg)

  def file_recv_cancel_cb(self, p_xfer):
    """Callback function when an incoming file transfer was canceled
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-recv-cancel']:
      func(msg)

  def file_recv_complete_cb(self, p_xfer):
    """Callback function when an incoming file transfer was completed
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-recv-complete']:
      func(msg)

  def file_send_accept_cb(self, p_xfer):
    """Callback function when an outgoing transfer has been accepted.
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-send-accept']:
      func(msg)

  def file_send_start_cb(self, p_xfer):
    """Callback function when an outgoing transfer has started.
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-send-start']:
      func(msg)

  def file_send_cancel_cb(self, p_xfer):
    """Callback function when an outgoing transfer has been canceled.
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-send-cancel']:
      func(msg)

  def file_send_complete_cb(self, p_xfer):
    """Callback function when an outgoing transfer has been completed.
    Arguments:
      p_xfer: Pointer to a PurpleXfer object
    """
    msg = self._get_xfer_data(p_xfer)
    for func in self.callbacks['file-send-complete']:
      func(msg)

  def cancel_transfer(self, account, username, filename, local_filename):
    """Cancel file transfer
    Arguments:
      account: String, full account (eg. prpl-jabber|username@domain)
      username: String, sender/receiver buddy
      filename: String, remote filename
      local_filename: String, local filename
    """
    xfer = self._find_xfer(account, username, filename, local_filename)
    if not xfer:
      log.warn('In Client::cancel_transfer: xfer not found')
      return
    purple.purple_xfer_cancel_local(xfer)


def str_normalize(input):
  """Normalize a string for comparison
  Argument:
    input: String, input string to be normalized
  Returns:
    String, normalized string
  """
  return input.replace(' ', '').lower()

