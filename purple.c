/**
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty.
 **/

#include <Python.h>
#include <glib.h>
#include "account.h"
#include "blist.h"
#include "conversation.h"
#include "eventloop.h"
#include "plugin.h"
#include "signals.h"
#include "debug.h"

//-----------------------------------------------------------------------------
#define FINCH_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define FINCH_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGntIOClosure {
  PurpleInputFunction function;
  guint               result;
  gpointer            data;
} PurpleGntIOClosure;

static void purple_gnt_io_destroy(gpointer data) {
  g_free(data);
}

static gboolean purple_gnt_io_invoke(GIOChannel *source,
  GIOCondition condition, gpointer data) {
  PurpleGntIOClosure *closure = data;
  PurpleInputCondition purple_cond = 0;

  if (condition & FINCH_READ_COND)
    purple_cond |= PURPLE_INPUT_READ;
  if (condition & FINCH_WRITE_COND)
    purple_cond |= PURPLE_INPUT_WRITE;

#ifdef _WIN32
  if(! purple_cond) {
#ifdef DEBUG
    purple_debug(PURPLE_DEBUG_MISC, "purplexmpp",
      "CLOSURE received GIOCondition of 0x%x, which does not"
      " match 0x%x (READ) or 0x%x (WRITE)\n",
      condition, PIDGIN_READ_COND, PIDGIN_WRITE_COND);
#endif /* DEBUG */

    return TRUE;
  }
#endif /* _WIN32 */

  closure->function(closure->data, g_io_channel_unix_get_fd(source),
                    purple_cond);
  return TRUE;
}

guint gnt_input_add(gint fd, PurpleInputCondition condition,
  PurpleInputFunction function, gpointer data) {
  PurpleGntIOClosure *closure = g_new0(PurpleGntIOClosure, 1);
  GIOChannel *channel;
  GIOCondition cond = 0;
#ifdef _WIN32
  static int use_glib_io_channel = -1;

  if (use_glib_io_channel == -1)
    use_glib_io_channel = (g_getenv("PIDGIN_GLIB_IO_CHANNEL") != NULL) ? 1 : 0;
#endif

  closure->function = function;
  closure->data = data;

  if (condition & PURPLE_INPUT_READ)
    cond |= FINCH_READ_COND;
  if (condition & PURPLE_INPUT_WRITE)
    cond |= FINCH_WRITE_COND;

#ifdef _WIN32
  if (use_glib_io_channel == 0)
    channel = wpurple_g_io_channel_win32_new_socket(fd);
  else
#endif
  channel = g_io_channel_unix_new(fd);

  closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
    purple_gnt_io_invoke, closure, purple_gnt_io_destroy);

  g_io_channel_unref(channel);
  return closure->result;
}

//-----------------------------------------------------------------------------
// Stub function to work with SWIG type checking of pointers.
PurpleAccount *to_account(void *p) {
  return p;
}

PurpleConversation *to_conversation(void *p) {
  return p;
}

PurpleBuddy *to_buddy(void *p) {
  return p;
}

PurpleStatus *to_status(void *p) {
  return p;
}

PurpleConnection *to_connection(void *p) {
  return p;
}

PurpleXfer *to_xfer(void *p) {
  return p;
}

PurpleNotifyUserInfo *to_user_info(void *p) {
  return p;
}

//-----------------------------------------------------------------------------
// Relay a received IM message to Python.
gboolean received_im_msg(PurpleAccount *account, char *sender, char *message,
  PurpleConversation *conv, PurpleMessageFlags flags, PyObject *func) {
  char *data = purple_markup_strip_html(message);
  
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *obj1;
  PyObject *result;

  if (0 == conv) {
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, sender);
  }
  
  obj0 = PyCObject_FromVoidPtr(account, NULL);
  obj1 = PyCObject_FromVoidPtr(conv, NULL);
  result = PyEval_CallFunction(func, "OssOi", obj0, sender, data, obj1, flags);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);
  Py_XDECREF(obj1);

  PyGILState_Release(state);
  g_free(data);
  
  return FALSE;
}

void set_received_im_msg(PurplePlugin *plugin, PyObject *func) {
  static PyObject *received_im_msg_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(received_im_msg_cb);
  received_im_msg_cb = func;

  purple_signal_connect(purple_conversations_get_handle(), "received-im-msg",
    plugin, PURPLE_CALLBACK(received_im_msg), received_im_msg_cb);
}

//-----------------------------------------------------------------------------
void buddy_typed(PurpleAccount *account, const char *name, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(account, NULL);
  result = PyEval_CallFunction(func, "Os", obj0, name);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_typed(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *buddy_typed_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_typed_cb);
  buddy_typed_cb = func;

  purple_signal_connect(purple_conversations_get_handle(), "buddy-typed",
    plugin, PURPLE_CALLBACK(buddy_typed), buddy_typed_cb);
}

//-----------------------------------------------------------------------------
void buddy_typing(PurpleAccount *account, const char *name, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(account, NULL);
  result = PyEval_CallFunction(func, "Os", obj0, name);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_typing(PurplePlugin *plugin, PyObject *func) {
  static PyObject *buddy_typing_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_typing_cb);
  buddy_typing_cb = func;

  purple_signal_connect(purple_conversations_get_handle(), "buddy-typing",
    plugin, PURPLE_CALLBACK(buddy_typing), buddy_typing_cb);
}

//-----------------------------------------------------------------------------
void buddy_typing_stopped(PurpleAccount *account, const char *name,
  PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(account, NULL);
  result = PyEval_CallFunction(func, "Os", obj0, name);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_typing_stopped(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *buddy_typing_stopped_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_typing_stopped_cb);
  buddy_typing_stopped_cb = func;

  purple_signal_connect(purple_conversations_get_handle(),
    "buddy-typing-stopped", plugin, PURPLE_CALLBACK(buddy_typing_stopped),
    buddy_typing_stopped_cb);
}

//-----------------------------------------------------------------------------
void buddy_signed_off(PurpleBuddy *buddy, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(O)", obj0));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_signed_off(PurplePlugin *plugin, PyObject *func) {
  static PyObject *buddy_signed_off_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_signed_off_cb);
  buddy_signed_off_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "buddy-signed-off", plugin,
    PURPLE_CALLBACK(buddy_signed_off), buddy_signed_off_cb);
}

//-----------------------------------------------------------------------------
void buddy_signed_on(PurpleBuddy *buddy, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(O)", obj0));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_signed_on(PurplePlugin *plugin, PyObject *func) {
  static PyObject *buddy_signed_on_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_signed_on_cb);
  buddy_signed_on_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "buddy-signed-on", plugin,
    PURPLE_CALLBACK(buddy_signed_on), buddy_signed_on_cb);
}

//-----------------------------------------------------------------------------
void buddy_status_changed(PurpleBuddy *buddy, PurpleStatus *old_status,
  PurpleStatus *status, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *obj1;
  PyObject *obj2;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  obj1 = PyCObject_FromVoidPtr(old_status, NULL);
  obj2 = PyCObject_FromVoidPtr(status, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(OOO)", obj0, obj1, obj2));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);
  Py_XDECREF(obj1);
  Py_XDECREF(obj2);

  PyGILState_Release(state);
}

void set_buddy_status_changed(PurplePlugin *plugin, PyObject *func) {
  static PyObject *buddy_status_changed_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_status_changed_cb);
  buddy_status_changed_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "buddy-status-changed",
    plugin, PURPLE_CALLBACK(buddy_status_changed), buddy_status_changed_cb);
}

//-----------------------------------------------------------------------------

gboolean purple_buddy_is_online(PurpleBuddy *b) {
  return PURPLE_BUDDY_IS_ONLINE(b);
}

//-----------------------------------------------------------------------------
static PyObject *heliotrope_request_authorize_cb = NULL;

void set_request_authorize_cb(PyObject *func) {
  Py_XINCREF(func);
  heliotrope_request_authorize_cb = func;
}

void *request_authorize(PurpleAccount *account, const char *remote_user,
  const char *id, const char *alias, const char *message, gboolean on_list,
  void *authorize_cb, void *deny_cb, void *user_data) {

  PyGILState_STATE state = PyGILState_Ensure();

  PyObject *py_account;
  PyObject *py_authorize_cb;
  PyObject *py_deny_cb;
  PyObject *py_user_data;
  PyObject *result;

  py_account = PyCObject_FromVoidPtr(account, NULL);
  py_authorize_cb = PyCObject_FromVoidPtr(authorize_cb, NULL);
  py_deny_cb = PyCObject_FromVoidPtr(deny_cb, NULL);
  py_user_data = PyCObject_FromVoidPtr(user_data, NULL);

  result = PyObject_CallObject(heliotrope_request_authorize_cb,
    Py_BuildValue("(OssssiOOO)", py_account, remote_user, id, alias,
                  message, on_list, py_authorize_cb, py_deny_cb,
                  py_user_data));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(py_account);
  Py_XDECREF(py_authorize_cb);
  Py_XDECREF(py_deny_cb);
  Py_XDECREF(py_user_data);
  Py_XDECREF(result);

  PyGILState_Release(state);
}

void invoke(PyObject *cb, PyObject *user_data) {
  void *cb_ptr = PyCObject_AsVoidPtr(cb);
  void *user_data_ptr = PyCObject_AsVoidPtr(user_data);

  ((void(*)(void *))cb_ptr)(user_data_ptr);
}

//-----------------------------------------------------------------------------
void connection_python_cb(PurpleConnection *gc, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(gc, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(O)", obj0));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_signed_on(PurplePlugin *plugin, PyObject *func) {
  static PyObject *signed_on_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(signed_on_cb);
  signed_on_cb = func;

  purple_signal_connect(purple_connections_get_handle(), "signed-on",
    plugin, PURPLE_CALLBACK(connection_python_cb), signed_on_cb);
}

//-----------------------------------------------------------------------------
void set_signed_off(PurplePlugin *plugin, PyObject *func) {
  static PyObject *signed_off_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(signed_off_cb);
  signed_off_cb = func;

  purple_signal_connect(purple_connections_get_handle(), "signed-off",
    plugin, PURPLE_CALLBACK(connection_python_cb), signed_off_cb);
}

//-----------------------------------------------------------------------------
void set_signing_on(PurplePlugin *plugin, PyObject *func) {
  static PyObject *signing_on_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(signing_on_cb);
  signing_on_cb = func;

  purple_signal_connect(purple_connections_get_handle(), "signing-on",
    plugin, PURPLE_CALLBACK(connection_python_cb), signing_on_cb);
}

//-----------------------------------------------------------------------------
void set_signing_off(PurplePlugin *plugin, PyObject *func) {
  static PyObject *signing_off_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(signing_off_cb);
  signing_off_cb = func;

  purple_signal_connect(purple_connections_get_handle(), "signing-off",
    plugin, PURPLE_CALLBACK(connection_python_cb), signing_off_cb);
}

//-----------------------------------------------------------------------------
void connection_error(PurpleConnection *gc, PurpleConnectionError err, const gchar *desc, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(gc, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(Ois)", obj0, err, desc));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_connection_error(PurplePlugin *plugin, PyObject *func) {
  static PyObject *connection_error_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(connection_error_cb);
  connection_error_cb = func;

  purple_signal_connect(purple_connections_get_handle(), "connection-error",
    plugin, PURPLE_CALLBACK(connection_error), connection_error_cb);
}

//-----------------------------------------------------------------------------
void buddy_icon_changed(PurpleBuddy *buddy, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  result = PyEval_CallFunction(func, "(O)", obj0);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_icon_changed(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *buddy_icon_changed_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_icon_changed_cb);
  buddy_icon_changed_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "buddy-icon-changed",
    plugin, PURPLE_CALLBACK(buddy_icon_changed), buddy_icon_changed_cb);
}

//-----------------------------------------------------------------------------
void blist_node_aliased(PurpleBuddy *buddy, const gchar *old_alias, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(Os)", obj0, old_alias));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_blist_node_aliased(PurplePlugin *plugin, PyObject *func) {
  static PyObject *blist_node_aliased_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(blist_node_aliased_cb);
  blist_node_aliased_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "blist-node-aliased", plugin,
    PURPLE_CALLBACK(blist_node_aliased), blist_node_aliased_cb);
}

//-----------------------------------------------------------------------------
void buddy_added(PurpleBuddy *buddy, PyObject *func) {
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(buddy, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(O)", obj0));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_buddy_added(PurplePlugin *plugin, PyObject *func) {
  static PyObject *buddy_added_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(buddy_added_cb);
  buddy_added_cb = func;

  purple_signal_connect(purple_blist_get_handle(), "buddy-added", plugin,
    PURPLE_CALLBACK(buddy_added), buddy_added_cb);
}

//-----------------------------------------------------------------------------
void displaying_userinfo(PurpleAccount *account, const char *who,
                         PurpleNotifyUserInfo *user_info, PyObject *func)
{
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *obj1;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(account, NULL);
  obj1 = PyCObject_FromVoidPtr(user_info, NULL);
  result = PyObject_CallObject(func, Py_BuildValue("(OsO)", obj0, who, obj1));
  if (result == NULL)
    PyErr_Print();

  Py_XDECREF(result);
  Py_XDECREF(obj0);
  Py_XDECREF(obj1);

  PyGILState_Release(state);
}

void set_displaying_userinfo(PurplePlugin *plugin, PyObject *func) {
  static PyObject *displaying_userinfo_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(displaying_userinfo_cb);
  displaying_userinfo_cb = func;

  purple_signal_connect(purple_notify_get_handle(), "displaying-userinfo",
    plugin, PURPLE_CALLBACK(displaying_userinfo), displaying_userinfo_cb);
}

//-----------------------------------------------------------------------------
static PyObject *heliotrope_print_debug_cb = NULL;

void set_heliotrope_print_debug_cb(PyObject *func) {
  Py_XINCREF(func);
  heliotrope_print_debug_cb = func;
}

void heliotrope_debug_print(PurpleDebugLevel level, const char *category,
    const char *args)
{
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *result;
  char *message;
  
  message = g_strdup_printf("%s: %s", category, args);
  // Remove the trailing newline because Python's logging module
  // already appends a newline by default.
  message = g_strchomp(message);

  result = PyObject_CallObject(heliotrope_print_debug_cb, Py_BuildValue("(s)", message));
  if (result == NULL)
    PyErr_Print();

  g_free(message);
  Py_XDECREF(result);
  PyGILState_Release(state);
}

gboolean heliotrope_debug_is_enabled(PurpleDebugLevel level, const char *category)
{
  return 1;
}

static PurpleDebugUiOps debug_ui_ops =
{
  heliotrope_debug_print,
  heliotrope_debug_is_enabled,

  /* padding */
  NULL,
  NULL,
  NULL,
  NULL
};

PurpleDebugUiOps *heliotrope_debug_get_ui_ops()
{
  return &debug_ui_ops;
}

static PurpleBlistUiOps blist_ui_ops = 
{
  NULL, // new_list
  NULL, // new_node
  NULL, // show
  NULL, // update
  NULL, // remove
  NULL, // destroy
  NULL, // set_visible
  NULL, // request_add_buddy
  NULL, // request_add_chat
  NULL, // request_add_group
  NULL, // save_node
  NULL, // remove_node
  NULL, // save_account
  NULL, // _purple_reserved1
};

PurpleBlistUiOps *heliotrope_get_blist_ui_ops()
{
  return &blist_ui_ops;
}
  
//-----------------------------------------------------------------------------

void xfers_python_cb(PurpleXfer *xfer, PyObject *func)
{
  PyGILState_STATE state = PyGILState_Ensure();
  
  PyObject *obj0;
  PyObject *result;

  obj0 = PyCObject_FromVoidPtr(xfer, NULL);
  result = PyEval_CallFunction(func, "(O)", obj0);
  if (result == NULL)
    PyErr_Print();
  
  Py_XDECREF(result);
  Py_XDECREF(obj0);

  PyGILState_Release(state);
}

void set_file_recv_request(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_recv_request_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_recv_request_cb);
  file_recv_request_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-recv-request",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_recv_request_cb);
}

void set_file_recv_accept(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_recv_accept_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_recv_accept_cb);
  file_recv_accept_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-recv-accept",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_recv_accept_cb);
}

void set_file_recv_start(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_recv_start_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_recv_start_cb);
  file_recv_start_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-recv-start",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_recv_start_cb);
}

void set_file_recv_cancel(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_recv_cancel_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_recv_cancel_cb);
  file_recv_cancel_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-recv-cancel",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_recv_cancel_cb);
}

void set_file_recv_complete(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_recv_complete_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_recv_complete_cb);
  file_recv_complete_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-recv-complete",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_recv_complete_cb);
}

void set_file_send_accept(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_send_accept_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_send_accept_cb);
  file_send_accept_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-send-accept",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_send_accept_cb);
}

void set_file_send_start(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_send_start_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_send_start_cb);
  file_send_start_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-send-start",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_send_start_cb);
}

void set_file_send_cancel(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_send_cancel_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_send_cancel_cb);
  file_send_cancel_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-send-cancel",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_send_cancel_cb);
}

void set_file_send_complete(PurplePlugin *plugin, PyObject *func)
{
  static PyObject *file_send_complete_cb = 0;

  Py_XINCREF(func);
  Py_XDECREF(file_send_complete_cb);
  file_send_complete_cb = func;

  purple_signal_connect(purple_xfers_get_handle(), "file-send-complete",
    plugin, PURPLE_CALLBACK(xfers_python_cb), file_send_complete_cb);
}

//-----------------------------------------------------------------------------

void heliotrope_xfire_tooltip_text(PurpleBuddy *buddy) {
  PurplePlugin *prpl;
  PurplePluginProtocolInfo *prpl_info;
  PurpleAccount *account;
  PurpleNotifyUserInfo *user_info;
  PurplePresence *presence;

  user_info = purple_notify_user_info_new();

  account = purple_buddy_get_account(buddy);
  presence = purple_buddy_get_presence(buddy);

  prpl = purple_find_prpl(purple_account_get_protocol_id(account));
  prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
  if (prpl_info && prpl_info->tooltip_text) {
    prpl_info->tooltip_text(buddy, user_info, 0);
  }

  purple_notify_user_info_destroy(user_info);
}

//-----------------------------------------------------------------------------

void *heliotrope_notify_userinfo(PurpleConnection *gc, const char *who,
                            PurpleNotifyUserInfo *user_info)
{
  /* We use purple signals to process this event, so this function
   * is just a stub that does nothing
   */
  return NULL;
}

static PurpleNotifyUiOps heliotrope_notify_ui_ops = {
  NULL,  /* notify_message */
  NULL,  /* notify_email */
  NULL,  /* notify_emails */
  NULL,  /* notify_formatted */
  NULL,  /* notify_searchresults */
  NULL,  /* notify_searchresults_new_rows */
  heliotrope_notify_userinfo,
  NULL,  /* notify_uri */
  NULL,  /* close_notify */
  NULL,  /* _purple_reserved1 */
  NULL,  /* _purple_reserved2 */
  NULL,  /* _purple_reserved3 */
  NULL,  /* _purple_reserved4 */
};

PurpleNotifyUiOps *heliotrope_get_notify_ui_ops()
{
  return &heliotrope_notify_ui_ops;
}
