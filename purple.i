/**
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty.
 **/

%module purple
%{
#include <glib.h>
#ifdef SWIGWIN
#include "internal.h"
#endif
#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "buddyicon.h"
#include "certificate.h"
#include "cipher.h"
#include "circbuffer.h"
#include "cmds.h"
#include "connection.h"
#include "conversation.h"
#include "core.h"
#include "debug.h"
#include "dnsquery.h"
#include "dnssrv.h"
#include "eventloop.h"
#include "ft.h"
#include "idle.h"
#include "imgstore.h"
#include "log.h"
#include "mime.h"
#include "nat-pmp.h"
#include "network.h"
#include "notify.h"
#include "ntlm.h"
#include "plugin.h"
#include "pluginpref.h"
#include "pounce.h"
#include "prefs.h"
#include "privacy.h"
#include "proxy.h"
#include "prpl.h"
#include "request.h"
#include "roomlist.h"
#include "savedstatuses.h"
#include "server.h"
#include "signals.h"
#include "sound.h"
#include "sslconn.h"
#include "status.h"
#include "stringref.h"
#include "stun.h"
#include "upnp.h"
#include "util.h"
#include "value.h"
#include "version.h"
#include "whiteboard.h"
#include "xmlnode.h"

guint gnt_input_add(int, PurpleInputCondition, PurpleInputFunction, gpointer);

gboolean purple_buddy_is_online(PurpleBuddy *b);
void *request_authorize(PurpleAccount *account, const char *remote_user,
  const char *id, const char *alias, const char *message, gboolean on_list,
  PurpleAccountRequestAuthorizationCb authorize_cb,
  PurpleAccountRequestAuthorizationCb deny_cb, void *user_data);
%}

typedef int gboolean;
typedef int PurpleMessageFlags;
typedef int PurpleStatusPrimitive;

typedef void (*PurpleInputFunction)(gpointer, gint, PurpleInputCondition);
typedef void (*PurpleAccountRequestAuthorizationCb)(void *);

typedef struct _GList                GList;
typedef struct _PurpleAccount        PurpleAccount;
typedef struct _PurpleConversation   PurpleConversation;
typedef struct _PurplePlugin         PurplePlugin;
typedef struct _PurpleRoomlistField  PurpleRoomlistField;
typedef char gchar;

%typemap(out) GList *purple_accounts_get_all {
  GList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleAccount, 0));
  }
}

%typemap(out) GList *purple_accounts_get_all_active {
  GList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleAccount, 0));
  }
}

%typemap(out) GList *purple_xfers_get_all {
  GList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleXfer, 0));
  }
}

%typemap(out) GList *purple_notify_user_info_get_entries {
  GList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleNotifyUserInfoEntry, 0));
  }
}

%typemap(out) GList *purple_roomlist_get_fields {
  GList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleRoomlistField, 0));
  }
}

%typemap(out) GList *purple_roomlist_room_get_fields {
  GList *i = 0;
  int n = 0;
  
  $result = PyList_New(0);
  for (i = g_list_first($1); i != 0; i = g_list_next(i)) {
    /* TODO(koyao): This implementation is only good for IRC. 
     * This needs to be fixed if we are to support MUC other than IRC.
     */
    if (n == 0 || n == 2) {
      /* The first and third field of an IRC room is of type gchar* */
      PyList_Append($result, PyString_FromString(i->data));
    } 
    else {
      /* The second field of an IRC room is of type long */
      PyList_Append($result, PyInt_FromLong((long)i->data));
    }
    n++;
  }
}

%typemap(out) GSList *purple_blist_get_buddies {
  GSList *i = 0;
  
  $result = PyList_New(0);
  for (i = g_slist_nth($1, 0); i != 0; i = g_slist_next(i)) {
    PyList_Append($result, SWIG_NewPointerObj(SWIG_as_voidptr(i->data), SWIGTYPE_p__PurpleBuddy, 0));
  }
}

%feature("autodoc") purple_accounts_get_all;
%feature("autodoc") purple_accounts_get_all_active;
%feature("autodoc") purple_notify_user_info_get_entries;

%typemap(out) struct _GList *;

%typemap(out) time_t purple_conv_im_get_type_again {
  $result = PyInt_FromSize_t($1);
}

%feature("autodoc") purple_account_new;
%feature("autodoc") purple_account_destroy;
%feature("autodoc") purple_account_connect;
%feature("autodoc") purple_account_set_register_callback;
%feature("autodoc") purple_account_disconnect;
%feature("autodoc") purple_account_notify_added;
%feature("autodoc") purple_account_request_add;
%feature("autodoc") purple_account_request_authorization;
%feature("autodoc") purple_account_request_close_with_account;
%feature("autodoc") purple_account_request_close;
%feature("autodoc") purple_account_request_password;
%feature("autodoc") purple_account_request_change_password;
%feature("autodoc") purple_account_request_change_user_info;
%feature("autodoc") purple_account_set_username;
%feature("autodoc") purple_account_set_password;
%feature("autodoc") purple_account_set_alias;
%feature("autodoc") purple_account_set_user_info;
%feature("autodoc") purple_account_set_buddy_icon_path;
%feature("autodoc") purple_account_set_protocol_id;
%feature("autodoc") purple_account_set_connection;
%feature("autodoc") purple_account_set_remember_password;
%feature("autodoc") purple_account_set_check_mail;
%feature("autodoc") purple_account_set_enabled;
%feature("autodoc") purple_account_set_proxy_info;
%feature("autodoc") purple_account_set_status_types;
%feature("autodoc") purple_account_set_status_list;
%feature("autodoc") purple_account_set_status;
%feature("autodoc") purple_account_clear_settings;
%feature("autodoc") purple_account_set_int;
%feature("autodoc") purple_account_set_string;
%feature("autodoc") purple_account_set_bool;
%feature("autodoc") purple_account_set_ui_int;
%feature("autodoc") purple_account_set_ui_string;
%feature("autodoc") purple_account_set_ui_bool;
%feature("autodoc") purple_account_is_connected;
%feature("autodoc") purple_account_is_connecting;
%feature("autodoc") purple_account_is_disconnected;
%feature("autodoc") purple_account_get_username;
%feature("autodoc") purple_account_get_password;
%feature("autodoc") purple_account_get_alias;
%feature("autodoc") purple_account_get_user_info;
%feature("autodoc") purple_account_get_buddy_icon_path;
%feature("autodoc") purple_account_get_protocol_id;
%feature("autodoc") purple_account_get_protocol_name;
%feature("autodoc") purple_account_get_connection;
%feature("autodoc") purple_account_get_remember_password;
%feature("autodoc") purple_account_get_check_mail;
%feature("autodoc") purple_account_get_enabled;
%feature("autodoc") purple_account_get_proxy_info;
%feature("autodoc") purple_account_get_active_status;
%feature("autodoc") purple_account_get_status;
%feature("autodoc") purple_account_get_status_type;
%feature("autodoc") purple_account_get_status_type_with_primitive;
%feature("autodoc") purple_account_get_presence;
%feature("autodoc") purple_account_is_status_active;
%feature("autodoc") purple_account_get_status_types;
%feature("autodoc") purple_account_get_int;
%feature("autodoc") purple_account_get_string;
%feature("autodoc") purple_account_get_bool;
%feature("autodoc") purple_account_get_ui_int;
%feature("autodoc") purple_account_get_ui_string;
%feature("autodoc") purple_account_get_ui_bool;
%feature("autodoc") purple_account_get_log;
%feature("autodoc") purple_account_destroy_log;
%feature("autodoc") purple_account_add_buddy;
%feature("autodoc") purple_account_add_buddies;
%feature("autodoc") purple_account_remove_buddy;
%feature("autodoc") purple_account_remove_buddies;
%feature("autodoc") purple_account_remove_group;
%feature("autodoc") purple_account_change_password;
%feature("autodoc") purple_account_supports_offline_message;
%feature("autodoc") purple_account_get_current_error;
%feature("autodoc") purple_account_clear_current_error;
%feature("autodoc") purple_accounts_add;
%feature("autodoc") purple_accounts_remove;
%feature("autodoc") purple_accounts_delete;
%feature("autodoc") purple_accounts_reorder;
%feature("autodoc") purple_accounts_find;
%feature("autodoc") purple_accounts_restore_current_statuses;
%feature("autodoc") purple_accounts_set_ui_ops;
%feature("autodoc") purple_accounts_get_ui_ops;
%feature("autodoc") purple_accounts_get_handle;
%feature("autodoc") purple_accounts_init;
%feature("autodoc") purple_accounts_uninit;

%feature("autodoc") purple_account_option_string_new;
%feature("autodoc") purple_account_option_list_new;
%feature("autodoc") purple_account_option_new;
%feature("autodoc") purple_account_option_bool_new;
%feature("autodoc") purple_account_option_int_new;
%feature("autodoc") purple_account_option_destroy;
%feature("autodoc") purple_account_option_set_default_bool;
%feature("autodoc") purple_account_option_set_default_int;
%feature("autodoc") purple_account_option_set_default_string;
%feature("autodoc") purple_account_option_set_masked;
%feature("autodoc") purple_account_option_set_list;
%feature("autodoc") purple_account_option_add_list_item;
%feature("autodoc") purple_account_option_get_type;
%feature("autodoc") purple_account_option_get_text;
%feature("autodoc") purple_account_option_get_setting;
%feature("autodoc") purple_account_option_get_default_bool;
%feature("autodoc") purple_account_option_get_default_int;
%feature("autodoc") purple_account_option_get_default_string;
%feature("autodoc") purple_account_option_get_default_list_value;
%feature("autodoc") purple_account_option_get_masked;
%feature("autodoc") purple_account_option_get_list;

%feature("autodoc") purple_blist_node_get_type;
%feature("autodoc") purple_blist_new;
%feature("autodoc") purple_blist_get_root;
%feature("autodoc") purple_blist_node_get_parent;
%feature("autodoc") purple_blist_node_get_first_child;
%feature("autodoc") purple_blist_node_get_sibling_next;
%feature("autodoc") purple_blist_node_get_sibling_prev;
%feature("autodoc") purple_blist_node_next;
%feature("autodoc") purple_blist_node_get_first_child;
%feature("autodoc") purple_blist_node_get_sibling_next;
%feature("autodoc") purple_blist_node_get_sibling_prev;
%feature("autodoc") purple_blist_node_get_parent;
%feature("autodoc") purple_blist_node_get_sibling_next;
%feature("autodoc") purple_blist_node_get_first_child;
%feature("autodoc") purple_blist_show;
%feature("autodoc") purple_blist_destroy;
%feature("autodoc") purple_blist_set_visible;
%feature("autodoc") purple_blist_update_buddy_status;
%feature("autodoc") purple_blist_update_buddy_icon;
%feature("autodoc") purple_blist_rename_buddy;
%feature("autodoc") purple_blist_alias_contact;
%feature("autodoc") purple_blist_alias_buddy;
%feature("autodoc") purple_blist_server_alias_buddy;
%feature("autodoc") purple_blist_alias_chat;
%feature("autodoc") purple_blist_rename_group;
%feature("autodoc") purple_blist_add_chat;
%feature("autodoc") purple_blist_add_buddy;
%feature("autodoc") purple_blist_add_group;
%feature("autodoc") purple_blist_add_contact;
%feature("autodoc") purple_blist_merge_contact;
%feature("autodoc") purple_blist_remove_buddy;
%feature("autodoc") purple_blist_remove_contact;
%feature("autodoc") purple_blist_remove_chat;
%feature("autodoc") purple_blist_remove_group;
%feature("autodoc") purple_blist_find_chat;
%feature("autodoc") purple_blist_add_account;
%feature("autodoc") purple_blist_remove_account;
%feature("autodoc") purple_blist_get_group_size;
%feature("autodoc") purple_blist_get_group_online_count;
%feature("autodoc") purple_blist_load;
%feature("autodoc") purple_blist_schedule_save;
%feature("autodoc") purple_blist_request_add_buddy;
%feature("autodoc") purple_blist_request_add_chat;
%feature("autodoc") purple_blist_request_add_group;
%feature("autodoc") purple_blist_node_set_bool;
%feature("autodoc") purple_blist_node_get_bool;
%feature("autodoc") purple_blist_node_set_int;
%feature("autodoc") purple_blist_node_get_int;
%feature("autodoc") purple_blist_node_set_string;
%feature("autodoc") purple_blist_node_get_string;
%feature("autodoc") purple_blist_node_remove_setting;
%feature("autodoc") purple_blist_node_get_flags;
%feature("autodoc") purple_blist_node_set_flags;
%feature("autodoc") purple_blist_node_get_extended_menu;
%feature("autodoc") purple_blist_set_ui_ops;
%feature("autodoc") purple_blist_get_ui_ops;
%feature("autodoc") purple_blist_get_handle;
%feature("autodoc") purple_blist_init;
%feature("autodoc") purple_blist_uninit;

%feature("autodoc") purple_buddy_icon_new;
%feature("autodoc") purple_buddy_icon_ref;
%feature("autodoc") purple_buddy_icon_unref;
%feature("autodoc") purple_buddy_icon_update;
%feature("autodoc") purple_buddy_icon_set_data;
%feature("autodoc") purple_buddy_icon_get_account;
%feature("autodoc") purple_buddy_icon_get_username;
%feature("autodoc") purple_buddy_icon_get_checksum;
%feature("autodoc") purple_buddy_icon_get_data;
%feature("autodoc") purple_buddy_icon_get_extension;
%feature("autodoc") purple_buddy_icon_get_full_path;
%feature("autodoc") purple_buddy_icons_set_for_user;
%feature("autodoc") purple_buddy_icons_get_checksum_for_user;
%feature("autodoc") purple_buddy_icons_find;
%feature("autodoc") purple_buddy_icons_has_custom_icon;
%feature("autodoc") purple_buddy_icons_find_account_icon;
%feature("autodoc") purple_buddy_icons_set_account_icon;
%feature("autodoc") purple_buddy_icons_get_account_icon_timestamp;
%feature("autodoc") purple_buddy_icons_find_custom_icon;
%feature("autodoc") purple_buddy_icons_set_custom_icon;
%feature("autodoc") purple_buddy_icons_set_caching;
%feature("autodoc") purple_buddy_icons_is_caching;
%feature("autodoc") purple_buddy_icons_set_cache_dir;
%feature("autodoc") purple_buddy_icons_get_cache_dir;
%feature("autodoc") purple_buddy_icons_get_handle;
%feature("autodoc") purple_buddy_icons_init;
%feature("autodoc") purple_buddy_icons_uninit;
%feature("autodoc") purple_buddy_icon_get_scale_size;

%feature("autodoc") purple_certificate_register_pool;
%feature("autodoc") purple_certificate_unregister_pool;
%feature("autodoc") purple_certificate_register_scheme;
%feature("autodoc") purple_certificate_export;
%feature("autodoc") purple_certificate_signed_by;
%feature("autodoc") purple_certificate_get_subject_name;
%feature("autodoc") purple_certificate_check_subject_name;
%feature("autodoc") purple_certificate_register_verifier;
%feature("autodoc") purple_certificate_verify;
%feature("autodoc") purple_certificate_find_verifier;
%feature("autodoc") purple_certificate_verify_complete;
%feature("autodoc") purple_certificate_copy;
%feature("autodoc") purple_certificate_copy_list;
%feature("autodoc") purple_certificate_destroy;
%feature("autodoc") purple_certificate_destroy_list;
%feature("autodoc") purple_certificate_check_signature_chain;
%feature("autodoc") purple_certificate_get_fingerprint_sha;
%feature("autodoc") purple_certificate_get_unique_id;
%feature("autodoc") purple_certificate_get_issuer_unique_id;
%feature("autodoc") purple_certificate_get_times;
%feature("autodoc") purple_certificate_pool_mkpath;
%feature("autodoc") purple_certificate_pool_usable;
%feature("autodoc") purple_certificate_pool_get_scheme;
%feature("autodoc") purple_certificate_pool_contains;
%feature("autodoc") purple_certificate_pool_retrieve;
%feature("autodoc") purple_certificate_pool_store;
%feature("autodoc") purple_certificate_pool_delete;
%feature("autodoc") purple_certificate_pool_destroy_idlist;
%feature("autodoc") purple_certificate_pool_get_idlist;
%feature("autodoc") purple_certificate_init;
%feature("autodoc") purple_certificate_uninit;
%feature("autodoc") purple_certificate_get_handle;
%feature("autodoc") purple_certificate_find_scheme;
%feature("autodoc") purple_certificate_get_schemes;
%feature("autodoc") purple_certificate_unregister_scheme;
%feature("autodoc") purple_certificate_get_verifiers;
%feature("autodoc") purple_certificate_unregister_verifier;
%feature("autodoc") purple_certificate_find_pool;
%feature("autodoc") purple_certificate_get_pools;
%feature("autodoc") purple_certificate_display_x;
%feature("autodoc") purple_certificate_add_ca_search_path;

%feature("autodoc") purple_cipher_get_name;
%feature("autodoc") purple_cipher_get_capabilities;
%feature("autodoc") purple_cipher_digest_region;
%feature("autodoc") purple_ciphers_find_cipher;
%feature("autodoc") purple_ciphers_register_cipher;
%feature("autodoc") purple_ciphers_unregister_cipher;
%feature("autodoc") purple_ciphers_get_ciphers;
%feature("autodoc") purple_ciphers_get_handle;
%feature("autodoc") purple_ciphers_init;
%feature("autodoc") purple_ciphers_uninit;
%feature("autodoc") purple_cipher_context_set_option;
%feature("autodoc") purple_cipher_context_get_option;
%feature("autodoc") purple_cipher_context_new;
%feature("autodoc") purple_cipher_context_new_by_name;
%feature("autodoc") purple_cipher_context_reset;
%feature("autodoc") purple_cipher_context_destroy;
%feature("autodoc") purple_cipher_context_set_iv;
%feature("autodoc") purple_cipher_context_append;
%feature("autodoc") purple_cipher_context_digest;
%feature("autodoc") purple_cipher_context_digest_to_str;
%feature("autodoc") purple_cipher_context_encrypt;
%feature("autodoc") purple_cipher_context_decrypt;
%feature("autodoc") purple_cipher_context_set_salt;
%feature("autodoc") purple_cipher_context_get_salt_size;
%feature("autodoc") purple_cipher_context_set_key;
%feature("autodoc") purple_cipher_context_get_key_size;
%feature("autodoc") purple_cipher_context_set_batch_mode;
%feature("autodoc") purple_cipher_context_get_batch_mode;
%feature("autodoc") purple_cipher_context_get_block_size;
%feature("autodoc") purple_cipher_context_set_key_with_len;
%feature("autodoc") purple_cipher_context_set_data;
%feature("autodoc") purple_cipher_context_get_data;
%feature("autodoc") purple_cipher_http_digest_calculate_session_key;
%feature("autodoc") purple_cipher_http_digest_calculate_response;

%feature("autodoc") purple_circ_buffer_destroy;
%feature("autodoc") purple_circ_buffer_new;
%feature("autodoc") purple_circ_buffer_append;
%feature("autodoc") purple_circ_buffer_mark_read;
%feature("autodoc") purple_circ_buffer_get_max_read;

%feature("autodoc") purple_cmd_do_command;
%feature("autodoc") purple_cmd_list;
%feature("autodoc") purple_cmd_help;

%feature("autodoc") purple_connection_error_reason;
%feature("autodoc") purple_connections_set_ui_ops;
%feature("autodoc") purple_connection_update_progress;
%feature("autodoc") purple_connection_notice;
%feature("autodoc") purple_connection_error;
%feature("autodoc") purple_connection_error_is_fatal;
%feature("autodoc") purple_connection_new;
%feature("autodoc") purple_connection_new_unregister;
%feature("autodoc") purple_connection_destroy;
%feature("autodoc") purple_connection_set_state;
%feature("autodoc") purple_connection_set_account;
%feature("autodoc") purple_connection_set_display_name;
%feature("autodoc") purple_connection_get_state;
%feature("autodoc") purple_connection_get_account;
%feature("autodoc") purple_connection_get_prpl;
%feature("autodoc") purple_connection_get_password;
%feature("autodoc") purple_connection_get_display_name;
%feature("autodoc") purple_connection_ssl_error;
%feature("autodoc") purple_connections_disconnect_all;
%feature("autodoc") purple_connections_get_all;
%feature("autodoc") purple_connections_get_connecting;
%feature("autodoc") purple_connections_get_ui_ops;
%feature("autodoc") purple_connections_init;
%feature("autodoc") purple_connections_uninit;
%feature("autodoc") purple_connections_get_handle;

%feature("autodoc") purple_conversation_write;
%feature("autodoc") purple_conversation_new;
%feature("autodoc") purple_conversation_destroy;
%feature("autodoc") purple_conversation_present;
%feature("autodoc") purple_conversation_get_type;
%feature("autodoc") purple_conversation_set_ui_ops;
%feature("autodoc") purple_conversations_set_ui_ops;
%feature("autodoc") purple_conversation_get_ui_ops;
%feature("autodoc") purple_conversation_set_account;
%feature("autodoc") purple_conversation_get_account;
%feature("autodoc") purple_conversation_get_user;
%feature("autodoc") purple_conversation_get_gc;
%feature("autodoc") purple_conversation_set_title;
%feature("autodoc") purple_conversation_get_title;
%feature("autodoc") purple_conversation_autoset_title;
%feature("autodoc") purple_conversation_set_name;
%feature("autodoc") purple_conversation_get_name;
%feature("autodoc") purple_conversation_set_logging;
%feature("autodoc") purple_conversation_is_logging;
%feature("autodoc") purple_conversation_close_logs;
%feature("autodoc") purple_conversation_get_im_data;
%feature("autodoc") purple_conversation_get_chat_data;
%feature("autodoc") purple_conversation_set_data;
%feature("autodoc") purple_conversation_get_data;
%feature("autodoc") purple_conversation_set_features;
%feature("autodoc") purple_conversation_get_features;
%feature("autodoc") purple_conversation_has_focus;
%feature("autodoc") purple_conversation_update;
%feature("autodoc") purple_conversation_foreach;
%feature("autodoc") purple_conversation_get_message_history;
%feature("autodoc") purple_conversation_clear_message_history;
%feature("autodoc") purple_conversation_message_get_sender;
%feature("autodoc") purple_conversation_message_get_message;
%feature("autodoc") purple_conversation_message_get_flags;
%feature("autodoc") purple_conversation_message_get_timestamp;
%feature("autodoc") purple_conversation_get_extended_menu;
%feature("autodoc") purple_conversation_do_command;
%feature("autodoc") purple_conversations_get_handle;
%feature("autodoc") purple_conversations_init;
%feature("autodoc") purple_conversations_uninit;

%feature("autodoc") purple_core_init;
%feature("autodoc") purple_core_quitcb;
%feature("autodoc") purple_core_quit;
%feature("autodoc") purple_core_quit_cb;
%feature("autodoc") purple_core_get_version;
%feature("autodoc") purple_core_get_ui;
%feature("autodoc") purple_core_set_ui_ops;
%feature("autodoc") purple_core_get_ui_ops;
%feature("autodoc") purple_core_migrate;
%feature("autodoc") purple_core_ensure_single_instance;
%feature("autodoc") purple_core_get_ui_info;

%rename("_print") print;
%feature("autodoc") purple_debug_misc;
%feature("autodoc") purple_debug_info;
%feature("autodoc") purple_debug_warning;
%feature("autodoc") purple_debug_error;
%feature("autodoc") purple_debug_fatal;
%feature("autodoc") purple_debug_set_enabled;
%feature("autodoc") purple_debug_is_enabled;
%feature("autodoc") purple_debug_set_ui_ops;
%feature("autodoc") purple_debug_get_ui_ops;
%feature("autodoc") purple_debug_init;

%feature("autodoc") purple_dnsquery_a;
%feature("autodoc") purple_dnsquery_destroy;
%feature("autodoc") purple_dnsquery_set_ui_ops;
%feature("autodoc") purple_dnsquery_get_ui_ops;
%feature("autodoc") purple_dnsquery_get_host;
%feature("autodoc") purple_dnsquery_get_port;
%feature("autodoc") purple_dnsquery_init;
%feature("autodoc") purple_dnsquery_uninit;

%feature("autodoc") purple_srv_resolve;
%feature("autodoc") purple_srv_cancel;

%feature("autodoc") purple_eventloop_set_ui_ops;
%feature("autodoc") purple_eventloop_get_ui_ops;

%feature("autodoc") purple_xfer_start;
%feature("autodoc") purple_xfer_ref;
%feature("autodoc") purple_xfer_new;
%feature("autodoc") purple_xfers_get_all;
%feature("autodoc") purple_xfer_unref;
%feature("autodoc") purple_xfer_destroy;
%feature("autodoc") purple_xfer_request;
%feature("autodoc") purple_xfer_request_accepted;
%feature("autodoc") purple_xfer_request_denied;
%feature("autodoc") purple_xfer_get_type;
%feature("autodoc") purple_xfer_get_account;
%feature("autodoc") purple_xfer_get_remote_user;
%feature("autodoc") purple_xfer_get_status;
%feature("autodoc") purple_xfer_is_canceled;
%feature("autodoc") purple_xfer_is_completed;
%feature("autodoc") purple_xfer_get_filename;
%feature("autodoc") purple_xfer_get_local_filename;
%feature("autodoc") purple_xfer_get_bytes_sent;
%feature("autodoc") purple_xfer_get_bytes_remaining;
%feature("autodoc") purple_xfer_get_size;
%feature("autodoc") purple_xfer_get_progress;
%feature("autodoc") purple_xfer_get_local_port;
%feature("autodoc") purple_xfer_get_remote_ip;
%feature("autodoc") purple_xfer_get_remote_port;
%feature("autodoc") purple_xfer_get_start_time;
%feature("autodoc") purple_xfer_get_end_time;
%feature("autodoc") purple_xfer_set_completed;
%feature("autodoc") purple_xfer_set_message;
%feature("autodoc") purple_xfer_set_filename;
%feature("autodoc") purple_xfer_set_local_filename;
%feature("autodoc") purple_xfer_set_size;
%feature("autodoc") purple_xfer_set_bytes_sent;
%feature("autodoc") purple_xfer_get_ui_ops;
%feature("autodoc") purple_xfer_set_read_fnc;
%feature("autodoc") purple_xfer_set_write_fnc;
%feature("autodoc") purple_xfer_set_ack_fnc;
%feature("autodoc") purple_xfer_set_request_denied_fnc;
%feature("autodoc") purple_xfer_set_init_fnc;
%feature("autodoc") purple_xfer_set_start_fnc;
%feature("autodoc") purple_xfer_set_end_fnc;
%feature("autodoc") purple_xfer_set_cancel_send_fnc;
%feature("autodoc") purple_xfer_set_cancel_recv_fnc;
%feature("autodoc") purple_xfer_read;
%feature("autodoc") purple_xfer_write;
%feature("autodoc") purple_xfer_end;
%feature("autodoc") purple_xfer_add;
%feature("autodoc") purple_xfer_cancel_local;
%feature("autodoc") purple_xfer_cancel_remote;
%feature("autodoc") purple_xfer_error;
%feature("autodoc") purple_xfer_update_progress;
%feature("autodoc") purple_xfer_conversation_write;
%feature("autodoc") purple_xfers_get_handle;
%feature("autodoc") purple_xfers_init;
%feature("autodoc") purple_xfers_uninit;
%feature("autodoc") purple_xfers_set_ui_ops;
%feature("autodoc") purple_xfers_get_ui_ops;

%feature("autodoc") purple_idle_touch;
%feature("autodoc") purple_idle_set;
%feature("autodoc") purple_idle_set_ui_ops;
%feature("autodoc") purple_idle_get_ui_ops;
%feature("autodoc") purple_idle_init;
%feature("autodoc") purple_idle_uninit;

%feature("autodoc") purple_imgstore_add_with_id;
%feature("autodoc") purple_imgstore_add;
%feature("autodoc") purple_imgstore_find_by_id;
%feature("autodoc") purple_imgstore_get_data;
%feature("autodoc") purple_imgstore_get_size;
%feature("autodoc") purple_imgstore_get_filename;
%feature("autodoc") purple_imgstore_get_extension;
%feature("autodoc") purple_imgstore_ref;
%feature("autodoc") purple_imgstore_ref_by_id;
%feature("autodoc") purple_imgstore_unref;
%feature("autodoc") purple_imgstore_unref_by_id;
%feature("autodoc") purple_imgstore_get_handle;
%feature("autodoc") purple_imgstore_init;
%feature("autodoc") purple_imgstore_uninit;

%feature("autodoc") purple_log_common_writer;
%feature("autodoc") purple_log_get_logs;
%feature("autodoc") purple_log_new;
%feature("autodoc") purple_log_free;
%feature("autodoc") purple_log_write;
%feature("autodoc") purple_log_read;
%feature("autodoc") purple_log_list;
%feature("autodoc") purple_log_set_free;
%feature("autodoc") purple_log_get_log_sets;
%feature("autodoc") purple_log_get_system_logs;
%feature("autodoc") purple_log_get_size;
%feature("autodoc") purple_log_get_total_size;
%feature("autodoc") purple_log_delete;
%feature("autodoc") purple_log_is_deletable;
%feature("autodoc") purple_log_get_log_dir;
%feature("autodoc") purple_log_compare;
%feature("autodoc") purple_log_set_compare;
%feature("autodoc") purple_log_logger_new;
%feature("autodoc") purple_log_common_lister;
%feature("autodoc") purple_log_common_total_sizer;
%feature("autodoc") purple_log_common_sizer;
%feature("autodoc") purple_log_common_deleter;
%feature("autodoc") purple_log_common_is_deletable;
%feature("autodoc") purple_log_logger_free;
%feature("autodoc") purple_log_logger_add;
%feature("autodoc") purple_log_logger_remove;
%feature("autodoc") purple_log_logger_set;
%feature("autodoc") purple_log_logger_get;
%feature("autodoc") purple_log_logger_get_options;
%feature("autodoc") purple_log_init;
%feature("autodoc") purple_log_get_handle;
%feature("autodoc") purple_log_uninit;

%feature("autodoc") purple_mime_document_new;
%feature("autodoc") purple_mime_document_free;
%feature("autodoc") purple_mime_document_parse;
%feature("autodoc") purple_mime_document_parsen;
%feature("autodoc") purple_mime_document_write;
%feature("autodoc") purple_mime_document_get_fields;
%feature("autodoc") purple_mime_document_get_field;
%feature("autodoc") purple_mime_document_set_field;
%feature("autodoc") purple_mime_document_get_parts;
%feature("autodoc") purple_mime_part_new;
%feature("autodoc") purple_mime_part_get_fields;
%feature("autodoc") purple_mime_part_get_field;
%feature("autodoc") purple_mime_part_get_field_decoded;
%feature("autodoc") purple_mime_part_set_field;
%feature("autodoc") purple_mime_part_get_data;
%feature("autodoc") purple_mime_part_get_data_decoded;
%feature("autodoc") purple_mime_part_get_length;
%feature("autodoc") purple_mime_part_set_data;

%feature("autodoc") purple_pmp_init;
%feature("autodoc") purple_pmp_get_public_ip;
%feature("autodoc") purple_pmp_create_map;
%feature("autodoc") purple_pmp_destroy_map;

%feature("autodoc") purple_network_ip_atoi;
%feature("autodoc") purple_network_set_public_ip;
%feature("autodoc") purple_network_get_public_ip;
%feature("autodoc") purple_network_get_local_system_ip;
%feature("autodoc") purple_network_get_my_ip;
%feature("autodoc") purple_network_listen_range;
%feature("autodoc") purple_network_listen_map_external;
%feature("autodoc") purple_network_listen;
%feature("autodoc") purple_network_listen_cancel;
%feature("autodoc") purple_network_get_port_from_fd;
%feature("autodoc") purple_network_is_available;
%feature("autodoc") purple_network_get_handle;
%feature("autodoc") purple_network_init;
%feature("autodoc") purple_network_uninit;

%feature("autodoc") purple_notify_searchresults;
%feature("autodoc") purple_notify_searchresults_free;
%feature("autodoc") purple_notify_searchresults_new_rows;
%feature("autodoc") purple_notify_searchresults_button_add;
%feature("autodoc") purple_notify_searchresults_button_add_labeled;
%feature("autodoc") purple_notify_searchresults_new;
%feature("autodoc") purple_notify_searchresults_column_new;
%feature("autodoc") purple_notify_searchresults_column_add;
%feature("autodoc") purple_notify_searchresults_row_add;
%feature("autodoc") purple_notify_searchresults_get_rows_count;
%feature("autodoc") purple_notify_searchresults_get_columns_count;
%feature("autodoc") purple_notify_searchresults_row_get;
%feature("autodoc") purple_notify_searchresults_column_get_title;
%feature("autodoc") purple_notify_message;
%feature("autodoc") purple_notify_email;
%feature("autodoc") purple_notify_emails;
%feature("autodoc") purple_notify_formatted;
%feature("autodoc") purple_notify_userinfo;
%feature("autodoc") purple_notify_user_info_new;
%feature("autodoc") purple_notify_user_info_destroy;
%feature("autodoc") purple_notify_user_info_remove_entry;
%feature("autodoc") purple_notify_user_info_get_entries;
%feature("autodoc") purple_notify_user_info_get_text_with_newline;
%feature("autodoc") purple_notify_user_info_add_pair;
%feature("autodoc") purple_notify_user_info_prepend_pair;
%feature("autodoc") purple_notify_user_info_entry_new;
%feature("autodoc") purple_notify_user_info_add_section_break;
%feature("autodoc") purple_notify_user_info_add_section_header;
%feature("autodoc") purple_notify_user_info_remove_last_item;
%feature("autodoc") purple_notify_user_info_entry_get_label;
%feature("autodoc") purple_notify_user_info_entry_set_label;
%feature("autodoc") purple_notify_user_info_entry_get_value;
%feature("autodoc") purple_notify_user_info_entry_set_value;
%feature("autodoc") purple_notify_user_info_entry_get_type;
%feature("autodoc") purple_notify_user_info_entry_set_type;
%feature("autodoc") purple_notify_uri;
%feature("autodoc") purple_notify_close;
%feature("autodoc") purple_notify_close_with_handle;
%feature("autodoc") purple_notify_message;
%feature("autodoc") purple_notify_info;
%feature("autodoc") purple_notify_warning;
%feature("autodoc") purple_notify_error;
%feature("autodoc") purple_notify_set_ui_ops;
%feature("autodoc") purple_notify_get_ui_ops;
%feature("autodoc") purple_notify_get_handle;
%feature("autodoc") purple_notify_init;
%feature("autodoc") purple_notify_uninit;

%feature("autodoc") purple_ntlm_gen_type;
%feature("autodoc") purple_ntlm_parse_type;

%feature("autodoc") purple_plugin_new;
%feature("autodoc") purple_plugin_load;
%feature("autodoc") purple_plugin_destroy;
%feature("autodoc") purple_plugin_reload;
%feature("autodoc") purple_plugins_save_loaded;
%feature("autodoc") purple_plugin_disable;
%feature("autodoc") purple_plugin_unload;
%feature("autodoc") purple_plugin_is_loaded;
%feature("autodoc") purple_plugin_is_unloadable;
%feature("autodoc") purple_plugin_get_id;
%feature("autodoc") purple_plugin_get_name;
%feature("autodoc") purple_plugin_get_version;
%feature("autodoc") purple_plugin_get_summary;
%feature("autodoc") purple_plugin_get_description;
%feature("autodoc") purple_plugin_get_author;
%feature("autodoc") purple_plugin_get_homepage;
%feature("autodoc") purple_plugin_ipc_register;
%feature("autodoc") purple_plugin_ipc_unregister;
%feature("autodoc") purple_plugin_ipc_unregister_all;
%feature("autodoc") purple_plugin_ipc_get_params;
%feature("autodoc") purple_plugin_ipc_call;
%feature("autodoc") purple_plugins_add_search_path;
%feature("autodoc") purple_plugins_unload_all;
%feature("autodoc") purple_plugins_destroy_all;
%feature("autodoc") purple_plugins_load_saved;
%feature("autodoc") purple_plugin_set_probe_path;
%feature("autodoc") purple_plugins_enabled;
%feature("autodoc") purple_plugins_register_probe_notify_cb;
%feature("autodoc") purple_plugins_unregister_probe_notify_cb;
%feature("autodoc") purple_plugins_register_load_notify_cb;
%feature("autodoc") purple_plugins_unregister_load_notify_cb;
%feature("autodoc") purple_plugins_register_unload_notify_cb;
%feature("autodoc") purple_plugins_unregister_unload_notify_cb;
%feature("autodoc") purple_plugins_find_with_name;
%feature("autodoc") purple_plugins_find_with_filename;
%feature("autodoc") purple_plugins_find_with_basename;
%feature("autodoc") purple_plugins_find_with_id;
%feature("autodoc") purple_plugins_get_loaded;
%feature("autodoc") purple_plugins_get_protocols;
%feature("autodoc") purple_plugins_get_all;
%feature("autodoc") purple_plugins_get_handle;
%feature("autodoc") purple_plugins_init;
%feature("autodoc") purple_plugins_uninit;
%feature("autodoc") purple_plugin_action_new;
%feature("autodoc") purple_plugin_action_free;

%feature("autodoc") purple_plugin_pref_frame_new;
%feature("autodoc") purple_plugin_pref_frame_destroy;
%feature("autodoc") purple_plugin_pref_frame_add;
%feature("autodoc") purple_plugin_pref_frame_get_prefs;
%feature("autodoc") purple_plugin_pref_new;
%feature("autodoc") purple_plugin_pref_new_with_name;
%feature("autodoc") purple_plugin_pref_new_with_label;
%feature("autodoc") purple_plugin_pref_new_with_name_and_label;
%feature("autodoc") purple_plugin_pref_destroy;
%feature("autodoc") purple_plugin_pref_set_name;
%feature("autodoc") purple_plugin_pref_get_name;
%feature("autodoc") purple_plugin_pref_set_label;
%feature("autodoc") purple_plugin_pref_get_label;
%feature("autodoc") purple_plugin_pref_set_bounds;
%feature("autodoc") purple_plugin_pref_get_bounds;
%feature("autodoc") purple_plugin_pref_set_type;
%feature("autodoc") purple_plugin_pref_get_type;
%feature("autodoc") purple_plugin_pref_add_choice;
%feature("autodoc") purple_plugin_pref_get_choices;
%feature("autodoc") purple_plugin_pref_set_max_length;
%feature("autodoc") purple_plugin_pref_get_max_length;
%feature("autodoc") purple_plugin_pref_set_masked;
%feature("autodoc") purple_plugin_pref_get_masked;
%feature("autodoc") purple_plugin_pref_set_format_type;
%feature("autodoc") purple_plugin_pref_get_format_type;

%feature("autodoc") purple_pounce_new;
%feature("autodoc") purple_pounce_destroy;
%feature("autodoc") purple_pounce_destroy_all_by_account;
%feature("autodoc") purple_pounce_set_events;
%feature("autodoc") purple_pounce_set_options;
%feature("autodoc") purple_pounce_set_pouncer;
%feature("autodoc") purple_pounce_set_pouncee;
%feature("autodoc") purple_pounce_set_save;
%feature("autodoc") purple_pounce_action_register;
%feature("autodoc") purple_pounce_action_set_enabled;
%feature("autodoc") purple_pounce_action_set_attribute;
%feature("autodoc") purple_pounce_set_data;
%feature("autodoc") purple_pounce_get_events;
%feature("autodoc") purple_pounce_get_options;
%feature("autodoc") purple_pounce_get_pouncer;
%feature("autodoc") purple_pounce_get_pouncee;
%feature("autodoc") purple_pounce_get_save;
%feature("autodoc") purple_pounce_action_is_enabled;
%feature("autodoc") purple_pounce_action_get_attribute;
%feature("autodoc") purple_pounce_get_data;
%feature("autodoc") purple_pounce_execute;
%feature("autodoc") purple_pounces_load;
%feature("autodoc") purple_pounces_register_handler;
%feature("autodoc") purple_pounces_unregister_handler;
%feature("autodoc") purple_pounces_get_all;
%feature("autodoc") purple_pounces_get_all_for_ui;
%feature("autodoc") purple_pounces_get_handle;
%feature("autodoc") purple_pounces_init;
%feature("autodoc") purple_pounces_uninit;

%feature("autodoc") purple_prefs_get_string_list;
%feature("autodoc") purple_prefs_connect_callback;
%feature("autodoc") purple_prefs_get_handle;
%feature("autodoc") purple_prefs_init;
%feature("autodoc") purple_prefs_uninit;
%feature("autodoc") purple_prefs_add_none;
%feature("autodoc") purple_prefs_add_bool;
%feature("autodoc") purple_prefs_add_int;
%feature("autodoc") purple_prefs_add_string;
%feature("autodoc") purple_prefs_add_string_list;
%feature("autodoc") purple_prefs_add_path;
%feature("autodoc") purple_prefs_add_path_list;
%feature("autodoc") purple_prefs_remove;
%feature("autodoc") purple_prefs_rename;
%feature("autodoc") purple_prefs_rename_boolean_toggle;
%feature("autodoc") purple_prefs_destroy;
%feature("autodoc") purple_prefs_set_generic;
%feature("autodoc") purple_prefs_set_bool;
%feature("autodoc") purple_prefs_set_int;
%feature("autodoc") purple_prefs_set_string;
%feature("autodoc") purple_prefs_set_string_list;
%feature("autodoc") purple_prefs_set_path;
%feature("autodoc") purple_prefs_set_path_list;
%feature("autodoc") purple_prefs_exists;
%feature("autodoc") purple_prefs_get_type;
%feature("autodoc") purple_prefs_get_bool;
%feature("autodoc") purple_prefs_get_int;
%feature("autodoc") purple_prefs_get_string;
%feature("autodoc") purple_prefs_get_path;
%feature("autodoc") purple_prefs_get_path_list;
%feature("autodoc") purple_prefs_get_children_names;
%feature("autodoc") purple_prefs_disconnect_callback;
%feature("autodoc") purple_prefs_disconnect_by_handle;
%feature("autodoc") purple_prefs_trigger_callback;
%feature("autodoc") purple_prefs_load;
%feature("autodoc") purple_prefs_update_old;

%feature("autodoc") purple_privacy_permit_add;
%feature("autodoc") purple_privacy_permit_remove;
%feature("autodoc") purple_privacy_deny_add;
%feature("autodoc") purple_privacy_deny_remove;
%feature("autodoc") purple_privacy_allow;
%feature("autodoc") purple_privacy_deny;
%feature("autodoc") purple_privacy_check;
%feature("autodoc") purple_privacy_set_ui_ops;
%feature("autodoc") purple_privacy_get_ui_ops;
%feature("autodoc") purple_privacy_init;

%feature("autodoc") purple_proxy_info_new;
%feature("autodoc") purple_proxy_info_destroy;
%feature("autodoc") purple_proxy_info_set_type;
%feature("autodoc") purple_proxy_info_set_host;
%feature("autodoc") purple_proxy_info_set_port;
%feature("autodoc") purple_proxy_info_set_username;
%feature("autodoc") purple_proxy_info_set_password;
%feature("autodoc") purple_proxy_info_get_type;
%feature("autodoc") purple_proxy_info_get_host;
%feature("autodoc") purple_proxy_info_get_port;
%feature("autodoc") purple_proxy_info_get_username;
%feature("autodoc") purple_proxy_info_get_password;
%feature("autodoc") purple_proxy_get_handle;
%feature("autodoc") purple_proxy_init;
%feature("autodoc") purple_proxy_uninit;
%feature("autodoc") purple_proxy_get_setup;
%feature("autodoc") purple_proxy_connect_cancel_with_handle;
%feature("autodoc") purple_proxy_connect;
%feature("autodoc") purple_proxy_connect_socks;
%feature("autodoc") purple_proxy_connect_cancel;

%feature("autodoc") purple_prpl_got_account_idle;
%feature("autodoc") purple_prpl_got_account_login_time;
%feature("autodoc") purple_prpl_got_account_status;
%feature("autodoc") purple_prpl_got_user_idle;
%feature("autodoc") purple_prpl_got_user_login_time;
%feature("autodoc") purple_prpl_got_user_status;
%feature("autodoc") purple_prpl_got_user_status_deactive;
%feature("autodoc") purple_prpl_change_account_status;
%feature("autodoc") purple_prpl_get_statuses;

%feature("autodoc") purple_request_folder;
%feature("autodoc") purple_request_action;
%feature("autodoc") purple_request_fields_new;
%feature("autodoc") purple_request_fields_destroy;
%feature("autodoc") purple_request_fields_add_group;
%feature("autodoc") purple_request_fields_get_groups;
%feature("autodoc") purple_request_fields_exists;
%feature("autodoc") purple_request_fields_get_required;
%feature("autodoc") purple_request_fields_is_field_required;
%feature("autodoc") purple_request_fields_all_required_filled;
%feature("autodoc") purple_request_fields_get_field;
%feature("autodoc") purple_request_fields_get_string;
%feature("autodoc") purple_request_fields_get_integer;
%feature("autodoc") purple_request_fields_get_bool;
%feature("autodoc") purple_request_fields_get_choice;
%feature("autodoc") purple_request_fields_get_account;
%feature("autodoc") purple_request_field_group_new;
%feature("autodoc") purple_request_field_group_destroy;
%feature("autodoc") purple_request_field_group_add_field;
%feature("autodoc") purple_request_field_group_get_title;
%feature("autodoc") purple_request_field_group_get_fields;
%feature("autodoc") purple_request_field_new;
%feature("autodoc") purple_request_field_destroy;
%feature("autodoc") purple_request_field_set_label;
%feature("autodoc") purple_request_field_set_visible;
%feature("autodoc") purple_request_field_set_type_hint;
%feature("autodoc") purple_request_field_set_required;
%feature("autodoc") purple_request_field_get_type;
%feature("autodoc") purple_request_field_get_id;
%feature("autodoc") purple_request_field_get_label;
%feature("autodoc") purple_request_field_is_visible;
%feature("autodoc") purple_request_field_get_type_hint;
%feature("autodoc") purple_request_field_is_required;
%feature("autodoc") purple_request_field_string_new;
%feature("autodoc") purple_request_field_string_set_default_value;
%feature("autodoc") purple_request_field_string_set_value;
%feature("autodoc") purple_request_field_string_set_masked;
%feature("autodoc") purple_request_field_string_set_editable;
%feature("autodoc") purple_request_field_string_get_default_value;
%feature("autodoc") purple_request_field_string_get_value;
%feature("autodoc") purple_request_field_string_is_multiline;
%feature("autodoc") purple_request_field_string_is_masked;
%feature("autodoc") purple_request_field_string_is_editable;
%feature("autodoc") purple_request_field_int_new;
%feature("autodoc") purple_request_field_int_set_default_value;
%feature("autodoc") purple_request_field_int_set_value;
%feature("autodoc") purple_request_field_int_get_default_value;
%feature("autodoc") purple_request_field_int_get_value;
%feature("autodoc") purple_request_field_bool_new;
%feature("autodoc") purple_request_field_bool_set_default_value;
%feature("autodoc") purple_request_field_bool_set_value;
%feature("autodoc") purple_request_field_bool_get_default_value;
%feature("autodoc") purple_request_field_bool_get_value;
%feature("autodoc") purple_request_field_choice_new;
%feature("autodoc") purple_request_field_choice_add;
%feature("autodoc") purple_request_field_choice_set_default_value;
%feature("autodoc") purple_request_field_choice_set_value;
%feature("autodoc") purple_request_field_choice_get_default_value;
%feature("autodoc") purple_request_field_choice_get_value;
%feature("autodoc") purple_request_field_choice_get_labels;
%feature("autodoc") purple_request_field_list_new;
%feature("autodoc") purple_request_field_list_set_multi_select;
%feature("autodoc") purple_request_field_list_get_multi_select;
%feature("autodoc") purple_request_field_list_get_data;
%feature("autodoc") purple_request_field_list_add;
%feature("autodoc") purple_request_field_list_add_selected;
%feature("autodoc") purple_request_field_list_clear_selected;
%feature("autodoc") purple_request_field_list_set_selected;
%feature("autodoc") purple_request_field_list_is_selected;
%feature("autodoc") purple_request_field_list_get_selected;
%feature("autodoc") purple_request_field_list_get_items;
%feature("autodoc") purple_request_field_label_new;
%feature("autodoc") purple_request_field_image_new;
%feature("autodoc") purple_request_field_image_set_scale;
%feature("autodoc") purple_request_field_image_get_buffer;
%feature("autodoc") purple_request_field_image_get_size;
%feature("autodoc") purple_request_field_image_get_scale_x;
%feature("autodoc") purple_request_field_image_get_scale_y;
%feature("autodoc") purple_request_field_account_new;
%feature("autodoc") purple_request_field_account_set_default_value;
%feature("autodoc") purple_request_field_account_set_value;
%feature("autodoc") purple_request_field_account_set_show_all;
%feature("autodoc") purple_request_field_account_set_filter;
%feature("autodoc") purple_request_field_account_get_default_value;
%feature("autodoc") purple_request_field_account_get_value;
%feature("autodoc") purple_request_field_account_get_show_all;
%feature("autodoc") purple_request_field_account_get_filter;
%feature("autodoc") purple_request_input;
%feature("autodoc") purple_request_choice;
%feature("autodoc") purple_request_choice_varg;
%feature("autodoc") purple_request_action;
%feature("autodoc") purple_request_action_varg;
%feature("autodoc") purple_request_fields;
%feature("autodoc") purple_request_close;
%feature("autodoc") purple_request_close_with_handle;
%feature("autodoc") purple_request_yes_no;
%feature("autodoc") purple_request_ok_cancel;
%feature("autodoc") purple_request_accept_cancel;
%feature("autodoc") purple_request_file;
%feature("autodoc") purple_request_set_ui_ops;
%feature("autodoc") purple_request_get_ui_ops;

%feature("autodoc") purple_roomlist_show_with_account;
%feature("autodoc") purple_roomlist_new;
%feature("autodoc") purple_roomlist_ref;
%feature("autodoc") purple_roomlist_unref;
%feature("autodoc") purple_roomlist_room_add;
%feature("autodoc") purple_roomlist_set_fields;
%feature("autodoc") purple_roomlist_set_in_progress;
%feature("autodoc") purple_roomlist_get_in_progress;
%feature("autodoc") purple_roomlist_get_list;
%feature("autodoc") purple_roomlist_cancel_get_list;
%feature("autodoc") purple_roomlist_expand_category;
%feature("autodoc") purple_roomlist_get_fields;
%feature("autodoc") purple_roomlist_room_new;
%feature("autodoc") purple_roomlist_room_add_field;
%feature("autodoc") purple_roomlist_room_join;
%feature("autodoc") purple_roomlist_room_get_type;
%feature("autodoc") purple_roomlist_room_get_name;
%feature("autodoc") purple_roomlist_room_get_parent;
%feature("autodoc") purple_roomlist_room_get_fields;
%feature("autodoc") purple_roomlist_field_new;
%feature("autodoc") purple_roomlist_field_get_type;
%feature("autodoc") purple_roomlist_field_get_label;
%feature("autodoc") purple_roomlist_field_get_hidden;
%feature("autodoc") purple_roomlist_set_ui_ops;
%feature("autodoc") purple_roomlist_get_ui_ops;

%feature("autodoc") purple_savedstatuses_get_all;
%feature("autodoc") purple_savedstatuses_get_popular;
%feature("autodoc") purple_savedstatuses_get_handle;
%feature("autodoc") purple_savedstatuses_init;
%feature("autodoc") purple_savedstatuses_uninit;

%feature("autodoc") purple_savedstatus_new;
%feature("autodoc") purple_savedstatus_set_title;
%feature("autodoc") purple_savedstatus_set_type;
%feature("autodoc") purple_savedstatus_set_message;
%feature("autodoc") purple_savedstatus_set_substatus;
%feature("autodoc") purple_savedstatus_unset_substatus;
%feature("autodoc") purple_savedstatus_delete;
%feature("autodoc") purple_savedstatus_delete_by_status;
%feature("autodoc") purple_savedstatus_get_default;
%feature("autodoc") purple_savedstatus_get_current;
%feature("autodoc") purple_savedstatus_get_idleaway;
%feature("autodoc") purple_savedstatus_is_idleaway;
%feature("autodoc") purple_savedstatus_set_idleaway;
%feature("autodoc") purple_savedstatus_get_startup;
%feature("autodoc") purple_savedstatus_find;
%feature("autodoc") purple_savedstatus_find_by_creation_time;
%feature("autodoc") purple_savedstatus_find_transient_by_type_and_message;
%feature("autodoc") purple_savedstatus_is_transient;
%feature("autodoc") purple_savedstatus_get_title;
%feature("autodoc") purple_savedstatus_get_type;
%feature("autodoc") purple_savedstatus_get_message;
%feature("autodoc") purple_savedstatus_get_creation_time;
%feature("autodoc") purple_savedstatus_has_substatuses;
%feature("autodoc") purple_savedstatus_get_substatus;
%feature("autodoc") purple_savedstatus_substatus_get_type;
%feature("autodoc") purple_savedstatus_substatus_get_message;
%feature("autodoc") purple_savedstatus_activate_for_account;
%feature("autodoc") purple_savedstatus_activate;

%feature("autodoc") serv_send_typing;
%feature("autodoc") serv_move_buddy;
%feature("autodoc") serv_send_im;
%feature("autodoc") serv_send_attention;
%feature("autodoc") serv_got_attention;
%feature("autodoc") serv_get_info;
%feature("autodoc") serv_set_info;
%feature("autodoc") serv_add_permit;
%feature("autodoc") serv_add_deny;
%feature("autodoc") serv_rem_permit;
%feature("autodoc") serv_rem_deny;
%feature("autodoc") serv_set_permit_deny;
%feature("autodoc") serv_chat_invite;
%feature("autodoc") serv_chat_leave;
%feature("autodoc") serv_chat_whisper;
%feature("autodoc") serv_chat_send;
%feature("autodoc") serv_alias_buddy;
%feature("autodoc") serv_got_alias;
%feature("autodoc") serv_got_private_alias;
%feature("autodoc") serv_got_typing_stopped;
%feature("autodoc") serv_got_typing;
%feature("autodoc") serv_got_im;
%feature("autodoc") serv_join_chat;
%feature("autodoc") serv_reject_chat;
%feature("autodoc") serv_got_chat_invite;
%feature("autodoc") serv_got_joined_chat;
%feature("autodoc") serv_got_chat_left;
%feature("autodoc") serv_got_chat_in;
%feature("autodoc") serv_send_file;

%feature("autodoc") purple_signals_unregister_by_instance;
%feature("autodoc") purple_signals_disconnect_by_handle;
%feature("autodoc") purple_signals_init;
%feature("autodoc") purple_signals_uninit;

%feature("autodoc") purple_sound_play_file;
%feature("autodoc") purple_sound_play_event;
%feature("autodoc") purple_sound_set_ui_ops;
%feature("autodoc") purple_sound_get_ui_ops;
%feature("autodoc") purple_sound_init;
%feature("autodoc") purple_sound_uninit;
%feature("autodoc") purple_sounds_get_handle;

%feature("autodoc") purple_ssl_set_ops;
%feature("autodoc") purple_ssl_init;
%feature("autodoc") purple_ssl_close;
%feature("autodoc") purple_ssl_read;
%feature("autodoc") purple_ssl_write;
%feature("autodoc") purple_ssl_is_supported;
%feature("autodoc") purple_ssl_strerror;
%feature("autodoc") purple_ssl_connect;
%feature("autodoc") purple_ssl_connect_with_host_fd;
%feature("autodoc") purple_ssl_connect_fd;
%feature("autodoc") purple_ssl_input_add;
%feature("autodoc") purple_ssl_get_peer_certificates;
%feature("autodoc") purple_ssl_get_ops;
%feature("autodoc") purple_ssl_uninit;

%feature("autodoc") purple_status_type_new_full;
%feature("autodoc") purple_status_type_new;
%feature("autodoc") purple_status_type_new_with_attrs;
%feature("autodoc") purple_status_type_destroy;
%feature("autodoc") purple_status_type_set_primary_attr;
%feature("autodoc") purple_status_type_add_attr;
%feature("autodoc") purple_status_type_add_attrs;
%feature("autodoc") purple_status_type_add_attrs_vargs;
%feature("autodoc") purple_status_type_get_primitive;
%feature("autodoc") purple_status_type_get_id;
%feature("autodoc") purple_status_type_get_name;
%feature("autodoc") purple_status_type_is_saveable;
%feature("autodoc") purple_status_type_is_user_settable;
%feature("autodoc") purple_status_type_is_independent;
%feature("autodoc") purple_status_type_is_exclusive;
%feature("autodoc") purple_status_type_is_available;
%feature("autodoc") purple_status_type_get_primary_attr;
%feature("autodoc") purple_status_type_get_attr;
%feature("autodoc") purple_status_type_get_attrs;
%feature("autodoc") purple_status_type_find_with_id;
%feature("autodoc") purple_status_attr_new;
%feature("autodoc") purple_status_attr_destroy;
%feature("autodoc") purple_status_attr_get_id;
%feature("autodoc") purple_status_attr_get_name;
%feature("autodoc") purple_status_attr_get_value;
%feature("autodoc") purple_status_new;
%feature("autodoc") purple_status_destroy;
%feature("autodoc") purple_status_set_active;
%feature("autodoc") purple_status_set_active_with_attrs;
%feature("autodoc") purple_status_set_active_with_attrs_list;
%feature("autodoc") purple_status_set_attr_boolean;
%feature("autodoc") purple_status_set_attr_int;
%feature("autodoc") purple_status_set_attr_string;
%feature("autodoc") purple_status_get_type;
%feature("autodoc") purple_status_get_presence;
%feature("autodoc") purple_status_get_id;
%feature("autodoc") purple_status_get_name;
%feature("autodoc") purple_status_is_independent;
%feature("autodoc") purple_status_is_exclusive;
%feature("autodoc") purple_status_is_available;
%feature("autodoc") purple_status_is_active;
%feature("autodoc") purple_status_is_online;
%feature("autodoc") purple_status_get_attr_value;
%feature("autodoc") purple_status_get_attr_boolean;
%feature("autodoc") purple_status_get_attr_int;
%feature("autodoc") purple_status_get_attr_string;
%feature("autodoc") purple_status_compare;
%feature("autodoc") purple_status_get_handle;
%feature("autodoc") purple_status_init;
%feature("autodoc") purple_status_uninit;

%feature("autodoc") purple_stringref_new;
%feature("autodoc") purple_stringref_new_noref;
%feature("autodoc") purple_stringref_printf;
%feature("autodoc") purple_stringref_ref;
%feature("autodoc") purple_stringref_unref;
%feature("autodoc") purple_stringref_value;
%feature("autodoc") purple_stringref_cmp;
%feature("autodoc") purple_stringref_len;

%feature("autodoc") purple_stun_discover;
%feature("autodoc") purple_stun_init;

%feature("autodoc") purple_upnp_init;
%feature("autodoc") purple_upnp_discover;
%feature("autodoc") purple_upnp_get_control_info;
%feature("autodoc") purple_upnp_get_public_ip;
%feature("autodoc") purple_upnp_cancel_port_mapping;
%feature("autodoc") purple_upnp_port_mapping_cancel;
%feature("autodoc") purple_upnp_set_port_mapping;
%feature("autodoc") purple_upnp_remove_port_mapping;

%feature("autodoc") purple_util_set_current_song;
%feature("autodoc") purple_util_format_song_info;
%feature("autodoc") purple_util_init;
%feature("autodoc") purple_util_uninit;
%feature("autodoc") purple_util_set_user_dir;
%feature("autodoc") purple_util_write_data_to_file;
%feature("autodoc") purple_util_write_data_to_file_absolute;
%feature("autodoc") purple_util_read_xml_from_file;
%feature("autodoc") purple_util_get_image_extension;
%feature("autodoc") purple_util_get_image_filename;
%feature("autodoc") purple_util_chrreplace;
%feature("autodoc") purple_util_fetch_url_request;
%feature("autodoc") purple_util_fetch_url;
%feature("autodoc") purple_util_fetch_url_cancel;

%feature("autodoc") purple_value_new;
%feature("autodoc") purple_value_new_outgoing;
%feature("autodoc") purple_value_destroy;
%feature("autodoc") purple_value_dup;
%feature("autodoc") purple_value_get_type;
%feature("autodoc") purple_value_get_subtype;
%feature("autodoc") purple_value_get_specific_type;
%feature("autodoc") purple_value_is_outgoing;
%feature("autodoc") purple_value_set_char;
%feature("autodoc") purple_value_set_uchar;
%feature("autodoc") purple_value_set_boolean;
%feature("autodoc") purple_value_set_short;
%feature("autodoc") purple_value_set_ushort;
%feature("autodoc") purple_value_set_int;
%feature("autodoc") purple_value_set_long;
%feature("autodoc") purple_value_set_ulong;
%feature("autodoc") purple_value_set_uint;
%feature("autodoc") purple_value_set_string;
%feature("autodoc") purple_value_set_object;
%feature("autodoc") purple_value_set_pointer;
%feature("autodoc") purple_value_set_enum;
%feature("autodoc") purple_value_set_boxed;
%feature("autodoc") purple_value_get_char;
%feature("autodoc") purple_value_get_uchar;
%feature("autodoc") purple_value_get_boolean;
%feature("autodoc") purple_value_get_short;
%feature("autodoc") purple_value_get_ushort;
%feature("autodoc") purple_value_get_int;
%feature("autodoc") purple_value_get_long;
%feature("autodoc") purple_value_get_ulong;
%feature("autodoc") purple_value_get_uint;
%feature("autodoc") purple_value_get_string;
%feature("autodoc") purple_value_get_object;
%feature("autodoc") purple_value_get_pointer;
%feature("autodoc") purple_value_get_enum;
%feature("autodoc") purple_value_get_boxed;

%feature("autodoc") purple_version_check;

%feature("autodoc") purple_whiteboard_set_ui_ops;
%feature("autodoc") purple_whiteboard_set_prpl_ops;
%feature("autodoc") purple_whiteboard_create;
%feature("autodoc") purple_whiteboard_destroy;
%feature("autodoc") purple_whiteboard_start;
%feature("autodoc") purple_whiteboard_get_session;
%feature("autodoc") purple_whiteboard_draw_list_destroy;
%feature("autodoc") purple_whiteboard_get_dimensions;
%feature("autodoc") purple_whiteboard_set_dimensions;
%feature("autodoc") purple_whiteboard_draw_point;
%feature("autodoc") purple_whiteboard_send_draw_list;
%feature("autodoc") purple_whiteboard_draw_line;
%feature("autodoc") purple_whiteboard_clear;
%feature("autodoc") purple_whiteboard_send_clear;
%feature("autodoc") purple_whiteboard_send_brush;
%feature("autodoc") purple_whiteboard_get_brush;
%feature("autodoc") purple_whiteboard_set_brush;

%feature("autodoc") xmlnode_new;
%feature("autodoc") xmlnode_new_child;
%feature("autodoc") xmlnode_insert_child;
%feature("autodoc") xmlnode_get_child;
%feature("autodoc") xmlnode_get_child_with_namespace;
%feature("autodoc") xmlnode_get_next_twin;
%feature("autodoc") xmlnode_insert_data;
%feature("autodoc") xmlnode_get_data;
%feature("autodoc") xmlnode_get_data_unescaped;
%feature("autodoc") xmlnode_set_attrib;
%feature("autodoc") xmlnode_set_attrib_with_prefix;
%feature("autodoc") xmlnode_set_attrib_with_namespace;
%feature("autodoc") xmlnode_get_attrib;
%feature("autodoc") xmlnode_get_attrib_with_namespace;
%feature("autodoc") xmlnode_remove_attrib;
%feature("autodoc") xmlnode_remove_attrib_with_namespace;
%feature("autodoc") xmlnode_set_namespace;
%feature("autodoc") xmlnode_get_namespace;
%feature("autodoc") xmlnode_set_prefix;
%feature("autodoc") xmlnode_get_prefix;
%feature("autodoc") xmlnode_to_str;
%feature("autodoc") xmlnode_to_formatted_str;
%feature("autodoc") xmlnode_from_str;
%feature("autodoc") xmlnode_copy;
%feature("autodoc") xmlnode_free;

%callback("%s_cb");
guint    g_timeout_add(guint, GSourceFunc, gpointer);
guint    g_timeout_add_seconds(guint, GSourceFunc, gpointer);
gboolean g_source_remove(guint);
%nocallback;

guint    g_timeout_add(guint interval, GSourceFunc function, gpointer data);
guint    g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data);
gboolean g_source_remove(guint tag);

#ifdef SWIGPYTHON
%typemap(in) void *p {
  $1 = PyCObject_AsVoidPtr($input);
}
#endif

void heliotrope_debug_print(PurpleDebugLevel level, const char *category,
    const char *args);
gboolean heliotrope_debug_is_enabled(PurpleDebugLevel level, const char *category);
PurpleDebugUiOps *heliotrope_debug_get_ui_ops();
void set_heliotrope_print_debug_cb(PyObject *func);
void heliotrope_xfire_tooltip_text(PurpleBuddy *buddy);
void set_heliotrope_add_room_cb(PyObject *func);
void set_heliotrope_room_refresh_in_progress_cb(PyObject *func);
PurpleNotifyUiOps *heliotrope_get_notify_ui_ops();
PurpleBlistUiOps *heliotrope_get_blist_ui_ops();
PurpleRoomlistUiOps *heliotrope_get_roomlist_ui_ops();

PurpleAccount *to_account(void *p);
PurpleConversation *to_conversation(void *p);
PurpleBuddy *to_buddy(void *p);
PurpleStatus *to_status(void *p);
PurpleConnection *to_connection(void *p);
PurpleXfer *to_xfer(void *p);
PurpleNotifyUserInfo *to_user_info(void *p);
PurpleRoomlist *to_room_list(void *p);
PurpleRoomlistRoom *to_room(void *p);
PurpleConversation *to_conv(void *p);

%callback("%s_cb");
guint gnt_input_add(int, PurpleInputCondition, PurpleInputFunction, gpointer);
%nocallback;

guint gnt_input_add(int fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data);

#ifdef SWIGPYTHON
%typemap(in) PyObject *func {
  if (! PyCallable_Check($input)) {
    PyErr_SetString(PyExc_TypeError, "parameter must be callable");
    return NULL;
  }
  $1 = $input;
}
#endif
    
void set_received_im_msg(PurplePlugin *plugin, PyObject *func);
void set_received_chat_msg(PurplePlugin *plugin, PyObject *func);
void set_buddy_typed(PurplePlugin *plugin, PyObject *func);
void set_buddy_typing(PurplePlugin *plugin, PyObject *func);
void set_buddy_typing_stopped(PurplePlugin *plugin, PyObject *func);
void set_buddy_signed_off(PurplePlugin *plugin, PyObject *func);
void set_buddy_signed_on(PurplePlugin *plugin, PyObject *func);
void set_buddy_status_changed(PurplePlugin *plugin, PyObject *func);
void set_buddy_icon_changed(PurplePlugin *plugin, PyObject *func);
void set_blist_node_aliased(PurplePlugin *plugin, PyObject *func);
void set_signed_on(PurplePlugin *plugin, PyObject *func);
void set_signed_off(PurplePlugin *plugin, PyObject *func);
void set_signing_on(PurplePlugin *plugin, PyObject *func);
void set_signing_off(PurplePlugin *plugin, PyObject *func);
void set_connection_error(PurplePlugin *plugin, PyObject *func);
gboolean purple_buddy_is_online(PurpleBuddy *b);
void set_buddy_added(PurplePlugin *plugin, PyObject *func);
void set_displaying_userinfo(PurplePlugin *plugin, PyObject *func);
void set_request_authorize_cb(PyObject *func);
void set_file_recv_request(PurplePlugin *plugin, PyObject *func);
void set_file_recv_accept(PurplePlugin *plugin, PyObject *func);
void set_file_recv_start(PurplePlugin *plugin, PyObject *func);
void set_file_recv_cancel(PurplePlugin *plugin, PyObject *func);
void set_file_recv_complete(PurplePlugin *plugin, PyObject *func);
void set_file_send_accept(PurplePlugin *plugin, PyObject *func);
void set_file_send_start(PurplePlugin *plugin, PyObject *func);
void set_file_send_cancel(PurplePlugin *plugin, PyObject *func);
void set_file_send_complete(PurplePlugin *plugin, PyObject *func);
void set_chat_buddy_joined(PurplePlugin *plugin, PyObject *func);
void set_chat_buddy_left(PurplePlugin *plugin, PyObject *func);

%callback("%s_cb");
void *request_authorize(PurpleAccount *account, const char *remote_user,
  const char *id, const char *alias, const char *message, gboolean on_list,
  PurpleAccountRequestAuthorizationCb authorize_cb,
  PurpleAccountRequestAuthorizationCb deny_cb, void *user_data);
%nocallback;

void *request_authorize(PurpleAccount *account, const char *remote_user,
  const char *id, const char *alias, const char *message, gboolean on_list,
  PurpleAccountRequestAuthorizationCb authorize_cb,
  PurpleAccountRequestAuthorizationCb deny_cb, void *user_data);

void invoke(PyObject *cb, PyObject *user_data);

%include "glib/gmacros.h"
%include "account.h"
%include "accountopt.h"
%include "blist.h"
%include "buddyicon.h"
%include "certificate.h"
%include "cipher.h"
%include "circbuffer.h"
%include "cmds.h"
%include "connection.h"
%include "conversation.h"
%include "core.h"
%include "debug.h"
%include "dnsquery.h"
%include "dnssrv.h"
%include "eventloop.h"
%include "ft.h"
%include "idle.h"
%include "imgstore.h"
%include "log.h"
%include "mime.h"
%include "nat-pmp.h"
%include "network.h"
%include "notify.h"
%include "ntlm.h"
%include "plugin.h"
%include "pluginpref.h"
%include "pounce.h"
%include "prefs.h"
%include "privacy.h"
%include "proxy.h"
%include "prpl.h"
%include "request.h"
%include "roomlist.h"
%include "savedstatuses.h"
%include "server.h"
%include "signals.h"
%include "sound.h"
%include "sslconn.h"
%include "status.h"
%include "stringref.h"
%include "stun.h"
%include "upnp.h"
%include "util.h"
%include "value.h"
%include "version.h"
%include "whiteboard.h"
%include "xmlnode.h"

%inline %{
PurpleBuddy *BlistNodeToBuddy(PurpleBlistNode *p) {
  return (PurpleBuddy *) p;
}

/* Create a wrapper around purple_account_set_status since Swig doesn't
 * support well functions with variable list of arguments.
 */
void heliotrope_account_set_status(PurpleAccount *account, const char *status_id,
                              gboolean active, const char *message) {
  purple_account_set_status(account, status_id, active, "message", message, NULL);
}
%}

void setup_exception_handler();
