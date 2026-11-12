/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-tofu-connection.h"
#include "nm-tofu.h"

#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-active-connection.h"
#include "settings/nm-settings.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-settings-connection.h"
#include "supplicant/nm-supplicant-config.h"
#include "core/nm-dbus-manager.h"
#include "core/nm-auth-utils.h"
#include "nm-manager.h"
#include "core/nm-types.h"
#include "devices/nm-device.h"

/* The agent side of this interface (nmt-certificate-agent.c and
 * equivalents) is registered via AgentManager.RegisterWithCapabilities +
 * NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU, so nm_agent_manager_find_secret_agent()
 * can find it — no separate registration entry point needed. */
#define CERT_AGENT_OBJECT_PATH   "/org/freedesktop/NetworkManager/CertificateAgent"
#define CERT_AGENT_IFACE         "org.freedesktop.NetworkManager.CertificateAgent"
#define NM_CERT_AGENT_TIMEOUT_MS 180000

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_TOFU
#define _NMLOG(level, ...) \
    nm_log((level), (_NMLOG_DOMAIN), NULL, NULL, "tofu-connection: " __VA_ARGS__)

/*****************************************************************************/

typedef struct {
    NMActiveConnection *req;
    char               *uuid;
    char               *ssid;
    NMAuthSubject      *subject;
    gboolean            accepted; /* Holds the user's accept/reject decision */
    GCancellable       *cancellable;
    gulong              ac_state_id;
    gulong              stage3_id; /* --- Added for Zombie Signal Fix --- */

} TofuConnectionCtx;

static void
tofu_ac_state_changed_cb(NMActiveConnection *active, GParamSpec *pspec, gpointer user_data)
{
    GCancellable           *cancellable = G_CANCELLABLE(user_data);
    NMActiveConnectionState state       = nm_active_connection_get_state(active);

    if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATING
        || state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
        _NMLOG(LOGL_DEBUG, "active connection deactivating, cancelling TOFU DBus prompt");
        g_cancellable_cancel(cancellable);
    }
}
static void
tofu_connection_ctx_free(TofuConnectionCtx *ctx)
{
    if (ctx->ac_state_id && ctx->req)
        nm_clear_g_signal_handler(ctx->req, &ctx->ac_state_id);

    /* Disconnect from the global singleton */
    if (ctx->stage3_id)
        nm_clear_g_signal_handler(nm_tofu_session_get(), &ctx->stage3_id);

    g_clear_object(&ctx->cancellable);
    g_clear_object(&ctx->req);
    g_clear_object(&ctx->subject);
    g_free(ctx->uuid);
    g_free(ctx->ssid);
    g_free(ctx);
}

static void
tofu_set_autoconnect_for_uuid(const char                     *uuid_target,
                              gboolean                        enable,
                              NMSettingsConnectionPersistMode persist_mode)
{
    NMSettingsConnection *sconn =
        nm_settings_get_connection_by_uuid(nm_settings_get(), uuid_target);
    NMConnection         *clone;
    NMSettingConnection  *s_con;
    gs_free_error GError *error = NULL;

    if (!sconn)
        return;

    clone = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_con = nm_connection_get_setting_connection(clone);

    if (s_con && nm_setting_connection_get_autoconnect(s_con) != enable) {
        g_object_set(s_con, NM_SETTING_CONNECTION_AUTOCONNECT, enable, NULL);
        nm_settings_connection_update(sconn,
                                      NULL,
                                      clone,
                                      persist_mode,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                      "tofu",
                                      &error);
    }
    g_object_unref(clone);
}

static void
tofu_update_ca_cert_hash(const char                     *uuid,
                         const char                     *hash_hex,
                         const char                     *domain,
                         NMSettingsConnectionPersistMode persist_mode)
{
    NMSettingsConnection *sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    NMConnection         *clone;
    NMSetting8021x       *s_8021x;
    gs_free char         *hash_uri = g_strdup_printf("hash://server/sha256/%s", hash_hex);
    gs_free_error GError *error    = NULL;

    if (!sconn || !hash_hex)
        return;

    clone   = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_8021x = nm_connection_get_setting_802_1x(clone);

    if (s_8021x) {
        nm_setting_802_1x_set_ca_cert(s_8021x,
                                      hash_uri,
                                      NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH,
                                      NULL,
                                      &error);
        if (domain && *domain)
            g_object_set(s_8021x, NM_SETTING_802_1X_DOMAIN_MATCH, domain, NULL);

        nm_settings_connection_update(sconn,
                                      NULL,
                                      clone,
                                      persist_mode,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                      "tofu",
                                      NULL);
    }
    g_object_unref(clone);
}

static gboolean
tofu_update_ca_cert(NMToFuSession                  *session,
                    const char                     *uuid,
                    GBytes                         *root_der,
                    const char                     *domain,
                    NMSettingsConnectionPersistMode persist_mode)
{
    NMSettingsConnection *sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    NMConnection         *clone;
    NMSetting8021x       *s_8021x;
    gs_free char         *pem_path = NULL;
    gs_free_error GError *error    = NULL;

    if (!sconn || !root_der)
        return FALSE;

    /* Requires exposing tofu_write_root_pem as nm_tofu_session_write_root_pem in nm-tofu.h */
    pem_path = nm_tofu_session_write_root_pem(session, root_der, &error);
    if (!pem_path)
        return FALSE;

    clone   = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_8021x = nm_connection_get_setting_802_1x(clone);

    if (s_8021x) {
        nm_setting_802_1x_set_ca_cert(s_8021x,
                                      pem_path,
                                      NM_SETTING_802_1X_CK_SCHEME_PATH,
                                      NULL,
                                      &error);
        if (domain && *domain)
            g_object_set(s_8021x, NM_SETTING_802_1X_DOMAIN_MATCH, domain, NULL);

        nm_settings_connection_update(sconn,
                                      NULL,
                                      clone,
                                      persist_mode,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                      NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                      "tofu",
                                      NULL);
    }
    g_object_unref(clone);
    return TRUE;
}

static void
tofu_deauthenticate_connection_by_uuid(const char *uuid_target)
{
    NMManager            *manager = nm_manager_get();
    NMSettingsConnection *sconn;
    NMActiveConnection   *ac;
    const CList          *tmp_list;

    if (!manager || !uuid_target)
        return;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid_target);
    if (!sconn)
        return;

    nm_manager_for_each_active_connection (manager, ac, tmp_list) {
        gs_free_error GError *error = NULL;

        if (nm_active_connection_get_settings_connection(ac) != sconn)
            continue;

        _NMLOG(LOGL_INFO, "deauthenticating uuid=%s", uuid_target);
        if (!nm_manager_deactivate_connection(manager,
                                              ac,
                                              NM_DEVICE_STATE_REASON_USER_REQUESTED,
                                              &error)) {
            _NMLOG(LOGL_WARN, "deactivate uuid=%s failed: %s", uuid_target, error->message);
        }
        return;
    }
}

static void
tofu_remove_connection(const char *uuid)
{
    NMSettingsConnection *sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (sconn) {
        _NMLOG(LOGL_INFO, "removing connection profile for uuid=%s", uuid);
        nm_settings_connection_delete(sconn, FALSE);
    }
}

static void
tofu_add_timestamp_to_connection(const char *uuid)
{
    NMSettingsConnection *sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (sconn) {
        nm_settings_connection_update_timestamp(sconn, (guint64) time(NULL));
    }
}

static NMActiveConnection *
tofu_authenticate_connection_by_uuid(const char *uuid_target)
{
    NMManager                     *manager = NULL;
    NMSettingsConnection          *sconn;
    NMConnection                  *conn;
    NMDevice                      *device  = NULL;
    NMActiveConnection            *active  = NULL;
    gs_free_error GError          *error   = NULL;
    gs_unref_object NMAuthSubject *subject = NULL;

    if (!uuid_target)
        return NULL;

    manager = nm_manager_get();
    if (!manager)
        return NULL;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid_target);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "no connection found for uuid=%s", uuid_target);
        return NULL;
    }
    conn = nm_settings_connection_get_connection(sconn);

    /* Reconnect on the same interface the connection is actually bound to */
    {
        const char *iface = nm_connection_get_interface_name(conn);

        if (iface)
            device = nm_manager_get_device(manager, iface, NM_DEVICE_TYPE_WIFI);
    }

    if (!device) {
        /* Fall back to any available WiFi device if no interface is bound */
        NMDevice    *dev_iter;
        const CList *tmp_list;

        nm_manager_for_each_device (manager, dev_iter, tmp_list) {
            if (nm_device_get_device_type(dev_iter) == NM_DEVICE_TYPE_WIFI) {
                device = dev_iter;
                break;
            }
        }
    }

    if (!device) {
        _NMLOG(LOGL_WARN, "no WiFi device found for uuid=%s", uuid_target);
        return NULL;
    }

    subject = nm_auth_subject_new_internal();
    _NMLOG(LOGL_INFO, "activating uuid=%s on %s", uuid_target, nm_device_get_iface(device));

    active = nm_manager_activate_connection(manager,
                                            sconn,
                                            NULL,
                                            NULL,
                                            device,
                                            subject,
                                            NM_ACTIVATION_TYPE_MANAGED,
                                            NM_ACTIVATION_REASON_USER_REQUEST,
                                            NM_ACTIVATION_STATE_FLAG_NONE,
                                            &error);
    if (!active)
        _NMLOG(LOGL_WARN, "activation failed for uuid=%s: %s", uuid_target, error->message);

    return active;
}

/* Polkit callback (Stage 4b) */
static void
tofu_revert_temporary_cert(const char *uuid)
{
    NMSettingsConnection         *sconn;
    gs_unref_object NMConnection *clone = NULL;
    NMSetting8021x               *s_8021x;
    gs_free_error GError         *error = NULL;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (!sconn)
        return;

    clone   = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_8021x = nm_connection_get_setting_802_1x(clone);
    if (!s_8021x)
        return;

    nm_setting_802_1x_set_ca_cert(s_8021x, NULL, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN, NULL, NULL);
    g_object_set(s_8021x, NM_SETTING_802_1X_DOMAIN_MATCH, NULL, NULL);

    if (!nm_settings_connection_update(sconn,
                                       NULL,
                                       clone,
                                       NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                       "tofu",
                                       &error)) {
        _NMLOG(LOGL_WARN, "revert-temporary-cert: failed for uuid=%s: %s", uuid, error->message);
    } else {
        _NMLOG(LOGL_INFO, "revert-temporary-cert: cleared temporary pin for uuid=%s", uuid);
    }

    tofu_set_autoconnect_for_uuid(uuid,
                                  FALSE,
                                  NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
}

static void
tofu_temp_pin_state_changed_cb(NMActiveConnection *active, GParamSpec *pspec, gpointer user_data)
{
    const char             *uuid;
    NMActiveConnectionState state = nm_active_connection_get_state(active);

    if (state != NM_ACTIVE_CONNECTION_STATE_ACTIVATED
        && state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
        return;

    uuid = g_object_get_data(G_OBJECT(active), "tofu-temp-pin-uuid");
    g_signal_handlers_disconnect_by_func(active, tofu_temp_pin_state_changed_cb, NULL);

    if (uuid)
        tofu_revert_temporary_cert(uuid);

    /* Disconnecting the handler and removing the data frees the string */
    g_object_set_data(G_OBJECT(active), "tofu-temp-pin-uuid", NULL);
}

/* Polkit callback (Stage 4b) */
static void
on_polkit_check_cb(gboolean authorized, gpointer user_data)
{
    GTask             *task             = G_TASK(user_data);
    TofuConnectionCtx *ctx              = g_task_get_task_data(task);
    NMToFuSession     *session          = nm_tofu_session_get();
    gboolean           temp_pin_applied = FALSE;

    if (ctx->accepted) {
        GBytes       *root_der  = NULL;
        const char   *leaf_hash = NULL;
        gs_free char *domain    = NULL;

        nm_tofu_session_get_pin_data(session, &root_der, &leaf_hash, (const char **) &domain);

        if (authorized) {
            if (tofu_update_ca_cert(session,
                                    ctx->uuid,
                                    root_der,
                                    domain,
                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK)) {
                _NMLOG(LOGL_INFO,
                       "agent response: pinned root CA for uuid=%s (persisted)",
                       ctx->uuid);
            } else if (leaf_hash) {
                tofu_update_ca_cert_hash(ctx->uuid,
                                         leaf_hash,
                                         domain,
                                         NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK);
                _NMLOG(LOGL_INFO,
                       "agent response: pinned leaf hash for uuid=%s (persisted)",
                       ctx->uuid);
            }
        } else {
            if (leaf_hash) {
                tofu_update_ca_cert_hash(ctx->uuid,
                                         leaf_hash,
                                         domain,
                                         NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
                _NMLOG(
                    LOGL_INFO,
                    "agent response: pinned leaf hash for uuid=%s (not persisted — modify denied)",
                    ctx->uuid);
                temp_pin_applied = TRUE;
            }
        }

        tofu_set_autoconnect_for_uuid(ctx->uuid,
                                      TRUE,
                                      authorized
                                          ? NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK
                                          : NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
        tofu_add_timestamp_to_connection(ctx->uuid);

        /* Integrate Reactivation */
        if (temp_pin_applied) {
            NMActiveConnection *active = tofu_authenticate_connection_by_uuid(ctx->uuid);
            if (active) {
                g_object_set_data_full(G_OBJECT(active),
                                       "tofu-temp-pin-uuid",
                                       g_strdup(ctx->uuid),
                                       g_free);
                g_signal_connect(active,
                                 "notify::" NM_ACTIVE_CONNECTION_STATE,
                                 G_CALLBACK(tofu_temp_pin_state_changed_cb),
                                 NULL);
            } else {
                tofu_revert_temporary_cert(ctx->uuid);
            }
        } else {
            tofu_authenticate_connection_by_uuid(ctx->uuid);
        }

    } else {
        /* User Rejected */
        if (authorized) {
            tofu_remove_connection(ctx->uuid);
            _NMLOG(LOGL_INFO, "user rejected cert; profile removed for SSID=%s", ctx->ssid);
        } else {
            _NMLOG(LOGL_INFO,
                   "user rejected cert for SSID=%s, but not authorized to delete this profile — "
                   "left in place",
                   ctx->ssid);
        }
    }

    nm_tofu_session_reset(session);
    g_object_unref(task);
}

typedef void (*TofuPolkitDoneFunc)(gboolean authorized, gpointer user_data);

static void
tofu_polkit_check_cb(NMAuthChain *chain, GDBusMethodInvocation *context, gpointer user_data)
{
    TofuPolkitDoneFunc done_func = nm_auth_chain_get_data(chain, "done_func");
    const char        *perm      = nm_auth_chain_get_data(chain, "perm");
    gboolean           authorized;

    authorized = perm && (nm_auth_chain_get_result(chain, perm) == NM_AUTH_CALL_RESULT_YES);

    _NMLOG(LOGL_DEBUG, "polkit %s check -> %s", perm ?: "(none)", authorized ? "YES" : "NO");

    if (done_func)
        done_func(authorized, nm_auth_chain_get_data(chain, "done_data"));

    nm_auth_chain_destroy(chain);
}
static gboolean
tofu_polkit_check_modify(NMConnection      *connection,
                         NMAuthSubject     *subject,
                         TofuPolkitDoneFunc done_func,
                         gpointer           user_data)
{
    NMSettingConnection *s_con;
    const char          *perm;
    NMAuthChain         *chain;

    if (!connection || !subject
        || (nm_auth_subject_get_subject_type(subject) != NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS))
        return FALSE;

    s_con = nm_connection_get_setting_connection(connection);
    perm  = (s_con && nm_setting_connection_get_num_permissions(s_con) == 1)
                ? NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN
                : NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;

    chain = nm_auth_chain_new_subject(subject, NULL, tofu_polkit_check_cb, NULL);
    nm_auth_chain_set_data(chain, "perm", (gpointer) perm, NULL);
    nm_auth_chain_set_data(chain, "done_func", (gpointer) done_func, NULL);
    nm_auth_chain_set_data(chain, "done_data", user_data, NULL);

    /* never show an admin popup for background/system connections */
    nm_auth_chain_add_call_unsafe(chain, perm, FALSE);

    return TRUE;
}
/* DBus Agent callback (Stage 4a) */
static void
on_agent_response_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GTask                     *task       = G_TASK(user_data);
    TofuConnectionCtx         *ctx        = g_task_get_task_data(task);
    gs_unref_variant GVariant *reply      = NULL;
    gs_free_error GError      *error      = NULL;
    NMConnection              *connection = NULL;

    reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source_object), res, &error);

    if (reply) {
        /* Store the user's decision directly into the context */
        g_variant_get(reply, "(b)", &ctx->accepted);
    } else {
        /* DBUS CANCELLATION ABORT */
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            _NMLOG(LOGL_DEBUG, "DBus prompt cancelled, aborting TOFU flow for SSID=%s", ctx->ssid);
            nm_tofu_session_reset(nm_tofu_session_get());
            g_object_unref(task);
            return;
        }

        _NMLOG(LOGL_WARN, "agent call failed: %s", error->message);
        ctx->accepted = FALSE; /* Default to rejected on other failures/timeouts */
    }

    /* Chain to Polkit check */
    connection = nm_settings_connection_get_connection(
        nm_settings_get_connection_by_uuid(nm_settings_get(), ctx->uuid));

    if (!tofu_polkit_check_modify(connection,
                                  ctx->subject,
                                  (TofuPolkitDoneFunc) on_polkit_check_cb,
                                  task)) {
        /* If no polkit check could be started (e.g., no human subject), default to unauthorized */
        on_polkit_check_cb(FALSE, task);
    }
}

/* Signal Handler (Stage 3) */
static gboolean
tofu_certificate_agent_pick(NMActiveConnection *req, char **out_unique)
{
    NMSecretAgent        *agent;
    NMSettingsConnection *sconn      = nm_active_connection_get_settings_connection(req);
    NMConnection         *connection = sconn ? nm_settings_connection_get_connection(sconn) : NULL;
    NMAuthSubject        *subject    = nm_active_connection_get_subject(req);

    if (!connection || !subject)
        return FALSE;

    agent = nm_agent_manager_find_secret_agent(nm_agent_manager_get(),
                                               connection,
                                               subject,
                                               NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU);
    if (!agent)
        return FALSE;

    *out_unique = g_strdup(nm_secret_agent_get_dbus_owner(agent));
    return TRUE;
}

static void
tofu_on_stage3_ready(NMToFuSession *session, gpointer user_data)
{
    GTask             *task      = G_TASK(user_data);
    TofuConnectionCtx *ctx       = g_task_get_task_data(task);
    GDBusConnection   *dbus_conn = nm_dbus_manager_get_dbus_connection(nm_dbus_manager_get());

    gs_free char *dest_agent = NULL;
    const char   *ssid       = nm_tofu_session_get_ssid(session);
    const char   *disclaimer;

    gs_free char *cn     = NULL;
    gs_free char *issuer = NULL;
    gs_free char *org    = NULL;
    gs_free char *sha256 = NULL;
    gs_free char *exp    = NULL;
    gs_free char *url    = NULL;

    if (!nm_streq0(ctx->uuid, nm_tofu_session_get_uuid(session))) {
        _NMLOG(LOGL_DEBUG,
               "ignoring stage3-ready signal for mismatched UUID (expected %s, got %s)",
               ctx->uuid,
               nm_tofu_session_get_uuid(session) ? nm_tofu_session_get_uuid(session) : "NULL");
        return;
    }

    if (!tofu_certificate_agent_pick(ctx->req, &dest_agent)) {
        _NMLOG(LOGL_WARN, "no eligible agent for SSID=%s", ssid ? ssid : "<unknown>");
        return;
    }

    if (!nm_tofu_session_get_display_fields(session, &cn, &issuer, &org, &sha256, &exp, &url)) {
        _NMLOG(LOGL_WARN, "failed to extract certificate display fields");
        return;
    }

    if (nm_tofu_session_get_via_system_trust(session)) {
        disclaimer =
            _("Review the server certificate details below before trusting this network. "
              "Its issuing CA is also recognized by your system's trusted certificate store, "
              "which supports (but does not guarantee) that it is legitimate.");
    } else {
        disclaimer = _("Review the server certificate details below before trusting this network.");
    }

    /* Disconnect the state watcher BEFORE we intentionally deauthenticate, 
       so we don't accidentally cancel our own DBus prompt. */
    if (ctx->ac_state_id && ctx->req) {
        nm_clear_g_signal_handler(ctx->req, &ctx->ac_state_id);
    }

    /* Disconnect while user reviews to prevent reconnect loop */
    tofu_deauthenticate_connection_by_uuid(ctx->uuid);
    tofu_set_autoconnect_for_uuid(ctx->uuid, FALSE, NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP);

    /* Dispatch DBus Call to CertificateAgent */
    g_dbus_connection_call(dbus_conn,
                           dest_agent,
                           CERT_AGENT_OBJECT_PATH,
                           CERT_AGENT_IFACE,
                           "CertificateVerificationRequest",
                           g_variant_new("(ssssssss)",
                                         ssid ? ssid : "",
                                         cn ? cn : "N/A",
                                         issuer ? issuer : "N/A",
                                         org ? org : "N/A",
                                         sha256 ? sha256 : "N/A",
                                         exp ? exp : "N/A",
                                         disclaimer,
                                         url ? url : "N/A"),
                           G_VARIANT_TYPE("(b)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           NM_CERT_AGENT_TIMEOUT_MS,
                           g_task_get_cancellable(task),
                           on_agent_response_cb,
                           task);
}

static gboolean
_has_supported_eap_method(NMSetting8021x *s_8021x)
{
    guint32 n_eap = nm_setting_802_1x_get_num_eap_methods(s_8021x);
    guint32 i;

    for (i = 0; i < n_eap; i++) {
        const char *method = nm_setting_802_1x_get_eap_method(s_8021x, i);

        if (NM_IN_STRSET(method, "tls", "ttls", "peap"))
            return TRUE;
    }

    return FALSE;
}

static gboolean
_is_tofu_eligible(NMSetting8021x *s_8021x)
{
    return s_8021x
           && (nm_setting_802_1x_get_ca_verify_mode(s_8021x)
               == NM_SETTING_802_1X_CA_VERIFY_MODE_TOFU)
           && (nm_setting_802_1x_get_ca_cert_scheme(s_8021x) == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
           && _has_supported_eap_method(s_8021x);
}

void
nm_tofu_connection_setup(NMConnection         *connection,
                         NMSettingsConnection *sett_conn,
                         NMSettingWireless    *s_wireless,
                         NMSupplicantConfig   *config,
                         NMActiveConnection   *req,
                         gboolean             *out_skip_sup_timeout)
{
    NMSetting8021x    *s_8021x;
    const char        *uuid;
    gs_free char      *ssid_str = NULL;
    GBytes            *ssid_bytes;
    GTask             *task;
    TofuConnectionCtx *ctx;
    GCancellable      *cancellable;

    /* ... existing early returns and setup ... */

    s_8021x = nm_connection_get_setting_802_1x(connection);
    if (!_is_tofu_eligible(s_8021x))
        return;

    uuid       = nm_settings_connection_get_uuid(sett_conn);
    ssid_bytes = nm_setting_wireless_get_ssid(s_wireless);
    ssid_str   = ssid_bytes ? _nm_utils_ssid_to_utf8(ssid_bytes) : NULL;

    nm_tofu_session_set(nm_tofu_session_get(),
                        NM_TOFU_SESSION_TYPE_TOFU,
                        ssid_str,
                        uuid,
                        nm_active_connection_get_subject(req));
    nm_supplicant_config_suppress_credentials_for_tofu(config);

    *out_skip_sup_timeout = TRUE;

    /* --- New Cancellable Logic --- */
    cancellable = g_cancellable_new();
    task        = g_task_new(connection, cancellable, NULL, NULL);

    ctx              = g_new0(TofuConnectionCtx, 1);
    ctx->req         = g_object_ref(req);
    ctx->uuid        = g_strdup(uuid);
    ctx->ssid        = g_strdup(ssid_str);
    ctx->subject     = nm_active_connection_get_subject(req)
                           ? g_object_ref(nm_active_connection_get_subject(req))
                           : NULL;
    ctx->cancellable = cancellable;

    /* Hook up the cancellation listener */
    ctx->ac_state_id = g_signal_connect(req,
                                        "notify::" NM_ACTIVE_CONNECTION_STATE,
                                        G_CALLBACK(tofu_ac_state_changed_cb),
                                        cancellable);

    g_task_set_task_data(task, ctx, (GDestroyNotify) tofu_connection_ctx_free);

    ctx->stage3_id = g_signal_connect(nm_tofu_session_get(),
                                      "stage3-ready",
                                      G_CALLBACK(tofu_on_stage3_ready),
                                      task);
}
