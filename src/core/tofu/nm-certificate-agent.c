/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-certificate-agent.h"

#include <gio/gio.h>

#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-log-core/nm-logging.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_TOFU
#define _NMLOG(level, ...) \
    nm_log((level), (_NMLOG_DOMAIN), NULL, NULL, "cert-agent: " __VA_ARGS__)

/*****************************************************************************/

typedef struct {
    char   *unique;          /* D-Bus unique name (:1.x), owned by D-Bus daemon — not caller-supplied */
    char   *obj_path;        /* object path the agent exported CertificateAgent on */
    guint   watch_id;        /* NameOwnerChanged subscription id */
    guint32 uid;             /* resolved UID, used for selection policy */
    guint64 registered_msec; /* monotonic timestamp of registration */
} CertificateAgent;

/* Global list; intentionally not a GObject — there is only one NM process. */
static GPtrArray *s_agents = NULL;

/*****************************************************************************/

static void
agents_ensure(void)
{
    if (!s_agents)
        s_agents = g_ptr_array_new();
}

static void
certificate_agent_free(CertificateAgent *agent, GDBusConnection *conn)
{
    if (!agent)
        return;
    if (agent->watch_id) {
        g_dbus_connection_signal_unsubscribe(conn, agent->watch_id);
        agent->watch_id = 0;
    }
    _NMLOG(LOGL_DEBUG, "destroyed agent %s", agent->unique);
    g_free(agent->unique);
    g_free(agent->obj_path);
    g_free(agent);
}

static void
agents_remove_idx(guint idx, GDBusConnection *conn)
{
    CertificateAgent *agent = g_ptr_array_index(s_agents, idx);

    _NMLOG(LOGL_INFO, "removing agent %s (index %u)", agent->unique, idx);
    certificate_agent_free(agent, conn);
    g_ptr_array_remove_index_fast(s_agents, idx);
}

static gboolean
agents_remove_by_unique(const char *unique, GDBusConnection *conn)
{
    guint i;

    if (!s_agents)
        return FALSE;

    for (i = 0; i < s_agents->len; i++) {
        CertificateAgent *a = g_ptr_array_index(s_agents, i);

        if (nm_streq(a->unique, unique)) {
            agents_remove_idx(i, conn);
            return TRUE;
        }
    }
    return FALSE;
}

/*****************************************************************************/

/* Resolve the UID of a D-Bus unique name via the bus daemon.
 * Returns G_MAXUINT32 on failure. */
static guint32
uid_for_unique(GDBusConnection *conn, const char *unique)
{
    gs_unref_variant GVariant *reply = NULL;
    gs_free_error GError      *error = NULL;
    guint32                    uid   = G_MAXUINT32;

    reply = g_dbus_connection_call_sync(conn,
                                        "org.freedesktop.DBus",
                                        "/org/freedesktop/DBus",
                                        "org.freedesktop.DBus",
                                        "GetConnectionUnixUser",
                                        g_variant_new("(s)", unique),
                                        G_VARIANT_TYPE("(u)"),
                                        G_DBUS_CALL_FLAGS_NONE,
                                        2000,
                                        NULL,
                                        &error);
    if (!reply) {
        _NMLOG(LOGL_WARN, "could not get UID for %s: %s", unique, error->message);
        return G_MAXUINT32;
    }

    g_variant_get(reply, "(u)", &uid);
    return uid;
}

/*****************************************************************************/

static void
on_name_owner_changed(GDBusConnection *conn,
                      const gchar     *sender_name,
                      const gchar     *object_path,
                      const gchar     *iface,
                      const gchar     *signal,
                      GVariant        *params,
                      gpointer         user_data)
{
    const char *name, *old_owner, *new_owner;

    g_variant_get(params, "(&s&s&s)", &name, &old_owner, &new_owner);

    /* unique name disappeared → drop agent */
    if (new_owner && new_owner[0] == '\0' && old_owner && old_owner[0] != '\0') {
        if (s_agents) {
            _NMLOG(LOGL_INFO, "agent %s vanished — unregistering", name);
            agents_remove_by_unique(name, conn);
        }
    }
}

/*****************************************************************************/

/**
 * nm_certificate_agent_register:
 *
 * Called from the RegisterCertificateAgent D-Bus handler (commit 7).
 * @sender_unique is taken from the D-Bus invocation context, not from the
 * caller-supplied arguments, so it cannot be spoofed.
 */
gboolean
nm_certificate_agent_register(GDBusConnection       *conn,
                               const char            *sender_unique,
                               const char            *object_path,
                               GDBusMethodInvocation *invocation)
{
    CertificateAgent *agent;

    g_return_val_if_fail(conn && sender_unique && object_path && invocation, FALSE);

    if (!nm_streq(object_path, "/org/freedesktop/NetworkManager/CertificateAgent")) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_INVALID_ARGS,
                                              "Bad object path: %s",
                                              object_path);
        return FALSE;
    }

    agents_ensure();

    /* Replace if same sender re-registers. */
    agents_remove_by_unique(sender_unique, conn);

    agent                  = g_new0(CertificateAgent, 1);
    agent->unique          = g_strdup(sender_unique);
    agent->obj_path        = g_strdup(object_path);
    agent->registered_msec = nm_utils_get_monotonic_timestamp_msec();
    agent->uid             = uid_for_unique(conn, sender_unique);

    /* Subscribe to watch for agent disappearing. */
    agent->watch_id = g_dbus_connection_signal_subscribe(conn,
                                                         "org.freedesktop.DBus",
                                                         "org.freedesktop.DBus",
                                                         "NameOwnerChanged",
                                                         "/org/freedesktop/DBus",
                                                         agent->unique,
                                                         G_DBUS_SIGNAL_FLAGS_NONE,
                                                         on_name_owner_changed,
                                                         NULL,
                                                         NULL);

    g_ptr_array_add(s_agents, agent);

    _NMLOG(LOGL_INFO,
           "registered agent: unique=%s path=%s uid=%u",
           agent->unique,
           agent->obj_path,
           agent->uid);

    g_dbus_method_invocation_return_value(invocation, NULL);
    return TRUE;
}

gboolean
nm_certificate_agent_unregister(GDBusConnection       *conn,
                                 const char            *sender_unique,
                                 GDBusMethodInvocation *invocation)
{
    guint i;

    g_return_val_if_fail(conn && sender_unique && invocation, FALSE);

    if (!s_agents) {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_FAILED,
                                              "No agents are registered");
        return FALSE;
    }

    for (i = 0; i < s_agents->len; i++) {
        CertificateAgent *a = g_ptr_array_index(s_agents, i);

        if (nm_streq(a->unique, sender_unique)) {
            agents_remove_idx(i, conn);
            _NMLOG(LOGL_INFO, "agent %s unregistered", sender_unique);
            g_dbus_method_invocation_return_value(invocation, NULL);
            return TRUE;
        }
    }

    g_dbus_method_invocation_return_error(invocation,
                                          G_DBUS_ERROR,
                                          G_DBUS_ERROR_FAILED,
                                          "No registered agent for this sender");
    return FALSE;
}

/**
 * nm_certificate_agent_pick:
 *
 * Selection policy: prefer the most-recently-registered non-root agent
 * (uid != 0) — this is the desktop user's agent.  Fall back to the newest
 * overall if only root agents are present.
 */
gboolean
nm_certificate_agent_pick(char **out_unique, char **out_object_path)
{
    CertificateAgent *best = NULL;
    gint              i;

    g_return_val_if_fail(out_unique && out_object_path, FALSE);

    if (!s_agents || s_agents->len == 0)
        return FALSE;

    for (i = (gint) s_agents->len - 1; i >= 0; i--) {
        CertificateAgent *a = g_ptr_array_index(s_agents, i);

        if (a->uid != 0) {
            best = a;
            break;
        }
        if (!best)
            best = a;
    }

    if (!best)
        return FALSE;

    *out_unique      = best->unique;
    *out_object_path = best->obj_path;
    return TRUE;
}

/*****************************************************************************/

typedef struct {
    char                   *dest_unique;
    char                   *ssid;
    NMCertAgentResponseFunc callback;
    gpointer                user_data;
} CertCallCtx;

static void
cert_req_cb(GObject *src, GAsyncResult *res, gpointer user_data)
{
    CertCallCtx              *ctx      = user_data;
    gs_unref_variant GVariant *reply   = NULL;
    gs_free_error GError      *error   = NULL;
    gboolean                   accepted = FALSE;

    reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, &error);

    if (!reply) {
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT)
            || g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY)) {
            _NMLOG(LOGL_WARN,
                   "agent %s timed out (SSID=%s) — treating as rejected",
                   ctx->dest_unique,
                   ctx->ssid);
        } else if (g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
                   || g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER)) {
            _NMLOG(LOGL_WARN,
                   "agent %s disappeared during request (SSID=%s)",
                   ctx->dest_unique,
                   ctx->ssid);
        } else {
            _NMLOG(LOGL_WARN,
                   "agent %s call failed (SSID=%s): %s",
                   ctx->dest_unique,
                   ctx->ssid,
                   error->message);
        }
        /* all failure modes → reject */
        accepted = FALSE;
    } else {
        g_variant_get(reply, "(b)", &accepted);
        _NMLOG(LOGL_INFO,
               "agent %s: user %s certificate (SSID=%s)",
               ctx->dest_unique,
               accepted ? "ACCEPTED" : "REJECTED",
               ctx->ssid);
    }

    if (ctx->callback)
        ctx->callback(accepted, ctx->ssid, ctx->user_data);

    g_free(ctx->dest_unique);
    g_free(ctx->ssid);
    g_free(ctx);
}

void
nm_certificate_agent_call_request(GDBusConnection        *conn,
                                   const char             *ssid,
                                   const char             *cn,
                                   const char             *issuer,
                                   const char             *org,
                                   const char             *sha256,
                                   const char             *exp,
                                   const char             *disclaimer,
                                   const char             *url,
                                   NMCertAgentResponseFunc callback,
                                   gpointer                user_data)
{
    CertCallCtx *ctx;
    char        *dest = NULL;
    char        *path = NULL;

    g_return_if_fail(conn);

    if (!nm_certificate_agent_pick(&dest, &path)) {
        _NMLOG(LOGL_WARN, "no agent available for SSID=%s", ssid);
        if (callback)
            callback(FALSE, ssid, user_data);
        return;
    }

    _NMLOG(LOGL_INFO, "calling agent %s at %s for SSID=%s", dest, path, ssid);

    ctx            = g_new0(CertCallCtx, 1);
    ctx->dest_unique = g_strdup(dest);
    ctx->ssid        = g_strdup(ssid);
    ctx->callback    = callback;
    ctx->user_data   = user_data;

    g_dbus_connection_call(conn,
                           dest,
                           path,
                           "org.freedesktop.NetworkManager.CertificateAgent",
                           "CertificateVerificationRequest",
                           g_variant_new("(ssssssss)",
                                         ssid,
                                         cn,
                                         issuer,
                                         org,
                                         sha256,
                                         exp,
                                         disclaimer,
                                         url),
                           G_VARIANT_TYPE("(b)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           NM_CERT_AGENT_TIMEOUT_MS,
                           NULL,
                           cert_req_cb,
                           ctx);
}

void
nm_certificate_agent_notify_failure(GDBusConnection *conn,
                                    const char      *ssid,
                                    const char      *message)
{
    char *dest = NULL;
    char *path = NULL;

    g_return_if_fail(conn);

    if (!nm_certificate_agent_pick(&dest, &path)) {
        _NMLOG(LOGL_WARN, "no agent available to notify failure for SSID=%s", ssid);
        return;
    }

    g_dbus_connection_call(conn,
                           dest,
                           path,
                           "org.freedesktop.NetworkManager.CertificateAgent",
                           "CertificateVerificationFailure",
                           g_variant_new("(ss)", ssid, message),
                           NULL,
                           G_DBUS_CALL_FLAGS_NONE,
                           0,
                           NULL,
                           NULL,
                           NULL);
}
