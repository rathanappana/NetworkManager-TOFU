/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-wifi-tofu.h"

#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-crypto/nm-crypto.h"
#include "nm-act-request.h"
#include "nm-auth-utils.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-secret-agent.h"
#include "settings/nm-settings-connection.h"

struct _NMWifiTofu {
    char      *system_ca_path;
    GPtrArray *chain;       /* GBytes, indexed by the depth reported by wpa_supplicant */
    GVariant  *server_cert; /* the "Certification" signal data of the server certificate */

    /* Set once the server certificate was received. */
    char                 *fingerprint;
    char                 *domain;
    GBytes               *root_ca; /* unless NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT */
    NMWifiTofuTrustAnchor trust_anchor;
    bool                  system_trusted : 1;

    bool changed : 1; /* the certificate replaces a trusted one */

    NMActRequest        *req;
    NMSecretAgent       *agent;
    NMSecretAgentCallId *call_id;
    NMAuthChain         *auth_chain;
    GSource             *fail_source;
    NMWifiTofuCallback   callback;
    gpointer             user_data;
};

/*****************************************************************************/

static void
_bytes_unref0(gpointer bytes)
{
    if (bytes)
        g_bytes_unref(bytes);
}

/* Like the domain-match of wpa_supplicant: the first DNS name of the
 * subjectAltName, or the common name if there is no DNS name. */
static char *
_get_server_name(GVariant *cert_info)
{
    gs_free const char **altsubject = NULL;
    const char          *subject;
    const char          *cn;
    gsize                len;
    guint                i;
    gboolean             has_dns = FALSE;

    if (g_variant_lookup(cert_info, "altsubject", "^a&s", &altsubject)) {
        for (i = 0; altsubject[i]; i++) {
            if (!g_str_has_prefix(altsubject[i], "DNS:"))
                continue;
            if (altsubject[i][NM_STRLEN("DNS:")])
                return g_strdup(&altsubject[i][NM_STRLEN("DNS:")]);
            has_dns = TRUE;
        }
    }
    if (has_dns)
        return NULL;

    /* The subject is like "/C=BE/O=Example/CN=radius.example.org". */
    if (!g_variant_lookup(cert_info, "subject", "&s", &subject))
        return NULL;
    cn = g_strrstr(subject, "/CN=");
    if (!cn)
        return NULL;
    cn += NM_STRLEN("/CN=");
    len = strcspn(cn, "/");
    if (len == 0)
        return NULL;
    for (i = 0; i < len; i++) {
        if (!g_ascii_isalnum(cn[i]) && !NM_IN_SET(cn[i], '.', '-', '*'))
            return NULL;
    }
    return g_strndup(cn, len);
}

/* Returns the CA of @cas that @chain leads to, if any. */
static GBytes *
_find_trust_anchor(GPtrArray *chain, GPtrArray *cas)
{
    gs_unref_ptrarray GPtrArray *one = NULL;
    guint                        i;

    if (!nm_crypto_verify_x509_chain(chain, cas, NULL))
        return NULL;

    one = g_ptr_array_sized_new(1);
    g_ptr_array_add(one, NULL);
    for (i = 0; i < cas->len; i++) {
        one->pdata[0] = cas->pdata[i];
        if (nm_crypto_verify_x509_chain(chain, one, NULL))
            return g_bytes_ref(cas->pdata[i]);
    }
    return NULL;
}

/* Chooses how to remember the server: by a CA if possible, as certificates
 * from the same CA for the same server name stay valid when the server
 * certificate is renewed. A CA alone would trust every server certificate it
 * issued, so it is only used together with the server name. */
static void
_choose_trust_anchor(NMWifiTofu *tofu)
{
    gs_unref_ptrarray GPtrArray *system_cas = NULL;
    gs_unref_ptrarray GPtrArray *root       = NULL;
    GBytes                      *top;

    gs_unref_bytes GBytes *system_ca = NULL;

    tofu->trust_anchor = NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT;

    if (tofu->system_ca_path) {
        system_cas           = nm_crypto_load_x509_certificates(tofu->system_ca_path);
        system_ca            = _find_trust_anchor(tofu->chain, system_cas);
        tofu->system_trusted = !!system_ca;
    }

    if (!tofu->domain)
        return;

    /* Only that root CA, not every CA of the system. */
    if (system_ca) {
        tofu->trust_anchor = NM_WIFI_TOFU_TRUST_ANCHOR_SYSTEM_CA;
        tofu->root_ca      = g_steal_pointer(&system_ca);
        return;
    }

    /* A root CA sent by the server itself. */
    top = tofu->chain->pdata[tofu->chain->len - 1];
    if (tofu->chain->len < 2 || !nm_crypto_x509_is_self_issued(top))
        return;

    root = g_ptr_array_new();
    g_ptr_array_add(root, top);
    if (nm_crypto_verify_x509_chain(tofu->chain, root, NULL)) {
        tofu->trust_anchor = NM_WIFI_TOFU_TRUST_ANCHOR_ROOT_CA;
        tofu->root_ca      = g_bytes_ref(top);
    }
}

/**
 * nm_wifi_tofu_add_certificate:
 * @tofu: the #NMWifiTofu
 * @cert_info: the a{sv} argument of wpa_supplicant's "Certification" signal
 *
 * Records a certificate of the chain that the server sent. wpa_supplicant
 * reports them from the top of the chain down to the server certificate
 * itself, at depth 0. With that, the trust anchor is chosen.
 *
 * Returns: %TRUE if @cert_info is the server certificate. Only the first
 *   server certificate is accepted.
 */
gboolean
nm_wifi_tofu_add_certificate(NMWifiTofu *tofu, GVariant *cert_info)
{
    nm_auto_free_checksum GChecksum *sum   = NULL;
    gs_unref_variant GVariant       *depth = NULL;
    gs_unref_variant GVariant       *cert  = NULL;
    guint8                           digest[NM_UTILS_CHECKSUM_LENGTH_SHA256];
    const guint8                    *data;
    gsize                            len;
    guint32                          d;
    guint                            i;

    if (tofu->fingerprint)
        return FALSE;

    depth = g_variant_lookup_value(cert_info, "depth", G_VARIANT_TYPE_UINT32);
    cert  = g_variant_lookup_value(cert_info, "cert", G_VARIANT_TYPE_BYTESTRING);
    if (!depth || !cert)
        return FALSE;

    d = g_variant_get_uint32(depth);
    if (d > 32)
        return FALSE;

    data = g_variant_get_fixed_array(cert, &len, 1);
    if (d >= tofu->chain->len)
        g_ptr_array_set_size(tofu->chain, d + 1);
    _bytes_unref0(tofu->chain->pdata[d]);
    tofu->chain->pdata[d] = g_bytes_new(data, len);

    if (d != 0)
        return FALSE;

    /* Ignore certificates from an earlier handshake above a gap. */
    for (i = 1; i < tofu->chain->len; i++) {
        if (!tofu->chain->pdata[i]) {
            g_ptr_array_set_size(tofu->chain, i);
            break;
        }
    }

    sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, data, len);
    nm_utils_checksum_get_digest(sum, digest);

    tofu->fingerprint = nm_utils_bin2hexstr_full(digest, sizeof(digest), ':', TRUE, NULL);
    tofu->server_cert = g_variant_ref(cert_info);
    tofu->domain      = _get_server_name(cert_info);
    _choose_trust_anchor(tofu);
    return TRUE;
}

gboolean
nm_wifi_tofu_has_server_cert(NMWifiTofu *tofu)
{
    return !!tofu->fingerprint;
}

NMWifiTofuTrustAnchor
nm_wifi_tofu_get_trust_anchor(NMWifiTofu *tofu)
{
    return tofu->trust_anchor;
}

/**
 * nm_wifi_tofu_get_certificate:
 * @tofu: the #NMWifiTofu, after the server certificate was added
 * @ssid: (nullable): the SSID of the network
 * @changed: whether the certificate replaces a trusted one
 *
 * Returns: the floating a{sv} description of the server certificate for the
 *   ConfirmServerCertificate D-Bus method of certificate agents.
 */
GVariant *
nm_wifi_tofu_get_certificate(NMWifiTofu *tofu, GBytes *ssid, gboolean changed)
{
    static const char *const anchor_names[] = {
        [NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT] = "server-certificate",
        [NM_WIFI_TOFU_TRUST_ANCHOR_ROOT_CA]     = "root-ca",
        [NM_WIFI_TOFU_TRUST_ANCHOR_SYSTEM_CA]   = "system-ca",
    };
    GVariantBuilder builder;
    GVariantBuilder cas;
    GVariant       *value;
    const char     *subject;
    guint           i;

    nm_assert(tofu->fingerprint);

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add(&builder,
                          "{sv}",
                          "certificate",
                          nm_g_bytes_to_variant_ay(tofu->chain->pdata[0]));
    g_variant_builder_init(&cas, G_VARIANT_TYPE("aay"));
    for (i = 1; i < tofu->chain->len; i++)
        g_variant_builder_add_value(&cas, nm_g_bytes_to_variant_ay(tofu->chain->pdata[i]));
    g_variant_builder_add(&builder, "{sv}", "ca-certificates", g_variant_builder_end(&cas));

    g_variant_builder_add(&builder, "{sv}", "fingerprint", g_variant_new_string(tofu->fingerprint));

    if (g_variant_lookup(tofu->server_cert, "subject", "&s", &subject))
        g_variant_builder_add(&builder, "{sv}", "subject", g_variant_new_string(subject));

    value = g_variant_lookup_value(tofu->server_cert, "altsubject", G_VARIANT_TYPE_STRING_ARRAY);
    if (value) {
        g_variant_builder_add(&builder, "{sv}", "altsubject", value);
        g_variant_unref(value);
    }

    g_variant_builder_add(&builder,
                          "{sv}",
                          "system-trusted",
                          g_variant_new_boolean(tofu->system_trusted));
    g_variant_builder_add(&builder,
                          "{sv}",
                          "trust-anchor",
                          g_variant_new_string(anchor_names[tofu->trust_anchor]));
    g_variant_builder_add(&builder, "{sv}", "changed", g_variant_new_boolean(changed));

    if (ssid)
        g_variant_builder_add(&builder, "{sv}", "ssid", nm_g_bytes_to_variant_ay(ssid));

    return g_variant_builder_end(&builder);
}

/*****************************************************************************/

static gboolean
_trust_anchor_equal(NMSetting8021x *a, NMSetting8021x *b)
{
    gs_unref_bytes GBytes *ca_a = NULL;
    gs_unref_bytes GBytes *ca_b = NULL;

    g_object_get(a, NM_SETTING_802_1X_CA_CERT, &ca_a, NULL);
    g_object_get(b, NM_SETTING_802_1X_CA_CERT, &ca_b, NULL);

    return nm_g_bytes_equal0(ca_a, ca_b)
           && nm_streq0(nm_setting_802_1x_get_ca_path(a), nm_setting_802_1x_get_ca_path(b))
           && nm_setting_802_1x_get_system_ca_certs(a) == nm_setting_802_1x_get_system_ca_certs(b)
           && nm_streq0(nm_setting_802_1x_get_server_cert_hash(a),
                        nm_setting_802_1x_get_server_cert_hash(b))
           && nm_streq0(nm_setting_802_1x_get_domain_match(a),
                        nm_setting_802_1x_get_domain_match(b));
}

static void
_copy_trust_anchor(NMSetting8021x *from, NMSetting8021x *to)
{
    gs_unref_bytes GBytes *ca_cert = NULL;

    g_object_get(from, NM_SETTING_802_1X_CA_CERT, &ca_cert, NULL);
    g_object_set(to,
                 NM_SETTING_802_1X_CA_CERT,
                 ca_cert,
                 NM_SETTING_802_1X_CA_PATH,
                 nm_setting_802_1x_get_ca_path(from),
                 NM_SETTING_802_1X_SYSTEM_CA_CERTS,
                 nm_setting_802_1x_get_system_ca_certs(from),
                 NM_SETTING_802_1X_SERVER_CERT_HASH,
                 nm_setting_802_1x_get_server_cert_hash(from),
                 NM_SETTING_802_1X_DOMAIN_MATCH,
                 nm_setting_802_1x_get_domain_match(from),
                 NULL);
}

/**
 * nm_wifi_tofu_set_trust_anchor:
 * @tofu: the #NMWifiTofu, after the server certificate was added
 * @s_8021x: the 802.1X setting to update
 *
 * Replaces the properties that verify the server with the chosen trust
 * anchor: #NMSetting8021x:server-cert-hash, or #NMSetting8021x:ca-cert
 * together with #NMSetting8021x:domain-match. #NMSetting8021x:ca-path and
 * #NMSetting8021x:system-ca-certs are cleared.
 */
void
nm_wifi_tofu_set_trust_anchor(NMWifiTofu *tofu, NMSetting8021x *s_8021x)
{
    nm_assert(tofu->fingerprint);

    g_object_set(s_8021x,
                 NM_SETTING_802_1X_CA_CERT,
                 tofu->root_ca,
                 NM_SETTING_802_1X_CA_PATH,
                 NULL,
                 NM_SETTING_802_1X_SYSTEM_CA_CERTS,
                 FALSE,
                 NM_SETTING_802_1X_SERVER_CERT_HASH,
                 tofu->trust_anchor == NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT ? tofu->fingerprint
                                                                             : NULL,
                 NM_SETTING_802_1X_DOMAIN_MATCH,
                 tofu->trust_anchor == NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT ? NULL : tofu->domain,
                 NULL);
}

/* Stores the trust anchor in the profile and in the applied connection, which
 * must stay identical to the profile. Only the properties of the trust anchor
 * are changed, so the profile is compared with the applied connection for
 * them alone. */
static gboolean
_store_trust_anchor(NMWifiTofu *tofu, GError **error)
{
    NMSettingsConnection         *sett_conn  = nm_act_request_get_settings_connection(tofu->req);
    NMConnection                 *applied    = nm_act_request_get_applied_connection(tofu->req);
    gs_unref_object NMConnection *connection = NULL;
    NMSetting8021x               *s_8021x;

    connection = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sett_conn));
    s_8021x    = nm_connection_get_setting_802_1x(connection);

    /* The profile might have been changed while the user was asked. */
    if (!s_8021x || !nm_setting_802_1x_get_trust_on_first_use(s_8021x)
        || !_trust_anchor_equal(s_8021x, nm_connection_get_setting_802_1x(applied))) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            "the profile was modified");
        return FALSE;
    }

    nm_wifi_tofu_set_trust_anchor(tofu, s_8021x);
    if (!nm_settings_connection_update(sett_conn,
                                       NULL,
                                       connection,
                                       NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                       "tofu",
                                       error))
        return FALSE;

    /* Copy what was stored: a CA certificate is moved to a file. */
    _copy_trust_anchor(
        nm_connection_get_setting_802_1x(nm_settings_connection_get_connection(sett_conn)),
        nm_connection_get_setting_802_1x(applied));
    return TRUE;
}

static void
_complete(NMWifiTofu *tofu, gboolean trusted, const char *reason, GError *error)
{
    NMWifiTofuCallback    callback = g_steal_pointer(&tofu->callback);
    gs_free_error GError *local    = NULL;

    nm_assert(callback);

    if (reason) {
        if (error)
            g_set_error(&local,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        "%s: %s",
                        reason,
                        error->message);
        else
            g_set_error_literal(&local, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, reason);
        error = local;
    }
    callback(tofu, trusted, error, tofu->user_data);
}

static const char *
_get_modify_permission(NMConnection *profile)
{
    return nm_setting_connection_get_num_permissions(nm_connection_get_setting_connection(profile))
                   == 1
               ? NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN
               : NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;
}

static gboolean
_delete_profile_cb(gpointer user_data)
{
    NMSettingsConnection *sett_conn = user_data;

    if (nm_settings_connection_still_valid(sett_conn))
        nm_settings_connection_delete(sett_conn, FALSE);
    return G_SOURCE_REMOVE;
}

static void
_reject_auth_done_cb(NMAuthChain *chain, GDBusMethodInvocation *context, gpointer user_data)
{
    NMWifiTofu           *tofu = user_data;
    const char           *perm = nm_auth_chain_get_data(chain, "perm");
    NMSettingsConnection *sett_conn;

    tofu->auth_chain = NULL;

    if (nm_auth_chain_get_result(chain, perm) != NM_AUTH_CALL_RESULT_YES) {
        _complete(tofu, FALSE, "the user rejected the server certificate", NULL);
        return;
    }

    /* Not now: deleting the profile deactivates it. */
    sett_conn = nm_act_request_get_settings_connection(tofu->req);
    g_idle_add_full(G_PRIORITY_DEFAULT_IDLE,
                    _delete_profile_cb,
                    g_object_ref(sett_conn),
                    g_object_unref);
    _complete(tofu, FALSE, "the user rejected the server certificate, deleting the profile", NULL);
}

/* The user does not want to connect to this server. A profile that was never
 * trusted is deleted, if the user may modify it without being asked for a
 * password. Otherwise it is kept, but no longer connects automatically, until
 * the user activates it. */
static void
_reject(NMWifiTofu *tofu, NMSecretAgent *agent)
{
    NMSettingsConnection *sett_conn = nm_act_request_get_settings_connection(tofu->req);
    NMConnection         *profile   = nm_settings_connection_get_connection(sett_conn);
    const char           *perm;

    nm_settings_connection_autoconnect_blocked_reason_set(
        sett_conn,
        NM_SETTINGS_AUTOCONNECT_BLOCKED_REASON_USER_REQUEST,
        TRUE);

    if (tofu->changed
        || !nm_auth_is_subject_in_acl(profile, nm_secret_agent_get_subject(agent), NULL)) {
        _complete(tofu, FALSE, "the user rejected the server certificate", NULL);
        return;
    }

    perm             = _get_modify_permission(profile);
    tofu->auth_chain = nm_auth_chain_new_subject(nm_secret_agent_get_subject(agent),
                                                 NULL,
                                                 _reject_auth_done_cb,
                                                 tofu);
    nm_auth_chain_set_data(tofu->auth_chain, "perm", (gpointer) perm, NULL);
    nm_auth_chain_add_call_unsafe(tofu->auth_chain, perm, FALSE);
}

static void
_auth_done_cb(NMAuthChain *chain, GDBusMethodInvocation *context, gpointer user_data)
{
    NMWifiTofu           *tofu  = user_data;
    const char           *perm  = nm_auth_chain_get_data(chain, "perm");
    gs_free_error GError *error = NULL;

    tofu->auth_chain = NULL;

    if (nm_auth_chain_get_result(chain, perm) != NM_AUTH_CALL_RESULT_YES) {
        _complete(tofu,
                  FALSE,
                  "not authorized to store the server certificate in the profile",
                  NULL);
        return;
    }

    if (!_store_trust_anchor(tofu, &error)) {
        _complete(tofu, FALSE, "failed to store the server certificate", error);
        return;
    }

    _complete(tofu, TRUE, NULL, NULL);
}

static void
_agent_reply_cb(NMSecretAgent       *agent,
                NMSecretAgentCallId *call_id,
                GVariant            *reply,
                GError              *error,
                gpointer             user_data)
{
    NMWifiTofu   *tofu = user_data;
    NMConnection *profile;
    const char   *perm;
    gboolean      accepted = FALSE;

    if (tofu->call_id != call_id) {
        /* cancelled by nm_wifi_tofu_free() */
        return;
    }
    tofu->call_id = NULL;

    if (error) {
        _complete(tofu, FALSE, "the agent failed", error);
        return;
    }

    g_variant_get(reply, "(b)", &accepted);
    if (!accepted) {
        _reject(tofu, agent);
        return;
    }

    /* Like for saving secrets: storing the certificate in a profile that is
     * shared with other users requires the permission to modify it. Check the
     * profile as it is now, it might have been changed during the prompt. */
    profile =
        nm_settings_connection_get_connection(nm_act_request_get_settings_connection(tofu->req));
    if (!nm_auth_is_subject_in_acl(profile, nm_secret_agent_get_subject(agent), NULL)) {
        _complete(tofu,
                  FALSE,
                  "not authorized to store the server certificate in the profile",
                  NULL);
        return;
    }
    perm = _get_modify_permission(profile);

    tofu->auth_chain =
        nm_auth_chain_new_subject(nm_secret_agent_get_subject(agent), NULL, _auth_done_cb, tofu);
    nm_auth_chain_set_data(tofu->auth_chain, "perm", (gpointer) perm, NULL);
    nm_auth_chain_add_call_unsafe(tofu->auth_chain, perm, TRUE);
}

static gboolean
_no_agent_cb(gpointer user_data)
{
    NMWifiTofu *tofu = user_data;

    nm_clear_g_source_inst(&tofu->fail_source);
    _complete(tofu, FALSE, "no agent can confirm the server certificate", NULL);
    return G_SOURCE_REMOVE;
}

/**
 * nm_wifi_tofu_confirm:
 * @tofu: the #NMWifiTofu, after the server certificate was added
 * @req: the activation request
 * @changed: whether the certificate replaces a trusted one, which the
 *   network rejected
 * @callback: invoked asynchronously with the result, unless @tofu is freed
 *   before. The callback may free @tofu.
 * @user_data: user data for @callback
 *
 * Asks a certificate agent to confirm the server certificate. If the user
 * trusts it and may modify the profile, the chosen trust anchor is stored in
 * the profile and in the applied connection of @req. If the user rejects it,
 * the profile no longer connects automatically, and is deleted on first use
 * if the user may modify it.
 */
void
nm_wifi_tofu_confirm(NMWifiTofu        *tofu,
                     NMActRequest      *req,
                     gboolean           changed,
                     NMWifiTofuCallback callback,
                     gpointer           user_data)
{
    NMConnection *applied = nm_act_request_get_applied_connection(req);

    g_return_if_fail(tofu->fingerprint);
    g_return_if_fail(!tofu->callback);

    tofu->req       = g_object_ref(req);
    tofu->changed   = changed;
    tofu->callback  = callback;
    tofu->user_data = user_data;

    tofu->agent = nm_g_object_ref(nm_agent_manager_get_certificate_agent(
        nm_agent_manager_get(),
        applied,
        nm_active_connection_get_subject(NM_ACTIVE_CONNECTION(req))));
    if (!tofu->agent) {
        tofu->fail_source = nm_g_idle_add_source(_no_agent_cb, tofu);
        return;
    }

    tofu->call_id = nm_secret_agent_confirm_server_cert(
        tofu->agent,
        nm_dbus_object_get_path(NM_DBUS_OBJECT(nm_act_request_get_settings_connection(req))),
        nm_wifi_tofu_get_certificate(
            tofu,
            nm_setting_wireless_get_ssid(nm_connection_get_setting_wireless(applied)),
            changed),
        _agent_reply_cb,
        tofu);
}

/*****************************************************************************/

/**
 * nm_wifi_tofu_new:
 * @system_ca_path: (nullable): the file or directory of the CA certificates
 *   that the system trusts
 */
NMWifiTofu *
nm_wifi_tofu_new(const char *system_ca_path)
{
    NMWifiTofu *tofu = g_slice_new0(NMWifiTofu);

    tofu->system_ca_path = g_strdup(system_ca_path);
    tofu->chain          = g_ptr_array_new_with_free_func(_bytes_unref0);
    return tofu;
}

/**
 * nm_wifi_tofu_free:
 * @tofu: the #NMWifiTofu
 *
 * Frees @tofu and cancels a pending confirmation without invoking its
 * callback.
 */
void
nm_wifi_tofu_free(NMWifiTofu *tofu)
{
    if (!tofu)
        return;

    nm_clear_pointer(&tofu->auth_chain, nm_auth_chain_destroy);
    if (tofu->call_id)
        nm_secret_agent_cancel_call(tofu->agent, g_steal_pointer(&tofu->call_id));
    nm_clear_g_source_inst(&tofu->fail_source);
    g_clear_object(&tofu->agent);
    g_clear_object(&tofu->req);
    g_ptr_array_unref(tofu->chain);
    nm_clear_pointer(&tofu->server_cert, g_variant_unref);
    nm_clear_pointer(&tofu->root_ca, g_bytes_unref);
    g_free(tofu->system_ca_path);
    g_free(tofu->fingerprint);
    g_free(tofu->domain);
    nm_g_slice_free(tofu);
}
