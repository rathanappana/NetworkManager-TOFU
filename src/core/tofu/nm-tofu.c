/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

/*
 * TOFU (Trust On First Use) core state machine.
 *
 * Stages:
 *   1. Detection  - nm-device-wifi.c detects EAP connection with
 *                   ca-verify-mode=tofu; calls nm_tofu_set_session().
 *   2. Collection - nm_tofu_stage2_cert_signal() accumulates certificates
 *                   from wpa_supplicant's Certification D-Bus signal.
 *   3. Dispatch   - On leaf cert (depth==0): parse cert fields, call
 *                   registered CertificateAgent. NM does not independently
 *                   verify the chain here — wpa_supplicant's own TLS stack
 *                   already did, and is the sole authority on that.
 *   4. Response   - tofu_on_agent_response() handles accept/reject from
 *                   the agent UI; pins cert or removes profile.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-tofu.h"

#include <gnutls/x509.h>
#include <time.h>

#include "devices/nm-device.h"
#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-act-request.h"
#include "nm-active-connection.h"
#include "nm-auth-utils.h"
#include "nm-dbus-manager.h"
#include "nm-manager.h"
#include "settings/nm-agent-manager.h"
#include "settings/nm-secret-agent.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings.h"

/* The agent side of this interface (nmt-certificate-agent.c and
 * equivalents) is registered via AgentManager.RegisterWithCapabilities +
 * NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU, so nm_agent_manager_find_secret_agent()
 * can find it — no separate registration entry point needed. */
#define CERT_AGENT_OBJECT_PATH "/org/freedesktop/NetworkManager/CertificateAgent"
#define CERT_AGENT_IFACE       "org.freedesktop.NetworkManager.CertificateAgent"
#define NM_CERT_AGENT_TIMEOUT_MS 180000

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_TOFU
#define _NMLOG(level, ...) \
    nm_log((level), (_NMLOG_DOMAIN), NULL, NULL, "tofu: " __VA_ARGS__)

#define TOFU_CERT_DIR   NMSTATEDIR "/tofu"

/*****************************************************************************/
/* Session state (module-global; one NM process, one active session)          */

static NMTOFUSessionType  s_session_type   = NM_TOFU_SESSION_TYPE_DEFAULT;
static char              *s_ssid           = NULL;
static char              *s_uuid           = NULL;
static NMAuthSubject     *s_subject        = NULL; /* who initiated the
                                                     * connection attempt —
                                                     * only their agent gets
                                                     * asked, see
                                                     * tofu_certificate_agent_call_request() */
static NMTOFUCertSession *s_observed_certs = NULL; /* certs from wpa_supplicant */
static GBytes            *s_resolved_root  = NULL; /* raw DER of the resolved
                                                     * self-signed root — set once
                                                     * in tofu_stage3(), reused by
                                                     * both display and pin so
                                                     * they always agree */

/*****************************************************************************/
/* NMTOFUCertInfo / NMTOFUCertSession lifetime                                */

static void
cert_info_free(NMTOFUCertInfo *info)
{
    if (!info)
        return;
    g_free(info->subject);
    g_free(info->hash);
    nm_clear_pointer(&info->cert_data, g_bytes_unref);
    g_free(info);
}

static NMTOFUCertSession *
cert_session_new(void)
{
    NMTOFUCertSession *s;

    s        = g_new0(NMTOFUCertSession, 1);
    s->certs = g_ptr_array_new_with_free_func((GDestroyNotify) cert_info_free);
    return s;
}

static void
cert_session_free(NMTOFUCertSession *s)
{
    if (!s)
        return;
    g_ptr_array_unref(s->certs);
    g_free(s);
}

/*****************************************************************************/
/* Session management                                                          */

void
nm_tofu_set_session(NMTOFUSessionType type,
                    const char       *ssid,
                    const char       *uuid,
                    NMAuthSubject    *subject)
{
    nm_tofu_reset_session();

    s_session_type = type;
    s_ssid         = g_strdup(ssid ?: "");
    s_uuid         = g_strdup(uuid ?: "");
    s_subject      = subject ? g_object_ref(subject) : NULL;

    _NMLOG(LOGL_INFO, "session started: type=%d ssid=%s uuid=%s", (int) type, s_ssid, s_uuid);
}

NMTOFUSessionType
nm_tofu_get_session_type(void)
{
    return s_session_type;
}

const char *
nm_tofu_get_ssid(void)
{
    return s_ssid;
}

const char *
nm_tofu_get_uuid(void)
{
    return s_uuid;
}

void
nm_tofu_reset_session(void)
{
    if (s_session_type == NM_TOFU_SESSION_TYPE_DEFAULT && !s_observed_certs)
        return;

    nm_clear_pointer(&s_observed_certs, cert_session_free);
    nm_clear_pointer(&s_resolved_root, g_bytes_unref);
    nm_clear_g_free(&s_ssid);
    nm_clear_g_free(&s_uuid);
    g_clear_object(&s_subject);
    s_session_type = NM_TOFU_SESSION_TYPE_DEFAULT;

    _NMLOG(LOGL_DEBUG, "session reset");
}

/*****************************************************************************/
/* GnuTLS helpers (static — internal to this module)                          */

/*
 * Extract DNS names from the Subject Alternative Name extension of a
 * DER-encoded cert.  Falls back to Common Name if no DNS SAN is present.
 * Returns a GPtrArray of (char *); caller must g_ptr_array_unref().
 */
static GPtrArray *
extract_san_dnsnames(GBytes *cert_data)
{
    gnutls_x509_crt_t  crt;
    gnutls_datum_t     datum;
    GPtrArray         *names;
    unsigned int       idx = 0;
    char               cn_buf[256];
    size_t             cn_len = sizeof(cn_buf);

    names = g_ptr_array_new_with_free_func(g_free);

    datum.data = (unsigned char *) g_bytes_get_data(cert_data, NULL);
    datum.size = g_bytes_get_size(cert_data);

    if (datum.size == 0)
        return names;

    if (gnutls_x509_crt_init(&crt) < 0) {
        _NMLOG(LOGL_WARN, "extract_san: gnutls_x509_crt_init() failed");
        return names;
    }

    if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) < 0) {
        _NMLOG(LOGL_WARN, "extract_san: cert DER import failed");
        gnutls_x509_crt_deinit(crt);
        return names;
    }

    /* gnutls_x509_crt_get_subject_alt_name() takes a caller-allocated
     * buffer, not an auto-allocated one — a NULL/zero-size buffer always
     * fails with GNUTLS_E_SHORT_MEMORY_BUFFER rather than allocating, so
     * this needs the standard probe-then-fetch two-call pattern. Also uses
     * the _2 variant, which is the one that actually reports @san_type —
     * the plain variant's 5th parameter is @critical, not @san_type. */
    for (;;) {
        size_t         san_len = 0;
        unsigned int   san_type, critical;
        gs_free char  *san_buf = NULL;
        int            rc;

        rc = gnutls_x509_crt_get_subject_alt_name2(crt, idx, NULL, &san_len, &san_type, &critical);
        if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
            break;

        san_buf = g_malloc(san_len);
        rc = gnutls_x509_crt_get_subject_alt_name2(crt,
                                                    idx,
                                                    san_buf,
                                                    &san_len,
                                                    &san_type,
                                                    &critical);
        if (rc < 0)
            break;

        /* wpa_supplicant's own domain_match (tls_match_suffix_helper() in
         * tls_openssl.c) only ever checks SAN dNSName entries — never URI —
         * and falls back to CN only when the cert has zero dNSName entries
         * at all. Match that exactly, so what NM extracts here is always
         * something wpa_supplicant's own matcher will actually consider. */
        if (san_type == GNUTLS_SAN_DNSNAME)
            g_ptr_array_add(names, g_strndup(san_buf, san_len));
        idx++;
    }

    if (names->len == 0) {
        /* Fall back to Common Name. */
        if (gnutls_x509_crt_get_dn_by_oid(crt,
                                            GNUTLS_OID_X520_COMMON_NAME,
                                            0,
                                            0,
                                            cn_buf,
                                            &cn_len)
            >= 0)
            g_ptr_array_add(names, g_strdup(cn_buf));
    }

    gnutls_x509_crt_deinit(crt);
    return names;
}

/* Forward declaration — defined in the connection management section below. */
static void tofu_deauthenticate_connection_by_uuid(const char *uuid_target);
static void tofu_set_autoconnect_for_uuid(const char                      *uuid_target,
                                          gboolean                         enable,
                                          NMSettingsConnectionPersistMode  persist_mode);

/* Forward declaration — defined in the Stage 3 section below, called from
 * the CertificateAgent dispatch section above it. */
static void tofu_on_agent_response(gboolean response, const char *ssid, gpointer user_data);

/*****************************************************************************/
/* Connection management helpers (all static — only called within this file)   */

/*
 * Find the self-signed root CA for this session: first checks whichever
 * non-leaf certs the AP actually sent; if none of those is self-signed,
 * walks up from the highest-depth one via the system trust store (completes
 * chains like HARICA's, where "HARICA TLS RSA Root CA 2021" is itself
 * cross-signed by an older "...RootCA 2015" that isn't sent over the wire
 * but is present in the OS's own ca-certificates bundle).
 *
 * Only this one self-signed cert is ever needed locally, regardless of how
 * many intermediates the AP sends — wpa_supplicant completes the rest of
 * the path itself using whatever non-root certs arrive over the wire, on
 * every connection attempt alike. Returns owned raw DER bytes of the found
 * self-signed cert, or NULL if none could be found at all (caller falls
 * back to leaf-hash pinning).
 * @out_via_system_trust: if non-NULL, set to TRUE when the root was found
 * via the system trust store rather than sent by the AP itself — lets the
 * caller tell the user their OS already recognizes this CA, for extra
 * confidence in the disclaimer text.
 */
static GBytes *
tofu_resolve_self_signed_root(NMTOFUCertSession *observed_session, gboolean *out_via_system_trust)
{
    NMTOFUCertInfo *top = NULL;
    guint           i;

    if (out_via_system_trust)
        *out_via_system_trust = FALSE;

    g_return_val_if_fail(observed_session && observed_session->certs, NULL);

    for (i = 0; i < observed_session->certs->len; i++) {
        NMTOFUCertInfo    *info = g_ptr_array_index(observed_session->certs, i);
        gnutls_x509_crt_t  crt;
        gnutls_datum_t     datum;
        gboolean           self_signed = FALSE;

        if (!info || info->depth == 0 || !info->cert_data)
            continue;

        datum.data = (unsigned char *) g_bytes_get_data(info->cert_data, NULL);
        datum.size = (unsigned int) g_bytes_get_size(info->cert_data);

        gnutls_x509_crt_init(&crt);
        if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
            char   subj_buf[256] = {0};
            char   issr_buf[256] = {0};
            size_t subj_len      = sizeof(subj_buf);
            size_t issr_len      = sizeof(issr_buf);

            gnutls_x509_crt_get_dn(crt, subj_buf, &subj_len);
            gnutls_x509_crt_get_issuer_dn(crt, issr_buf, &issr_len);
            self_signed = gnutls_x509_crt_check_issuer(crt, crt) != 0;

            _NMLOG(LOGL_DEBUG,
                   "resolve-root: candidate depth=%u self_signed=%d subject='%s' issuer='%s'",
                   info->depth,
                   (int) self_signed,
                   subj_buf,
                   issr_buf);

            if (self_signed) {
                /* AP already sent a self-signed root directly — nothing to
                 * complete. Still check the system trust store, purely for
                 * the disclaimer's confidence wording: does the OS also
                 * recognize this exact cert (byte match, not just name —
                 * HARICA publishes two different certs under the identical
                 * subject name). Reuses the same trust-list pattern as the
                 * walk-up below, just to confirm rather than to complete. */
                if (out_via_system_trust) {
                    gnutls_x509_trust_list_t sys_trust = NULL;

                    gnutls_x509_trust_list_init(&sys_trust, 0);
                    if (gnutls_x509_trust_list_add_system_trust(sys_trust, 0, 0) > 0) {
                        gnutls_x509_crt_t match = NULL;

                        if (gnutls_x509_trust_list_get_issuer(sys_trust,
                                                              crt,
                                                              &match,
                                                              GNUTLS_TL_GET_COPY)
                                == GNUTLS_E_SUCCESS
                            && match) {
                            gnutls_datum_t match_der = {};

                            if (gnutls_x509_crt_export2(match, GNUTLS_X509_FMT_DER, &match_der)
                                == GNUTLS_E_SUCCESS) {
                                *out_via_system_trust =
                                    match_der.size == datum.size
                                    && memcmp(match_der.data, datum.data, datum.size) == 0;
                                gnutls_free(match_der.data);
                            }
                            gnutls_x509_crt_deinit(match);
                        }
                    }
                    gnutls_x509_trust_list_deinit(sys_trust, 0);
                }

                _NMLOG(LOGL_DEBUG,
                       "resolve-root: AP sent its own self-signed root at depth=%u (also in "
                       "system trust store: %d)",
                       info->depth,
                       out_via_system_trust ? (int) *out_via_system_trust : -1);
                gnutls_x509_crt_deinit(crt);
                return g_bytes_ref(info->cert_data);
            }
        } else {
            _NMLOG(LOGL_DEBUG, "resolve-root: candidate depth=%u DER import failed", info->depth);
        }
        gnutls_x509_crt_deinit(crt);

        if (!top || info->depth > top->depth)
            top = info;
    }

    if (!top)
        return NULL;

    /* AP didn't send a self-signed root itself — walk up from the
     * highest-depth observed cert via the system trust store. */
    {
        gnutls_x509_crt_t        top_crt;
        gnutls_datum_t           top_datum;
        gnutls_x509_trust_list_t trust_list = NULL;
        GBytes                  *result = NULL;

        top_datum.data = (unsigned char *) g_bytes_get_data(top->cert_data, NULL);
        top_datum.size = (unsigned int) g_bytes_get_size(top->cert_data);

        gnutls_x509_crt_init(&top_crt);
        if (gnutls_x509_crt_import(top_crt, &top_datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
            gnutls_x509_trust_list_init(&trust_list, 0);
            if (gnutls_x509_trust_list_add_system_trust(trust_list, 0, 0) > 0) {
                gnutls_x509_crt_t current = top_crt;
                int               depth   = 0;

                while (depth < 10) {
                    gnutls_x509_crt_t issuer = NULL;
                    int               rc;

                    rc = gnutls_x509_trust_list_get_issuer(trust_list,
                                                            current,
                                                            &issuer,
                                                            GNUTLS_TL_GET_COPY);
                    if (rc != GNUTLS_E_SUCCESS || !issuer)
                        break;

                    if (current != top_crt)
                        gnutls_x509_crt_deinit(current);
                    current = issuer;
                    depth++;

                    if (gnutls_x509_crt_check_issuer(current, current)) {
                        gnutls_datum_t der = {};

                        if (gnutls_x509_crt_export2(current, GNUTLS_X509_FMT_DER, &der)
                            == GNUTLS_E_SUCCESS) {
                            result = g_bytes_new(der.data, der.size);
                            gnutls_free(der.data);
                        }
                        break;
                    }
                }

                if (current != top_crt)
                    gnutls_x509_crt_deinit(current);
            }
            gnutls_x509_trust_list_deinit(trust_list, 0);
        }
        gnutls_x509_crt_deinit(top_crt);

        if (result) {
            _NMLOG(LOGL_DEBUG, "resolve-root: found self-signed root via system trust store");
            if (out_via_system_trust)
                *out_via_system_trust = TRUE;
        } else {
            _NMLOG(LOGL_INFO,
                   "resolve-root: no self-signed root found — AP didn't send one, "
                   "none in system trust store either");
        }
        return result;
    }
}

/*
 * Export @root_der (a single self-signed cert) as a PEM file in
 * TOFU_CERT_DIR. Returns owned path.
 */
static char *
tofu_write_root_pem(GBytes *root_der, GError **error)
{
    gs_free char     *path = NULL;
    gnutls_x509_crt_t crt;
    gnutls_datum_t    datum, pem_datum = {};

    datum.data = (unsigned char *) g_bytes_get_data(root_der, NULL);
    datum.size = (unsigned int) g_bytes_get_size(root_der);

    gnutls_x509_crt_init(&crt);
    if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS
        || gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &pem_datum) != GNUTLS_E_SUCCESS) {
        gnutls_x509_crt_deinit(crt);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to export root cert as PEM");
        return NULL;
    }
    gnutls_x509_crt_deinit(crt);

    g_mkdir_with_parents(TOFU_CERT_DIR, 0700);
    path = g_strdup_printf("%s/ca-cert-%s.pem",
                           TOFU_CERT_DIR,
                           (s_uuid && *s_uuid) ? s_uuid : "unknown");
    if (!g_file_set_contents(path, (char *) pem_datum.data, (gssize) pem_datum.size, error)) {
        gnutls_free(pem_datum.data);
        return NULL;
    }

    _NMLOG(LOGL_DEBUG, "saved self-signed root PEM (%u bytes) to %s", pem_datum.size, path);
    gnutls_free(pem_datum.data);
    return g_steal_pointer(&path);
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
    _NMLOG(LOGL_DEBUG, "no active connection for uuid=%s", uuid_target);
}

static void
tofu_set_autoconnect_for_uuid(const char                      *uuid_target,
                               gboolean                         enable,
                               NMSettingsConnectionPersistMode  persist_mode)
{
    NMSettingsConnection *sconn;
    NMConnection         *clone;
    NMSettingConnection  *s_con;
    gs_free_error GError *error = NULL;

    if (!uuid_target)
        return;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid_target);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "no connection found for uuid=%s", uuid_target);
        return;
    }

    clone = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_con = nm_connection_get_setting_connection(clone);
    if (!s_con) {
        _NMLOG(LOGL_WARN, "no connection setting for uuid=%s", uuid_target);
        g_object_unref(clone);
        return;
    }

    if (nm_setting_connection_get_autoconnect(s_con) == enable) {
        g_object_unref(clone);
        return;
    }

    g_object_set(s_con, NM_SETTING_CONNECTION_AUTOCONNECT, enable, NULL);
    if (!nm_settings_connection_update(sconn,
                                       NULL,
                                       clone,
                                       persist_mode,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                       "tofu",
                                       &error)) {
        _NMLOG(LOGL_WARN,
               "failed to set autoconnect=%s for uuid=%s: %s",
               enable ? "on" : "off",
               uuid_target,
               error->message);
    } else {
        _NMLOG(LOGL_INFO, "autoconnect=%s for uuid=%s", enable ? "on" : "off", uuid_target);
    }
    g_object_unref(clone);
}

/*
 * Returns the new NMActiveConnection on success (borrowed reference, owned
 * by NMManager — do not unref), or NULL on failure. The return value lets
 * the not-authorized path in tofu_accept_persist() hook a one-shot
 * state-changed handler to revert the temporary in-memory cert once this
 * one activation settles, instead of leaving it mutated indefinitely.
 */
static NMActiveConnection *
tofu_authenticate_connection_by_uuid(const char *uuid_target)
{
    NMManager                     *manager;
    NMSettingsConnection          *sconn;
    NMConnection                  *conn;
    NMDevice                      *device = NULL;
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

    /* Reconnect on the same interface the connection is actually bound
     * to — picking "any WiFi device" here can grab a different radio
     * than the one that ran the TOFU handshake (e.g. an AP-mode radio
     * hosting a test hostapd instance), reconnecting on the wrong
     * interface entirely. */
    {
        const char *iface = nm_connection_get_interface_name(conn);

        if (iface)
            device = nm_manager_get_device(manager, iface, NM_DEVICE_TYPE_WIFI);
    }
    if (!device) {
        /* No interface-name bound (common for profiles created without
         * an explicit ifname) — fall back to any available WiFi device. */
        NMDevice    *dev_iter;
        const CList *tmp_list;

        nm_manager_for_each_device(manager, dev_iter, tmp_list) {
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

static void
tofu_remove_connection(const char *uuid)
{
    NMSettingsConnection *sconn;

    if (!uuid)
        return;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "no connection found to remove for uuid=%s", uuid);
        return;
    }

    _NMLOG(LOGL_INFO, "removing connection profile for uuid=%s", uuid);
    nm_settings_connection_delete(sconn, FALSE);
}

static void
tofu_add_timestamp_to_connection(const char *uuid)
{
    NMSettingsConnection *sconn;

    if (!uuid)
        return;

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "no connection found for timestamp uuid=%s", uuid);
        return;
    }

    _NMLOG(LOGL_DEBUG, "updating timestamp for uuid=%s", uuid);
    nm_settings_connection_update_timestamp(sconn, (guint64) time(NULL));
}

/*
 * Write the resolved self-signed root (s_resolved_root, set once in
 * tofu_stage3()) into the connection profile's 802-1x ca-cert field, then
 * save to disk.
 *
 * Returns FALSE when no self-signed root was resolved for this session —
 * caller falls back to leaf-hash pinning in that case.
 * @domain: SAN DNS name (or CN fallback) of the observed leaf, or NULL — set
 * as 802-1x.domain-match alongside ca-cert. A CA-root pin alone trusts any
 * cert that CA ever issues for any name; domain-match narrows that back down
 * to the one server actually observed (upstream RFC's stated preference:
 * CA-hash/pin + domain match, see GitLab NetworkManager#1999).
 */
static gboolean
tofu_update_ca_cert(const char                      *uuid,
                    GBytes                          *root_der,
                    const char                      *domain,
                    NMSettingsConnectionPersistMode  persist_mode)
{
    gs_free char         *pem_path = NULL;
    gs_free_error GError *error = NULL;
    NMSettingsConnection *sconn;
    NMConnection         *clone;
    NMSetting8021x       *s_8021x;
    gs_free_error GError *upd_err = NULL;

    if (!root_der) {
        _NMLOG(LOGL_INFO, "update-ca-cert: no self-signed root resolved for this session");
        return FALSE;
    }

    pem_path = tofu_write_root_pem(root_der, &error);
    if (!pem_path) {
        _NMLOG(LOGL_WARN, "update-ca-cert: %s", error->message);
        return FALSE;
    }

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "update-ca-cert: no connection found for uuid=%s", uuid);
        return FALSE;
    }

    clone   = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_8021x = nm_connection_get_setting_802_1x(clone);
    if (!s_8021x) {
        _NMLOG(LOGL_WARN, "update-ca-cert: no 802-1x setting for uuid=%s", uuid);
        g_object_unref(clone);
        return FALSE;
    }

    if (!nm_setting_802_1x_set_ca_cert(s_8021x,
                                        pem_path,
                                        NM_SETTING_802_1X_CK_SCHEME_PATH,
                                        NULL,
                                        &upd_err)) {
        _NMLOG(LOGL_WARN,
               "update-ca-cert: set_ca_cert failed for uuid=%s: %s",
               uuid,
               upd_err->message);
        g_object_unref(clone);
        return FALSE;
    }

    if (domain && *domain)
        g_object_set(s_8021x, NM_SETTING_802_1X_DOMAIN_MATCH, domain, NULL);

    if (!nm_settings_connection_update(sconn,
                                       NULL,
                                       clone,
                                       persist_mode,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                       "tofu",
                                       &upd_err)) {
        _NMLOG(LOGL_WARN, "update-ca-cert: save failed for uuid=%s: %s", uuid, upd_err->message);
        g_object_unref(clone);
        return FALSE;
    }

    _NMLOG(LOGL_INFO,
           "update-ca-cert: set ca-cert=%s domain-match=%s for uuid=%s",
           pem_path,
           (domain && *domain) ? domain : "(none)",
           uuid);
    g_object_unref(clone);
    return TRUE;
}

/*
 * Pin a leaf-only observed cert directly on the connection profile's 802-1x
 * ca-cert field, using the SERVER_HASH scheme, then save to disk.
 * @domain: SAN DNS name (or CN fallback) of the observed leaf, or NULL — set
 * as 802-1x.domain-match alongside ca-cert. Redundant with the hash pin
 * itself (which already matches one exact cert) but kept consistent with
 * tofu_update_ca_cert()'s behavior; cheap, harmless either way.
 */
static void
tofu_update_ca_cert_hash(const char                      *uuid,
                         const char                      *hash_hex,
                         const char                      *domain,
                         NMSettingsConnectionPersistMode  persist_mode)
{
    gs_free char         *hash_uri = NULL;
    NMSettingsConnection *sconn;
    NMConnection         *clone;
    NMSetting8021x       *s_8021x;
    gs_free_error GError *upd_err = NULL;

    if (!hash_hex || !*hash_hex) {
        _NMLOG(LOGL_WARN, "update-ca-cert-hash: empty hash for uuid=%s", uuid);
        return;
    }

    hash_uri = g_strdup_printf("hash://server/sha256/%s", hash_hex);

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), uuid);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "update-ca-cert-hash: no connection found for uuid=%s", uuid);
        return;
    }

    clone   = nm_simple_connection_new_clone(nm_settings_connection_get_connection(sconn));
    s_8021x = nm_connection_get_setting_802_1x(clone);
    if (!s_8021x) {
        _NMLOG(LOGL_WARN, "update-ca-cert-hash: no 802-1x setting for uuid=%s", uuid);
        g_object_unref(clone);
        return;
    }

    if (!nm_setting_802_1x_set_ca_cert(s_8021x,
                                        hash_uri,
                                        NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH,
                                        NULL,
                                        &upd_err)) {
        _NMLOG(LOGL_WARN,
               "update-ca-cert-hash: set_ca_cert failed for uuid=%s: %s",
               uuid,
               upd_err->message);
        g_object_unref(clone);
        return;
    }

    if (domain && *domain)
        g_object_set(s_8021x, NM_SETTING_802_1X_DOMAIN_MATCH, domain, NULL);

    if (!nm_settings_connection_update(sconn,
                                       NULL,
                                       clone,
                                       persist_mode,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_INT_FLAGS_NONE,
                                       NM_SETTINGS_CONNECTION_UPDATE_REASON_UPDATE_NON_SECRET,
                                       "tofu",
                                       &upd_err)) {
        _NMLOG(LOGL_WARN,
               "update-ca-cert-hash: save failed for uuid=%s: %s",
               uuid,
               upd_err->message);
    } else {
        _NMLOG(LOGL_INFO,
               "update-ca-cert-hash: set ca-cert=%s domain-match=%s for uuid=%s",
               hash_uri,
               (domain && *domain) ? domain : "(none)",
               uuid);
    }
    g_object_unref(clone);
}

/*****************************************************************************/
/* CertificateAgent dispatch                                                   */

/* Only the initiating user's agent is ever eligible — no fall-back to other
 * users' agents on failure. This mirrors nm_agent_manager_find_secret_agent()'s
 * ACL+UID match exactly, but skips GetSecrets' multi-agent retry list: that
 * retry exists for requests with no specific initiator (autoconnect), where
 * several users' agents can be ACL-eligible at once. A TOFU popup always has
 * a specific initiator, so at most one agent is ever eligible. */
static gboolean
certificate_agent_pick(NMConnection *connection, char **out_unique)
{
    NMSecretAgent *agent;

    agent = nm_agent_manager_find_secret_agent(nm_agent_manager_get(),
                                               connection,
                                               s_subject,
                                               NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU);
    if (!agent)
        return FALSE;

    *out_unique = g_strdup(nm_secret_agent_get_dbus_owner(agent));
    return TRUE;
}

typedef struct {
    char *ssid;
} CertCallCtx;

static void
cert_req_cb(GObject *src, GAsyncResult *res, gpointer user_data)
{
    CertCallCtx               *ctx      = user_data;
    gs_unref_variant GVariant *reply    = NULL;
    gs_free_error GError      *error    = NULL;
    gboolean                   response = FALSE;

    reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, &error);

    if (!reply) {
        _NMLOG(LOGL_WARN,
               "agent call failed (SSID=%s): %s — treating as rejected",
               ctx->ssid,
               error->message);
    } else {
        g_variant_get(reply, "(b)", &response);
        _NMLOG(LOGL_INFO,
               "agent: user %s certificate (SSID=%s)",
               response ? "ACCEPTED" : "REJECTED",
               ctx->ssid);
    }

    tofu_on_agent_response(response, ctx->ssid, NULL);

    g_free(ctx->ssid);
    g_free(ctx);
}

static void
tofu_certificate_agent_call_request(GDBusConnection *conn,
                                    NMConnection     *connection,
                                    const char       *ssid,
                                    const char       *cn,
                                    const char       *issuer,
                                    const char       *org,
                                    const char       *sha256,
                                    const char       *exp,
                                    const char       *disclaimer,
                                    const char       *url)
{
    CertCallCtx  *ctx;
    gs_free char *dest = NULL;

    if (!certificate_agent_pick(connection, &dest)) {
        _NMLOG(LOGL_WARN, "no eligible agent for SSID=%s", ssid);
        tofu_on_agent_response(FALSE, ssid, NULL);
        return;
    }

    _NMLOG(LOGL_INFO, "calling agent %s for SSID=%s", dest, ssid);

    ctx       = g_new0(CertCallCtx, 1);
    ctx->ssid = g_strdup(ssid);

    g_dbus_connection_call(conn,
                           dest,
                           CERT_AGENT_OBJECT_PATH,
                           CERT_AGENT_IFACE,
                           "CertificateVerificationRequest",
                           g_variant_new("(ssssssss)", ssid, cn, issuer, org, sha256, exp, disclaimer, url),
                           G_VARIANT_TYPE("(b)"),
                           G_DBUS_CALL_FLAGS_NONE,
                           NM_CERT_AGENT_TIMEOUT_MS,
                           NULL,
                           cert_req_cb,
                           ctx);
}

/*****************************************************************************/
/* Stage 3: parse cert + dispatch to agent                                     */

/*
 * Snapshot of everything the accept path needs, taken before the polkit
 * round-trip — session state (s_uuid/s_resolved_root/s_subject/s_observed_certs)
 * can be reset or replaced by a new session while the chain is pending.
 */
typedef struct {
    char          *uuid;
    char          *domain;
    char          *leaf_hash; /* NULL if no leaf observed */
    GBytes        *resolved_root; /* ref'd snapshot of s_resolved_root, or NULL */
    NMAuthSubject *subject; /* ref'd snapshot of s_subject, or NULL */
} TofuAcceptCtx;

static void
tofu_accept_ctx_free(TofuAcceptCtx *ctx)
{
    if (!ctx)
        return;
    g_free(ctx->uuid);
    g_free(ctx->domain);
    g_free(ctx->leaf_hash);
    nm_clear_pointer(&ctx->resolved_root, g_bytes_unref);
    g_clear_object(&ctx->subject);
    g_free(ctx);
}

/*
 * Persist (or not) and reconnect. @authorized decides both the persist
 * mode AND which pin method is allowed:
 *
 * Authorized: TO_DISK, root CA pin preferred (tofu_update_ca_cert()),
 * falling back to leaf hash — same as before this gate existed.
 *
 * Not authorized: leaf-hash pin ONLY, IN_MEMORY_DETACHED. Root pinning is
 * deliberately skipped here even if one was resolved: tofu_update_ca_cert()
 * always writes the root PEM to TOFU_CERT_DIR via tofu_write_root_pem()
 * regardless of persist mode, so taking that path here would leave an
 * orphaned file on disk referenced by nothing, surviving every future NM
 * restart — confirmed by testing, a real leak, not hypothetical. The hash
 * scheme (ca-cert=hash://server/sha256/<hex>) needs no file at all, so it
 * has no equivalent leak — the only pin method safe to use when nothing
 * is allowed to touch disk.
 *
 * This is the split the RFC thread settled on (Mathy, Beniamino +1'd):
 * lack of modify.system/own permission doesn't block connecting, it just
 * doesn't survive to the next attempt or become part of the shared
 * profile.
 *
 * IN_MEMORY_DETACHED alone updates NM's live /run-backed copy of the
 * stored connection, which every later activation also reads from —
 * confirmed by testing to survive even a full `systemctl restart
 * NetworkManager` (NM rescans /run on every startup), not just this one
 * attempt. A fix via nm_manager_activate_connection()'s applied_connection
 * override was tried and reverted: it breaks the EAP identity/password
 * secrets fetch that runs during the same activation, because
 * nm_settings_connection_has_unmodified_applied_connection() requires
 * applied == stored before it'll hand back secrets, and the override
 * deliberately makes them differ. Fix used instead: still mutate the
 * stored connection in-memory (so applied == stored, secrets fetch still
 * works), but revert it back to no-cert right after THIS activation
 * settles (tofu_revert_temporary_cert(), hooked via a one-shot state
 * watcher in tofu_accept_persist() below) instead of leaving it mutated
 * indefinitely.
 */
static void
tofu_revert_temporary_cert(const char *uuid)
{
    NMSettingsConnection          *sconn;
    gs_unref_object NMConnection *clone = NULL;
    NMSetting8021x                *s_8021x;
    gs_free_error GError          *error = NULL;

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
        _NMLOG(LOGL_INFO,
               "revert-temporary-cert: cleared temporary pin for uuid=%s — "
               "next attempt re-triggers TOFU",
               uuid);
    }

    /* autoconnect=TRUE was also only ever meant for this one attempt in
     * the not-authorized path (set via tofu_set_autoconnect_for_uuid()
     * with IN_MEMORY_DETACHED in tofu_accept_persist()) — put it back to
     * FALSE in-memory too, same lifecycle as the cert above. */
    tofu_set_autoconnect_for_uuid(uuid, FALSE, NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
}

/*
 * One-shot: fires on every state change of the activation the temporary
 * pin was for, ignores transient ACTIVATING/DEACTIVATING states, and on
 * the first settled state (ACTIVATED or DEACTIVATED) disconnects itself
 * and reverts. @user_data is a heap-owned uuid string, freed here.
 */
static void
tofu_temp_pin_state_changed_cb(NMActiveConnection *active, GParamSpec *pspec, gpointer user_data)
{
    char                   *uuid  = user_data;
    NMActiveConnectionState state = nm_active_connection_get_state(active);

    if (state != NM_ACTIVE_CONNECTION_STATE_ACTIVATED
        && state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
        return;

    g_signal_handlers_disconnect_by_func(active, tofu_temp_pin_state_changed_cb, uuid);
    tofu_revert_temporary_cert(uuid);
    g_free(uuid);
}

static void
tofu_accept_persist(TofuAcceptCtx *ctx, gboolean authorized)
{
    gboolean temp_pin_applied = FALSE;

    if (authorized) {
        if (tofu_update_ca_cert(ctx->uuid,
                                ctx->resolved_root,
                                ctx->domain,
                                NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK)) {
            _NMLOG(LOGL_INFO, "agent response: pinned root CA for uuid=%s (persisted)", ctx->uuid);
        } else if (ctx->leaf_hash) {
            tofu_update_ca_cert_hash(ctx->uuid,
                                    ctx->leaf_hash,
                                    ctx->domain,
                                    NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK);
            _NMLOG(LOGL_INFO,
                   "agent response: pinned leaf hash for uuid=%s (persisted)",
                   ctx->uuid);
        } else {
            _NMLOG(LOGL_WARN, "agent response: no usable cert to pin for uuid=%s", ctx->uuid);
        }
    } else if (ctx->leaf_hash) {
        tofu_update_ca_cert_hash(ctx->uuid,
                                 ctx->leaf_hash,
                                 ctx->domain,
                                 NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
        _NMLOG(LOGL_INFO,
               "agent response: pinned leaf hash for uuid=%s "
               "(not persisted — modify permission denied)",
               ctx->uuid);
        temp_pin_applied = TRUE;
    } else {
        _NMLOG(LOGL_WARN,
               "agent response: no leaf hash to pin for uuid=%s (modify permission denied)",
               ctx->uuid);
    }

    /* Only reset the global session if it's still ours — a new one may
     * have started while the polkit chain was pending. */
    if (nm_streq0(s_uuid, ctx->uuid))
        nm_tofu_reset_session();

    tofu_set_autoconnect_for_uuid(ctx->uuid,
                                  TRUE,
                                  authorized ? NM_SETTINGS_CONNECTION_PERSIST_MODE_TO_DISK
                                             : NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_DETACHED);
    tofu_add_timestamp_to_connection(ctx->uuid);

    if (temp_pin_applied) {
        NMActiveConnection *active = tofu_authenticate_connection_by_uuid(ctx->uuid);

        if (active) {
            g_signal_connect(active,
                             "notify::" NM_ACTIVE_CONNECTION_STATE,
                             G_CALLBACK(tofu_temp_pin_state_changed_cb),
                             g_strdup(ctx->uuid));
        } else {
            /* Activation didn't even start (e.g. no WiFi device found) —
             * nothing will ever fire the state-changed watcher, so revert
             * immediately instead of leaving the temporary pin stuck. */
            tofu_revert_temporary_cert(ctx->uuid);
        }
    } else {
        tofu_authenticate_connection_by_uuid(ctx->uuid);
    }

    tofu_accept_ctx_free(ctx);
}

/*
 * Shared polkit modify.own/modify.system check — same permission split
 * real NM's own Settings.Connection.Update and .Delete D-Bus calls use
 * (get_modify_permission_basic(), nm-settings-connection.c:1917-1931), so
 * both the accept (pin+persist) and reject (delete) paths below reuse one
 * mechanism instead of each building its own auth chain.
 *
 * Returns TRUE if an async check was started — @done_func fires later via
 * tofu_polkit_check_cb(). Returns FALSE immediately, without ever calling
 * @done_func, when there's no real human subject to check (e.g. NM's own
 * autoconnect reconnecting on its own, subject type INTERNAL not
 * UNIX_PROCESS) — caller decides the safe default itself in that case.
 * allow_interaction=FALSE: never show an admin password popup, just read
 * whatever's already authorized.
 */
typedef void (*TofuPolkitDoneFunc)(gboolean authorized, gpointer user_data);

static void
tofu_polkit_check_cb(NMAuthChain *chain, GDBusMethodInvocation *context, gpointer user_data)
{
    TofuPolkitDoneFunc done_func = nm_auth_chain_get_data(chain, "done_func");
    const char         *perm     = nm_auth_chain_get_data(chain, "perm");
    gboolean            authorized;

    authorized = perm && nm_auth_chain_get_result(chain, perm) == NM_AUTH_CALL_RESULT_YES;

    _NMLOG(LOGL_DEBUG, "polkit %s check -> %s", perm ?: "(none)", authorized ? "YES" : "NO");

    done_func(authorized, nm_auth_chain_get_data(chain, "done_data"));
}

static gboolean
tofu_polkit_check_modify(NMConnection       *connection,
                         NMAuthSubject      *subject,
                         TofuPolkitDoneFunc  done_func,
                         gpointer            user_data)
{
    NMSettingConnection *s_con;
    const char          *perm;
    NMAuthChain          *chain;

    if (!connection || !subject
        || nm_auth_subject_get_subject_type(subject) != NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS)
        return FALSE;

    s_con = nm_connection_get_setting_connection(connection);
    perm  = (s_con && nm_setting_connection_get_num_permissions(s_con) == 1)
              ? NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN
              : NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM;

    chain = nm_auth_chain_new_subject(subject, NULL, tofu_polkit_check_cb, NULL);
    nm_auth_chain_set_data(chain, "perm", (gpointer) perm, NULL);
    nm_auth_chain_set_data(chain, "done_func", (gpointer) done_func, NULL);
    nm_auth_chain_set_data(chain, "done_data", user_data, NULL);
    nm_auth_chain_add_call_unsafe(chain, perm, FALSE); /* never show an admin popup */
    return TRUE;
}

static void
tofu_accept_polkit_done(gboolean authorized, gpointer user_data)
{
    tofu_accept_persist(user_data, authorized);
}

/*
 * Rejection also deletes the profile — same real modify action real NM's
 * own Settings.Connection.Delete D-Bus call requires modify.own/system
 * for. Without this, any eligible-but-unauthorized user could delete a
 * shared profile just by rejecting its cert.
 */
typedef struct {
    char              *uuid;
    char              *ssid;
    NMTOFUSessionType  session_type; /* snapshot — reject never deletes
                                      * during REVERIFY, regardless of
                                      * @authorized below */
} TofuRejectCtx;

static void
tofu_reject_finish(TofuRejectCtx *rctx, gboolean authorized)
{
    if (rctx->session_type == NM_TOFU_SESSION_TYPE_REVERIFY) {
        /* Re-verify reject: user may be on an evil-twin AP right now —
         * discard this attempt only, keep the existing pin untouched. */
        tofu_deauthenticate_connection_by_uuid(rctx->uuid);
        _NMLOG(LOGL_INFO,
               "user rejected re-verify cert; disconnected, profile kept for SSID=%s",
               rctx->ssid);
    } else if (authorized) {
        tofu_remove_connection(rctx->uuid);
        _NMLOG(LOGL_INFO, "user rejected cert; profile removed for SSID=%s", rctx->ssid);
    } else {
        _NMLOG(LOGL_INFO,
               "user rejected cert for SSID=%s, but not authorized to delete this profile "
               "— left in place",
               rctx->ssid);
    }
    g_free(rctx->uuid);
    g_free(rctx->ssid);
    g_free(rctx);
}

static void
tofu_reject_polkit_done(gboolean authorized, gpointer user_data)
{
    tofu_reject_finish(user_data, authorized);
}

/*
 * Called when the agent responds (accept/reject) or the call times out.
 * Snapshots SSID/UUID before resetting session so reconnect calls are safe.
 */
static void
tofu_on_agent_response(gboolean response, const char *ssid, gpointer user_data)
{
    _NMLOG(LOGL_INFO,
           "agent response: %s for SSID=%s",
           response ? "ACCEPTED" : "REJECTED",
           ssid ?: "(null)");

    if (!ssid || !*ssid) {
        _NMLOG(LOGL_WARN, "agent response: empty SSID — ignoring");
        return;
    }
    if (!nm_streq0(ssid, s_ssid)) {
        _NMLOG(LOGL_WARN,
               "agent response: SSID mismatch (got=%s expected=%s) — stale session",
               ssid,
               s_ssid ?: "");
        return;
    }

    if (response) {
        NMTOFUCertInfo       *leaf = NULL;
        TofuAcceptCtx        *ctx;
        NMSettingsConnection *sconn;
        NMConnection         *connection;
        guint                 i;

        if (s_observed_certs) {
            for (i = 0; i < s_observed_certs->certs->len; i++) {
                NMTOFUCertInfo *info = g_ptr_array_index(s_observed_certs->certs, i);

                if (info->depth == 0)
                    leaf = info;
            }
        }

        ctx                = g_new0(TofuAcceptCtx, 1);
        ctx->uuid          = g_strdup(s_uuid);
        ctx->resolved_root = s_resolved_root ? g_bytes_ref(s_resolved_root) : NULL;
        ctx->leaf_hash     = leaf ? g_strdup(leaf->hash) : NULL;
        ctx->subject       = s_subject ? g_object_ref(s_subject) : NULL;

        if (leaf && leaf->cert_data) {
            gs_unref_ptrarray GPtrArray *san_names = extract_san_dnsnames(leaf->cert_data);

            if (san_names->len > 0)
                ctx->domain = g_strdup(g_ptr_array_index(san_names, 0));
        }

        if (!ctx->resolved_root && !ctx->leaf_hash) {
            _NMLOG(LOGL_WARN, "agent response: no usable cert to pin for uuid=%s", ctx->uuid);
            tofu_accept_ctx_free(ctx);
            nm_tofu_reset_session();
            return;
        }

        sconn      = nm_settings_get_connection_by_uuid(nm_settings_get(), ctx->uuid);
        connection = sconn ? nm_settings_connection_get_connection(sconn) : NULL;

        /* Polkit gate per the RFC thread's settled design: a per-user agent
         * accepting a server identity for a system-wide profile is a
         * privilege boundary. No real human subject to check (e.g. NM's own
         * autoconnect reconnecting on its own) — default to the safe side,
         * same reasoning as the reject path below: an unattended reconnect
         * must never end up MORE trusted than an explicit, denied human
         * request would be. */
        if (!tofu_polkit_check_modify(connection, ctx->subject, tofu_accept_polkit_done, ctx))
            tofu_accept_persist(ctx, FALSE);
    } else {
        TofuRejectCtx                 *rctx       = g_new0(TofuRejectCtx, 1);
        NMSettingsConnection          *sconn;
        NMConnection                  *connection;
        gs_unref_object NMAuthSubject *snap_subject = s_subject ? g_object_ref(s_subject) : NULL;

        rctx->uuid         = g_strdup(s_uuid);
        rctx->ssid         = g_strdup(s_ssid);
        rctx->session_type = s_session_type;

        sconn      = nm_settings_get_connection_by_uuid(nm_settings_get(), rctx->uuid);
        connection = sconn ? nm_settings_connection_get_connection(sconn) : NULL;

        /* Reset now, independent of the polkit result below — the TOFU
         * interaction itself is over either way; only whether we're
         * allowed to delete the profile depends on authorization. uuid,
         * ssid, session_type and subject above are already snapshotted, so
         * clearing s_subject/s_session_type here is safe. */
        nm_tofu_reset_session();

        if (rctx->session_type == NM_TOFU_SESSION_TYPE_REVERIFY) {
            /* No modify happens on this path (no delete, no persist) —
             * nothing to gate behind polkit. */
            tofu_reject_finish(rctx, FALSE);
        } else if (!tofu_polkit_check_modify(connection, snap_subject, tofu_reject_polkit_done, rctx)) {
            tofu_reject_finish(rctx, FALSE);
        }
    }
}

/*
 * Parse the top-of-chain cert from s_observed_certs, extract display
 * fields (CN, issuer, org, SHA-256 fingerprint, expiry, SAN DNS names),
 * then dispatch an async CertificateVerificationRequest to the registered
 * agent.
 */
static void
tofu_parse_and_dispatch(const char *disclaimer)
{
    NMTOFUCertInfo    *leaf_cert        = NULL;
    GBytes            *display_cert_data = NULL;
    gnutls_x509_crt_t  crt;
    gnutls_datum_t     datum;
    char               cn[256]        = {0};
    char               issuer[256]    = {0};
    char               org[256]       = {0};
    char               sha256_hex[65] = {0};
    char               exp_str[128]   = {0};
    size_t             field_len;
    unsigned char      sha256_raw[32];
    size_t             sha256_len = sizeof(sha256_raw);
    time_t             exp_time;
    struct tm         *tm_info;
    GPtrArray         *san_names = NULL;
    const char        *best_url  = "N/A";
    NMDBusManager     *dbus_mgr;
    GDBusConnection   *dbus_conn;
    NMSettingsConnection *sconn;
    NMConnection      *connection;
    guint              i;

    if (!s_observed_certs || s_observed_certs->certs->len == 0) {
        _NMLOG(LOGL_WARN, "no certs to dispatch for SSID=%s", s_ssid);
        return;
    }

    sconn = nm_settings_get_connection_by_uuid(nm_settings_get(), s_uuid);
    if (!sconn) {
        _NMLOG(LOGL_WARN, "no connection found for uuid=%s — cannot dispatch", s_uuid);
        return;
    }
    connection = nm_settings_connection_get_connection(sconn);

    _NMLOG(LOGL_INFO,
           "dispatching %u cert(s) for SSID=%s",
           s_observed_certs->certs->len,
           s_ssid);

    /* The server's own leaf cert (depth==0) is what the user needs to
     * verify — not array index 0. wpa_supplicant's Certification signal
     * fires highest-depth-first (root/intermediate before leaf), so index 0
     * is the CA's own cert, not the server's; showing it here would ask the
     * user to verify the wrong entity's identity. */
    for (i = 0; i < s_observed_certs->certs->len; i++) {
        NMTOFUCertInfo *info = g_ptr_array_index(s_observed_certs->certs, i);

        if (info && info->depth == 0) {
            leaf_cert = info;
            break;
        }
    }
    /* Show whatever's actually being pinned: the resolved self-signed root
     * (set in tofu_stage3()) if one was found, since that's what the user
     * is really trusting going forward — otherwise the leaf itself, since
     * that's what gets hash-pinned instead. Domain/url below always come
     * from the leaf regardless, since that's the real server's identity. */
    display_cert_data = s_resolved_root ?: (leaf_cert ? leaf_cert->cert_data : NULL);

    if (!display_cert_data) {
        _NMLOG(LOGL_WARN, "invalid cert data for dispatch");
        return;
    }

    datum.data = (unsigned char *) g_bytes_get_data(display_cert_data, NULL);
    datum.size = g_bytes_get_size(display_cert_data);

    if (gnutls_x509_crt_init(&crt) < 0
        || gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) < 0) {
        _NMLOG(LOGL_WARN, "cert parse failed for dispatch (SSID=%s)", s_ssid);
        return;
    }

    field_len = sizeof(cn);
    gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, cn, &field_len);

    field_len = sizeof(issuer);
    gnutls_x509_crt_get_issuer_dn_by_oid(crt,
                                          GNUTLS_OID_X520_COMMON_NAME,
                                          0,
                                          0,
                                          issuer,
                                          &field_len);

    field_len = sizeof(org);
    gnutls_x509_crt_get_dn_by_oid(crt,
                                   GNUTLS_OID_X520_ORGANIZATION_NAME,
                                   0,
                                   0,
                                   org,
                                   &field_len);

    gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, sha256_raw, &sha256_len);
    for (i = 0; i < sha256_len; i++)
        (void) sprintf(&sha256_hex[i * 2], "%02X", sha256_raw[i]);

    exp_time = gnutls_x509_crt_get_expiration_time(crt);
    tm_info  = localtime(&exp_time);
    if (tm_info)
        strftime(exp_str, sizeof(exp_str), "%c", tm_info);

    gnutls_x509_crt_deinit(crt);

    if (leaf_cert && leaf_cert->cert_data) {
        san_names = extract_san_dnsnames(leaf_cert->cert_data);
        if (san_names->len > 0)
            best_url = g_ptr_array_index(san_names, 0);
    }

    _NMLOG(LOGL_INFO,
           "cert display fields: cn=%s issuer=%s org=%s sha256=%.16s... exp=%s url=%s",
           cn,
           issuer,
           org,
           sha256_hex,
           exp_str,
           best_url);

    dbus_mgr  = nm_dbus_manager_get();
    dbus_conn = nm_dbus_manager_get_dbus_connection(dbus_mgr);

    tofu_certificate_agent_call_request(dbus_conn,
                                        connection,
                                        s_ssid,
                                        cn,
                                        issuer,
                                        org,
                                        sha256_hex,
                                        exp_str,
                                        disclaimer ?: "",
                                        best_url);

    nm_clear_pointer(&san_names, g_ptr_array_unref);
}

/*
 * Stage 3 entry for TOFU path: dispatch cert info to the registered
 * CertificateAgent for user acceptance. wpa_supplicant's own TLS stack has
 * already validated (or not) this chain by the time its Certification
 * signal reaches us — NM does not redo that check here.
 *
 * Deauthenticates and disables autoconnect before calling the agent so the
 * user's decision is not overridden by an automatic reconnect.
 */
static void
tofu_stage3(void)
{
    gboolean via_system_trust = FALSE;

    /* Disconnect while user reviews; prevent reconnect loop. */
    tofu_deauthenticate_connection_by_uuid(s_uuid);
    tofu_set_autoconnect_for_uuid(s_uuid, FALSE, NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP);

    /* Resolved once here — reused by both the display below and the actual
     * pin on accept (tofu_update_ca_cert()), so they can never disagree. */
    nm_clear_pointer(&s_resolved_root, g_bytes_unref);
    s_resolved_root = tofu_resolve_self_signed_root(s_observed_certs, &via_system_trust);

    if (via_system_trust) {
        tofu_parse_and_dispatch(
            _("Review the server certificate details below before trusting this network. "
              "Its issuing CA is also recognized by your system's trusted certificate store, "
              "which supports (but does not guarantee) that it is legitimate."));
    } else {
        tofu_parse_and_dispatch(
            _("Review the server certificate details below before trusting this network."));
    }
}

/*
 * nm_tofu_stage2_eap_failure: see nm-tofu.h. Reuses tofu_stage3() as-is —
 * same deauth + resolve-root + agent dispatch as first-use, since the only
 * difference (reject must not delete) lives in the reject path, not here.
 */
void
nm_tofu_stage2_eap_failure(const char *status, const char *parameter)
{
    if (s_session_type != NM_TOFU_SESSION_TYPE_REVERIFY)
        return;
    if (!nm_streq0(status, "remote certificate verification"))
        return;
    if (nm_streq0(parameter, "success"))
        return; /* same status fires on a passing handshake too */
    if (!s_observed_certs || !s_observed_certs->finalized)
        return;

    _NMLOG(LOGL_INFO,
           "reverify: wpa_supplicant rejected pinned cert for SSID=%s (%s) — re-prompting",
           s_ssid,
           parameter ?: "");
    tofu_stage3();
}

/*****************************************************************************/
/* Stage 2: cert collection from wpa_supplicant Certification signal           */

/*
 * nm_tofu_stage2_cert_signal:
 * @parameters: GVariant from the wpa_supplicant Certification signal.
 *              Expected format: (@a{sv}) with keys:
 *              "depth" (u), "subject" (s), "cert_hash" (s), "cert" (ay).
 *
 * Accumulates server certificates from the ongoing TLS handshake.
 * Dispatches to Stage 3 when the leaf cert (depth==0) is received.
 * Connected to the supplicant-interface signal handler in commit 8.
 */
void
nm_tofu_stage2_cert_signal(GVariant *parameters)
{
    gs_unref_variant GVariant *dict      = NULL;
    GVariantIter              *iter      = NULL;
    const char                *key;
    GVariant                  *value;
    const char                *subject   = NULL;
    const char                *hash      = NULL;
    guint                      depth     = G_MAXUINT;
    GBytes                    *cert_data = NULL;
    NMTOFUCertInfo            *info;
    guint                      i;

    if (s_session_type == NM_TOFU_SESSION_TYPE_DEFAULT) {
        _NMLOG(LOGL_DEBUG, "stage2: no active TOFU session — ignoring Certification signal");
        return;
    }

    g_return_if_fail(parameters != NULL);

    g_variant_get(parameters, "(@a{sv})", &dict);
    g_variant_get(dict, "a{sv}", &iter);

    while (g_variant_iter_next(iter, "{sv}", &key, &value)) {
        if (nm_streq(key, "depth"))
            depth = g_variant_get_uint32(value);
        else if (nm_streq(key, "subject"))
            subject = g_variant_get_string(value, NULL);
        else if (nm_streq(key, "cert_hash"))
            hash = g_variant_get_string(value, NULL);
        else if (nm_streq(key, "cert"))
            cert_data = g_bytes_ref(g_variant_get_data_as_bytes(value));
        g_variant_unref(value);
    }
    g_variant_iter_free(iter);

    if (depth == G_MAXUINT || !subject || !hash || !cert_data) {
        _NMLOG(LOGL_WARN, "stage2: incomplete Certification signal — ignoring");
        nm_clear_pointer(&cert_data, g_bytes_unref);
        return;
    }

    if (!s_observed_certs)
        s_observed_certs = cert_session_new();

    /* Deduplicate by (depth, hash). */
    for (i = 0; i < s_observed_certs->certs->len; i++) {
        NMTOFUCertInfo *existing = g_ptr_array_index(s_observed_certs->certs, i);

        if (existing->depth == depth && nm_streq0(existing->hash, hash)) {
            _NMLOG(LOGL_DEBUG,
                   "stage2: duplicate cert depth=%u hash=%.16s... — skipping",
                   depth,
                   hash);
            g_bytes_unref(cert_data);
            return;
        }
    }

    info            = g_new0(NMTOFUCertInfo, 1);
    info->depth     = depth;
    info->subject   = g_strdup(subject);
    info->hash      = g_strdup(hash);
    info->cert_data = cert_data;
    g_ptr_array_add(s_observed_certs->certs, info);

    _NMLOG(LOGL_INFO,
           "stage2: collected cert depth=%u subject=%s hash=%.16s...",
           depth,
           subject,
           hash);

    if (depth != 0 || s_observed_certs->finalized)
        return;

    /* Leaf cert arrived — trigger dispatch based on session type. */
    s_observed_certs->finalized = TRUE;
    _NMLOG(LOGL_INFO,
           "stage2: leaf cert received, session_type=%d SSID=%s",
           (int) s_session_type,
           s_ssid);

    switch (s_session_type) {
    case NM_TOFU_SESSION_TYPE_TOFU:
        tofu_stage3();
        break;

    case NM_TOFU_SESSION_TYPE_REVERIFY:
        /* Already pinned — just keep what was collected. Real dispatch (if
         * any) happens from nm_tofu_stage2_eap_failure() instead, once
         * wpa_supplicant's own verdict on this cert is known. */
        break;

    default:
        _NMLOG(LOGL_WARN, "stage2: unexpected session type %d", (int) s_session_type);
        break;
    }
}
