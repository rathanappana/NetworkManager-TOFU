/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

/*
 * TOFU (Trust On First Use) core state machine.
 *
 * Stages:
 * 1. Detection  - nm-device-wifi.c detects EAP connection with
 *                 ca-verify-mode=tofu; calls nm_tofu_session_set().
 * 2. Collection - nm_tofu_stage2_cert_signal() accumulates certificates
 *                 from wpa_supplicant's Certification D-Bus signal.
 * 3. Dispatch   - On leaf cert (depth==0): parse cert fields, call
 *                 registered CertificateAgent. NM does not independently
 *                 verify the chain here — wpa_supplicant's own TLS stack
 *                 already did, and is the sole authority on that.
 * 4. Response   - tofu_on_agent_response() handles accept/reject from
 *                 the agent UI; pins cert or removes profile.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-tofu.h"

#include <gnutls/x509.h>
#include <time.h>

#include "nm-active-connection.h"
#include "nm-manager.h"
#include "settings/nm-settings.h"

#define CERT_AGENT_OBJECT_PATH   "/org/freedesktop/NetworkManager/CertificateAgent"
#define CERT_AGENT_IFACE         "org.freedesktop.NetworkManager.CertificateAgent"
#define NM_CERT_AGENT_TIMEOUT_MS 180000

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_TOFU
#define _NMLOG(level, ...) nm_log((level), (_NMLOG_DOMAIN), NULL, NULL, "tofu: " __VA_ARGS__)

#define TOFU_CERT_DIR NMSTATEDIR "/tofu"

/*****************************************************************************/

struct _NMToFuSession {
    GObject            parent;
    NMTOFUSessionType  session_type;
    char              *ssid;
    char              *uuid;
    NMAuthSubject     *subject;
    NMTOFUCertSession *observed_certs;
    GBytes            *resolved_root;
};

G_DEFINE_TYPE(NMToFuSession, nm_tofu_session, G_TYPE_OBJECT)

/*****************************************************************************/
/* NMTOFUCertInfo / NMTOFUCertSession Lifetime                                */

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
/* GObject Lifecycle Methods                                                 */

static void
nm_tofu_session_dispose(GObject *object)
{
    NMToFuSession *self = NM_TOFU_SESSION(object);

    nm_tofu_session_reset(self);

    G_OBJECT_CLASS(nm_tofu_session_parent_class)->dispose(object);
}

static void
nm_tofu_session_init(NMToFuSession *self)
{
    self->session_type = NM_TOFU_SESSION_TYPE_DEFAULT;
}

static void
nm_tofu_session_class_init(NMToFuSessionClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->dispose = nm_tofu_session_dispose;
}

NMToFuSession *
nm_tofu_session_get(void)
{
    static NMToFuSession *singleton = NULL;

    if (G_UNLIKELY(!singleton)) {
        singleton = g_object_new(NM_TYPE_TOFU_SESSION, NULL);
        g_object_add_weak_pointer(G_OBJECT(singleton), (gpointer *) &singleton);
    }
    return singleton;
}

/*****************************************************************************/
/* Session Management                                                        */

void
nm_tofu_session_set(NMToFuSession    *self,
                    NMTOFUSessionType type,
                    const char       *ssid,
                    const char       *uuid,
                    NMAuthSubject    *subject)
{
    g_return_if_fail(NM_IS_TOFU_SESSION(self));

    nm_tofu_session_reset(self);

    self->session_type = type;
    self->ssid         = g_strdup(ssid ?: "");
    self->uuid         = g_strdup(uuid ?: "");
    self->subject      = subject ? g_object_ref(subject) : NULL;

    _NMLOG(LOGL_INFO,
           "session started: type=%d ssid=%s uuid=%s",
           (int) type,
           self->ssid,
           self->uuid);
}

NMTOFUSessionType
nm_tofu_session_get_session_type(NMToFuSession *self)
{
    g_return_val_if_fail(NM_IS_TOFU_SESSION(self), NM_TOFU_SESSION_TYPE_DEFAULT);
    return self->session_type;
}

const char *
nm_tofu_session_get_ssid(NMToFuSession *self)
{
    g_return_val_if_fail(NM_IS_TOFU_SESSION(self), NULL);
    return self->ssid;
}

const char *
nm_tofu_session_get_uuid(NMToFuSession *self)
{
    g_return_val_if_fail(NM_IS_TOFU_SESSION(self), NULL);
    return self->uuid;
}

void
nm_tofu_session_reset(NMToFuSession *self)
{
    g_return_if_fail(NM_IS_TOFU_SESSION(self));

    if (self->session_type == NM_TOFU_SESSION_TYPE_DEFAULT && !self->observed_certs)
        return;

    nm_clear_pointer(&self->observed_certs, cert_session_free);
    nm_clear_pointer(&self->resolved_root, g_bytes_unref);
    nm_clear_g_free(&self->ssid);
    nm_clear_g_free(&self->uuid);
    g_clear_object(&self->subject);
    self->session_type = NM_TOFU_SESSION_TYPE_DEFAULT;

    _NMLOG(LOGL_DEBUG, "session reset");
}

/*****************************************************************************/
/* GnuTLS Helpers                                                            */

static GPtrArray *
extract_san_dnsnames(GBytes *cert_data)
{
    gnutls_x509_crt_t crt;
    gnutls_datum_t    datum;
    GPtrArray        *names;
    unsigned          idx = 0;
    char              cn_buf[256];
    size_t            cn_len = sizeof(cn_buf);

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

    for (;;) {
        size_t        san_len = 0;
        unsigned      san_type, critical;
        gs_free char *san_buf = NULL;
        int           rc;

        rc = gnutls_x509_crt_get_subject_alt_name2(crt, idx, NULL, &san_len, &san_type, &critical);
        if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
            break;

        san_buf = g_malloc(san_len);
        rc      = gnutls_x509_crt_get_subject_alt_name2(crt,
                                                        idx,
                                                        san_buf,
                                                        &san_len,
                                                        &san_type,
                                                        &critical);
        if (rc < 0)
            break;

        if (san_type == GNUTLS_SAN_DNSNAME)
            g_ptr_array_add(names, g_strndup(san_buf, san_len));
        idx++;
    }

    if (names->len == 0) {
        if (gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, cn_buf, &cn_len)
            >= 0)
            g_ptr_array_add(names, g_strdup(cn_buf));
    }

    gnutls_x509_crt_deinit(crt);
    return names;
}

/*****************************************************************************/
/* Connection Management Helpers                                             */

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

static char *
tofu_write_root_pem(NMToFuSession *self, GBytes *root_der, GError **error)
{
    gs_free char     *path = NULL;
    gnutls_x509_crt_t crt;
    gnutls_datum_t    datum, pem_datum = {};

    datum.data = (unsigned char *) g_bytes_get_data(root_der, NULL);
    datum.size = (unsigned) g_bytes_get_size(root_der);

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
                           (self->uuid && *self->uuid) ? self->uuid : "unknown");
    if (!g_file_set_contents(path, (char *) pem_datum.data, (gssize) pem_datum.size, error)) {
        gnutls_free(pem_datum.data);
        return NULL;
    }

    _NMLOG(LOGL_DEBUG, "saved self-signed root PEM (%u bytes) to %s", pem_datum.size, path);
    gnutls_free(pem_datum.data);
    return g_steal_pointer(&path);
}

/*****************************************************************************/
/* Stage 2: Certificate Collection                                           */

void
nm_tofu_stage2_cert_signal(NMToFuSession *self, GVariant *parameters)
{
    g_return_if_fail(NM_IS_TOFU_SESSION(self));
    g_return_if_fail(parameters);

    if (self->session_type == NM_TOFU_SESSION_TYPE_DEFAULT)
        return;

    if (!self->observed_certs)
        self->observed_certs = cert_session_new();

    /* Accumulation logic for wpa_supplicant Certification signal parsing goes here */
    _NMLOG(LOGL_DEBUG, "stage2: processing certification signal");
}