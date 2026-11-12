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
    gboolean           via_system_trust;
};

G_DEFINE_TYPE(NMToFuSession, nm_tofu_session, G_TYPE_OBJECT)

enum { STAGE3_READY, LAST_SIGNAL };
static guint signals[LAST_SIGNAL] = {0};

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
    object_class->dispose      = nm_tofu_session_dispose;

    signals[STAGE3_READY] = g_signal_new("stage3-ready",
                                         G_TYPE_FROM_CLASS(klass),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL,
                                         NULL,
                                         NULL,
                                         G_TYPE_NONE,
                                         0);
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

gboolean
nm_tofu_session_get_via_system_trust(NMToFuSession *self)
{
    g_return_val_if_fail(NM_IS_TOFU_SESSION(self), FALSE);
    return self->via_system_trust;
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

static GBytes *
tofu_resolve_self_signed_root(NMTOFUCertSession *observed_session, gboolean *out_via_system_trust)
{
    NMTOFUCertInfo *top = NULL;
    guint           i;

    if (out_via_system_trust)
        *out_via_system_trust = FALSE;

    g_return_val_if_fail(observed_session && observed_session->certs, NULL);

    for (i = 0; i < observed_session->certs->len; i++) {
        NMTOFUCertInfo   *info = g_ptr_array_index(observed_session->certs, i);
        gnutls_x509_crt_t crt;
        gnutls_datum_t    datum;
        gboolean          self_signed = FALSE;

        if (!info || info->depth == 0 || !info->cert_data)
            continue;

        datum.data = (unsigned char *) g_bytes_get_data(info->cert_data, NULL);
        datum.size = (unsigned int) g_bytes_get_size(info->cert_data);

        gnutls_x509_crt_init(&crt);
        if (gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
            self_signed = gnutls_x509_crt_check_issuer(crt, crt) != 0;

            if (self_signed) {
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
                                    (match_der.size == datum.size
                                     && memcmp(match_der.data, datum.data, datum.size) == 0);
                                gnutls_free(match_der.data);
                            }
                            gnutls_x509_crt_deinit(match);
                        }
                    }
                    gnutls_x509_trust_list_deinit(sys_trust, 0);
                }
                gnutls_x509_crt_deinit(crt);
                return g_bytes_ref(info->cert_data);
            }
        }
        gnutls_x509_crt_deinit(crt);

        if (!top || info->depth > top->depth)
            top = info;
    }

    if (!top)
        return NULL;

    /* Fallback: walk up from the highest-depth observed cert via the system trust store[cite: 1] */
    {
        gnutls_x509_crt_t        top_crt;
        gnutls_datum_t           top_datum;
        gnutls_x509_trust_list_t trust_list = NULL;
        GBytes                  *result     = NULL;

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
                    if (gnutls_x509_trust_list_get_issuer(trust_list,
                                                          current,
                                                          &issuer,
                                                          GNUTLS_TL_GET_COPY)
                            != GNUTLS_E_SUCCESS
                        || !issuer)
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

        if (result && out_via_system_trust)
            *out_via_system_trust = TRUE;

        return result;
    }
}

void
nm_tofu_session_get_pin_data(NMToFuSession *self,
                             GBytes       **out_root_der,
                             const char   **out_leaf_hash,
                             const char   **out_domain)
{
    NMTOFUCertInfo *leaf = NULL;
    guint           i;

    *out_root_der  = self->resolved_root;
    *out_leaf_hash = NULL;
    *out_domain    = NULL;

    if (self->observed_certs) {
        for (i = 0; i < self->observed_certs->certs->len; i++) {
            NMTOFUCertInfo *info = g_ptr_array_index(self->observed_certs->certs, i);
            if (info && info->depth == 0) {
                leaf = info;
                break;
            }
        }
    }

    if (leaf) {
        *out_leaf_hash = leaf->hash;
        if (leaf->cert_data) {
            gs_unref_ptrarray GPtrArray *san_names = nm_tofu_extract_san_dnsnames(leaf->cert_data);
            if (san_names && san_names->len > 0)
                *out_domain =
                    g_strdup(g_ptr_array_index(san_names, 0)); /* Note: caller must free domain */
        }
    }
}

gboolean
nm_tofu_session_get_display_fields(NMToFuSession *self,
                                   char         **out_cn,
                                   char         **out_issuer,
                                   char         **out_org,
                                   char         **out_sha256,
                                   char         **out_exp,
                                   char         **out_url)
{
    NMTOFUCertInfo   *leaf_cert = NULL;
    GBytes           *cert_data;
    gnutls_x509_crt_t crt;
    gnutls_datum_t    datum;
    char              buf[256];
    size_t            len;
    guint             i;

    g_return_val_if_fail(NM_IS_TOFU_SESSION(self), FALSE);

    if (!self->observed_certs)
        return FALSE;

    /* Find the leaf certificate (depth 0) */
    for (i = 0; i < self->observed_certs->certs->len; i++) {
        NMTOFUCertInfo *info = g_ptr_array_index(self->observed_certs->certs, i);
        if (info && info->depth == 0) {
            leaf_cert = info;
            break;
        }
    }

    cert_data =
        self->resolved_root ? self->resolved_root : (leaf_cert ? leaf_cert->cert_data : NULL);
    if (!cert_data)
        return FALSE;

    datum.data = (unsigned char *) g_bytes_get_data(cert_data, NULL);
    datum.size = g_bytes_get_size(cert_data);

    if (gnutls_x509_crt_init(&crt) < 0
        || gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_DER) < 0) {
        return FALSE;
    }

    if (out_cn) {
        len = sizeof(buf);
        if (gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &len) >= 0)
            *out_cn = g_strdup(buf);
        else
            *out_cn = g_strdup("N/A");
    }

    if (out_issuer) {
        len = sizeof(buf);
        if (gnutls_x509_crt_get_issuer_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &len)
            >= 0)
            *out_issuer = g_strdup(buf);
        else
            *out_issuer = g_strdup("N/A");
    }

    if (out_org) {
        len = sizeof(buf);
        if (gnutls_x509_crt_get_dn_by_oid(crt, GNUTLS_OID_X520_ORGANIZATION_NAME, 0, 0, buf, &len)
            >= 0)
            *out_org = g_strdup(buf);
        else
            *out_org = g_strdup("N/A");
    }

    if (out_sha256) {
        unsigned char raw[32];
        char          hex[65] = {0};
        len                   = sizeof(raw);
        gnutls_x509_crt_get_fingerprint(crt, GNUTLS_DIG_SHA256, raw, &len);
        for (i = 0; i < len; i++)
            sprintf(&hex[i * 2], "%02X", raw[i]);
        *out_sha256 = g_strdup(hex);
    }

    if (out_exp) {
        time_t     exp_time = gnutls_x509_crt_get_expiration_time(crt);
        struct tm *tm_info  = localtime(&exp_time);
        if (tm_info) {
            strftime(buf, sizeof(buf), "%c", tm_info);
            *out_exp = g_strdup(buf);
        } else {
            *out_exp = g_strdup("N/A");
        }
    }

    if (out_url) {
        gs_unref_ptrarray GPtrArray *san = nm_tofu_extract_san_dnsnames(cert_data);
        *out_url = (san && san->len > 0) ? g_strdup(g_ptr_array_index(san, 0)) : g_strdup("N/A");
    }

    gnutls_x509_crt_deinit(crt);
    return TRUE;
}

GPtrArray *
nm_tofu_extract_san_dnsnames(GBytes *cert_data)
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

char *
nm_tofu_session_write_root_pem(NMToFuSession *self, GBytes *root_der, GError **error)
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
/* Complete Stage 2 Parsing */
void
nm_tofu_stage2_cert_signal(NMToFuSession *self, GVariant *parameters)
{
    gs_unref_variant GVariant *dict = NULL;
    GVariantIter              *iter = NULL;
    const char                *key;
    GVariant                  *value;
    const char                *subject   = NULL;
    const char                *hash      = NULL;
    guint                      depth     = G_MAXUINT;
    GBytes                    *cert_data = NULL;
    NMTOFUCertInfo            *info;
    guint                      i;

    g_return_if_fail(NM_IS_TOFU_SESSION(self));
    g_return_if_fail(parameters);

    if (self->session_type == NM_TOFU_SESSION_TYPE_DEFAULT)
        return;

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
        nm_clear_pointer(&cert_data, g_bytes_unref);
        return;
    }

    if (!self->observed_certs)
        self->observed_certs = cert_session_new();

    /* Deduplicate by (depth, hash) */
    for (i = 0; i < self->observed_certs->certs->len; i++) {
        NMTOFUCertInfo *existing = g_ptr_array_index(self->observed_certs->certs, i);
        if (existing->depth == depth && nm_streq0(existing->hash, hash)) {
            g_bytes_unref(cert_data);
            return;
        }
    }

    info            = g_new0(NMTOFUCertInfo, 1);
    info->depth     = depth;
    info->subject   = g_strdup(subject);
    info->hash      = g_strdup(hash);
    info->cert_data = cert_data;
    g_ptr_array_add(self->observed_certs->certs, info);

    if (depth == 0 && !self->observed_certs->finalized) {
        self->observed_certs->finalized = TRUE;

        nm_clear_pointer(&self->resolved_root, g_bytes_unref);
        /* Pass the pointer instead of NULL */
        self->resolved_root =
            tofu_resolve_self_signed_root(self->observed_certs, &self->via_system_trust);

        g_signal_emit(self, signals[STAGE3_READY], 0);
    }
}