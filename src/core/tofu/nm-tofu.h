/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#ifndef NM_TOFU_H
#define NM_TOFU_H

#include <glib.h>

/*****************************************************************************/

/*
 * NMTOFUSessionType:
 *
 * Describes why NM is intercepting the wpa_supplicant Certification signal
 * for the current connection attempt.
 *
 * DEFAULT  - no interception; let wpa_supplicant handle cert verification
 *            normally (ca-verify-mode == default or CA cert configured).
 * TOFU     - no CA cert configured; first-use path: collect server cert,
 *            ask the user to accept/reject, pin on accept.
 * CONFIGURED_CA - CA cert present in connection profile; verify observed
 *            server cert against it and notify agent on mismatch.
 * USER_TRUSTED_NO_CA - no CA cert configured but the connection has a
 *            previously pinned cert hash; verify hash and re-TOFU if changed.
 */
typedef enum {
    NM_TOFU_SESSION_TYPE_DEFAULT          = 0,
    NM_TOFU_SESSION_TYPE_TOFU             = 1,
    NM_TOFU_SESSION_TYPE_CONFIGURED_CA    = 2,
    NM_TOFU_SESSION_TYPE_USER_TRUSTED_NO_CA = 3,
} NMTOFUSessionType;

/*
 * NMTOFUCertInfo: one certificate from the TLS chain sent by wpa_supplicant.
 * depth==0 is the server (leaf) certificate.
 */
typedef struct {
    guint   depth;
    char   *subject;
    char   *hash;    /* hex SHA-256 as reported by wpa_supplicant */
    GBytes *cert_data; /* raw DER bytes */
} NMTOFUCertInfo;

/*
 * NMTOFUCertSession: accumulates certs for one TLS handshake.
 * finalized is set TRUE once the leaf (depth==0) cert has arrived.
 */
typedef struct {
    GPtrArray *certs;     /* element type: NMTOFUCertInfo* */
    gboolean   finalized;
} NMTOFUCertSession;

/*****************************************************************************/
/* Session management                                                         */

void              nm_tofu_set_session(NMTOFUSessionType type,
                                      const char       *ssid,
                                      const char       *uuid);
NMTOFUSessionType nm_tofu_get_session_type(void);
const char       *nm_tofu_get_ssid(void);
const char       *nm_tofu_get_uuid(void);
void              nm_tofu_reset_session(void);

/*****************************************************************************/
/* Stage 2: cert collection from wpa_supplicant Certification signal          */

void nm_tofu_stage2_cert_signal(GVariant *parameters);

/*****************************************************************************/
/* Trusted cert keyfile store                                                 */

gboolean nm_tofu_mark_server_cert_as_trusted(const char *uuid,
                                              const char *cert_hash);
gboolean nm_tofu_is_uuid_trusted(const char *uuid);
gboolean nm_tofu_is_cert_hash_trusted(const char *uuid,
                                       const char *observed_hash);
void     nm_tofu_remove_server_cert_from_trusted(const char *uuid);
char    *nm_tofu_get_stored_cert_hash(const char *uuid);

/*****************************************************************************/
/* CA cert from connection profile (CONFIGURED_CA path)                       */

void nm_tofu_save_config_ca_cert_data(GBytes *cert_data);

#endif /* NM_TOFU_H */
