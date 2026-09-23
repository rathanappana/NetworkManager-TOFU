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
 *            normally (ca-verify-mode == default, or not an EAP-TLS method).
 * TOFU     - ca-verify-mode == tofu; first-use path: collect server cert,
 *            ask the user to accept/reject, pin on accept. NM does not
 *            independently re-verify the chain — wpa_supplicant's own TLS
 *            stack is the sole authority on whether it's valid.
 *
 * This is the only session type wired up for now. A CONFIGURED_CA-style
 * independent re-verification path, and a USER_TRUSTED_NO_CA path that
 * silently re-enters TOFU on a changed pinned hash, existed previously but
 * were removed: both required NM to redo certificate chain validation
 * itself via GnuTLS, duplicating what wpa_supplicant already does
 * correctly. A replacement design for re-issuing the accept/reject prompt
 * when a previously-pinned identity changes belongs here later, built
 * around wpa_supplicant's own verdict instead.
 */
typedef enum {
    NM_TOFU_SESSION_TYPE_DEFAULT = 0,
    NM_TOFU_SESSION_TYPE_TOFU    = 1,
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
gboolean nm_tofu_has_pinned_leaf_hash(const char *uuid);
gboolean nm_tofu_is_cert_hash_trusted(const char *uuid,
                                       const char *observed_hash);
void     nm_tofu_remove_server_cert_from_trusted(const char *uuid);
char    *nm_tofu_get_stored_cert_hash(const char *uuid);

#endif /* NM_TOFU_H */
