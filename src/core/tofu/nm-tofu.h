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
 * REVERIFY - ca-verify-mode == tofu, cert already pinned by a previous
 *            TOFU accept. Real credentials used, wpa_supplicant validates
 *            against the existing pin exactly as it would with any
 *            configured CA. NM only watches: collects certs via the
 *            Certification signal (nm_tofu_stage2_cert_signal(), silent,
 *            no dispatch on leaf arrival unlike TOFU) and re-prompts only
 *            if wpa_supplicant's own verification fails
 *            (nm_tofu_stage2_eap_failure()) — reuses the same
 *            accept/reject dispatch as TOFU, except a reject here never
 *            deletes the profile: it just discards this attempt and
 *            leaves the existing pin in place.
 */
typedef enum {
    NM_TOFU_SESSION_TYPE_DEFAULT  = 0,
    NM_TOFU_SESSION_TYPE_TOFU     = 1,
    NM_TOFU_SESSION_TYPE_REVERIFY = 2,
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
                                      const char       *uuid,
                                      NMAuthSubject    *subject);
NMTOFUSessionType nm_tofu_get_session_type(void);
const char       *nm_tofu_get_ssid(void);
const char       *nm_tofu_get_uuid(void);
void              nm_tofu_reset_session(void);

/*****************************************************************************/
/* Stage 2: cert collection from wpa_supplicant Certification signal          */

void nm_tofu_stage2_cert_signal(GVariant *parameters);

/*
 * nm_tofu_stage2_eap_failure:
 * @status: the wpa_supplicant EAP signal's status string, verbatim.
 * @parameter: the EAP signal's parameter string, verbatim — "success" for
 *             this status on a passing handshake, an error reason
 *             otherwise ("Server certificate mismatch", "self-signed
 *             certificate in certificate chain", ...).
 *
 * Only acts during a REVERIFY session, and only when status is
 * "remote certificate verification" AND parameter is not "success" — any
 * other EAP outcome (passing handshake, wrong password, timeout, etc.) is
 * left alone, same as it would be without TOFU at all.
 */
void nm_tofu_stage2_eap_failure(const char *status, const char *parameter);

#endif /* NM_TOFU_H */
