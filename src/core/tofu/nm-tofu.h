/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#ifndef NM_TOFU_H
#define NM_TOFU_H

#include <glib-object.h>
#include "libnm-core-aux-intern/nm-auth-subject.h"

#define NM_TYPE_TOFU_SESSION (nm_tofu_session_get_type())
G_DECLARE_FINAL_TYPE(NMToFuSession, nm_tofu_session, NM, TOFU_SESSION, GObject)

/*****************************************************************************/

/*
 * NMTOFUSessionType:
 *
 * Describes why NM is intercepting the wpa_supplicant Certification signal
 * for the current connection attempt.
 *
 * DEFAULT - No interception; let wpa_supplicant handle certificate verification
 *           normally.
 * TOFU    - First-use path: collect server certificate, ask the user to
 *           accept/reject, and pin on accept.
 */
typedef enum {
    NM_TOFU_SESSION_TYPE_DEFAULT = 0,
    NM_TOFU_SESSION_TYPE_TOFU    = 1,
} NMTOFUSessionType;

/*
 * NMTOFUCertInfo: One certificate from the TLS chain sent by wpa_supplicant.
 * depth == 0 is the server (leaf) certificate.
 */
typedef struct {
    guint   depth;
    char   *subject;
    char   *hash;      /* hex SHA-256 as reported by wpa_supplicant */
    GBytes *cert_data; /* raw DER bytes */
} NMTOFUCertInfo;

/*
 * NMTOFUCertSession: Accumulates certificates for one TLS handshake.
 * finalized is set TRUE once the leaf (depth == 0) certificate arrives.
 */
typedef struct {
    GPtrArray *certs; /* element type: NMTOFUCertInfo * */
    gboolean   finalized;
} NMTOFUCertSession;

/*****************************************************************************/
/* Session Management                                                         */

NMToFuSession *nm_tofu_session_get(void);

void nm_tofu_session_set(NMToFuSession    *self,
                         NMTOFUSessionType type,
                         const char       *ssid,
                         const char       *uuid,
                         NMAuthSubject    *subject);

NMTOFUSessionType nm_tofu_session_get_session_type(NMToFuSession *self);
const char       *nm_tofu_session_get_ssid(NMToFuSession *self);
const char       *nm_tofu_session_get_uuid(NMToFuSession *self);
void              nm_tofu_session_reset(NMToFuSession *self);

/*****************************************************************************/
/* Stage 2: Cert Collection from wpa_supplicant Certification Signal          */

void nm_tofu_stage2_cert_signal(NMToFuSession *self, GVariant *parameters);

#endif /* NM_TOFU_H */