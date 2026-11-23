/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#ifndef NM_TOFU_CONNECTION_H
#define NM_TOFU_CONNECTION_H

#include "core/nm-default-daemon.h"
#include "libnm-core-public/nm-connection.h"
#include "libnm-core-public/nm-setting-wireless.h"
#include "supplicant/nm-supplicant-config.h"
#include "tofu/nm-tofu.h"

typedef enum {
    NM_TOFU_CONNECTION_DECISION_ACCEPT_PERSIST,
    NM_TOFU_CONNECTION_DECISION_ACCEPT_TEMPORARY,
    NM_TOFU_CONNECTION_DECISION_REJECT_DELETE,
    NM_TOFU_CONNECTION_DECISION_REJECT_KEEP,
} NMTofuConnectionDecision;

NMTofuConnectionDecision nm_tofu_connection_decide(gboolean accepted, gboolean authorized);

void nm_tofu_connection_setup(NMConnection         *connection,
                              NMSettingsConnection *sett_conn,
                              NMSettingWireless    *s_wireless,
                              NMSupplicantConfig   *config,
                              NMActiveConnection   *req,
                              gboolean             *out_skip_sup_timeout);

gboolean nm_tofu_connection_prepare(NMConnection       *connection,
                                    const char         *uuid,
                                    const char         *ssid,
                                    NMAuthSubject      *subject,
                                    NMSupplicantConfig *config,
                                    gboolean           *out_skip_sup_timeout);

gboolean nm_tofu_connection_set_ca_cert_hash(NMConnection *connection,
                                             const char   *hash_hex,
                                             const char   *domain,
                                             GError      **error);

gboolean nm_tofu_connection_agent_call_request(GDBusConnection    *dbus_conn,
                                               const char         *dest_agent,
                                               NMToFuSession      *session,
                                               GCancellable       *cancellable,
                                               GAsyncReadyCallback callback,
                                               gpointer            user_data);

gboolean nm_tofu_connection_agent_call_finish(GDBusConnection *dbus_conn,
                                              GAsyncResult    *result,
                                              gboolean        *out_accepted,
                                              GError         **error);

#endif /* NM_TOFU_CONNECTION_H */