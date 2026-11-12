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

void nm_tofu_connection_setup(NMConnection         *connection,
                              NMSettingsConnection *sett_conn,
                              NMSettingWireless    *s_wireless,
                              NMSupplicantConfig   *config,
                              NMActiveConnection   *req,
                              gboolean             *out_skip_sup_timeout);

#endif /* NM_TOFU_CONNECTION_H */