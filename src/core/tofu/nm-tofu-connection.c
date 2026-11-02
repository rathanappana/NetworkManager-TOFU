/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-tofu-connection.h"
#include "nm-tofu.h"

#include "libnm-core-aux-intern/nm-common-macros.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-active-connection.h"
#include "settings/nm-settings-connection.h"
#include "supplicant/nm-supplicant-config.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN LOGD_TOFU
#define _NMLOG(level, ...) \
    nm_log((level), (_NMLOG_DOMAIN), NULL, NULL, "tofu-connection: " __VA_ARGS__)

/*****************************************************************************/

static gboolean
_has_supported_eap_method(NMSetting8021x *s_8021x)
{
    guint32 n_eap = nm_setting_802_1x_get_num_eap_methods(s_8021x);
    guint32 i;

    for (i = 0; i < n_eap; i++) {
        const char *method = nm_setting_802_1x_get_eap_method(s_8021x, i);

        if (NM_IN_STRSET(method, "tls", "ttls", "peap"))
            return TRUE;
    }

    return FALSE;
}

static gboolean
_is_tofu_eligible(NMSetting8021x *s_8021x)
{
    return s_8021x
           && (nm_setting_802_1x_get_ca_verify_mode(s_8021x)
               == NM_SETTING_802_1X_CA_VERIFY_MODE_TOFU)
           && (nm_setting_802_1x_get_ca_cert_scheme(s_8021x) == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
           && _has_supported_eap_method(s_8021x);
}

void
nm_tofu_connection_setup(NMConnection         *connection,
                         NMSettingsConnection *sett_conn,
                         NMSettingWireless    *s_wireless,
                         NMSupplicantConfig   *config,
                         NMActiveConnection   *req,
                         gboolean             *out_skip_sup_timeout)
{
    NMSetting8021x *s_8021x;
    const char     *uuid;
    gs_free char   *ssid_str = NULL;
    GBytes         *ssid_bytes;

    g_return_if_fail(NM_IS_CONNECTION(connection));
    g_return_if_fail(NM_IS_SETTINGS_CONNECTION(sett_conn));
    g_return_if_fail(NM_IS_SETTING_WIRELESS(s_wireless));
    g_return_if_fail(NM_IS_SUPPLICANT_CONFIG(config));
    g_return_if_fail(NM_IS_ACTIVE_CONNECTION(req));
    g_return_if_fail(out_skip_sup_timeout);

    s_8021x = nm_connection_get_setting_802_1x(connection);

    if (!_is_tofu_eligible(s_8021x))
        return;

    uuid       = nm_settings_connection_get_uuid(sett_conn);
    ssid_bytes = nm_setting_wireless_get_ssid(s_wireless);
    ssid_str   = ssid_bytes ? _nm_utils_ssid_to_utf8(ssid_bytes) : NULL;

    nm_tofu_session_set(nm_tofu_session_get(),
                        NM_TOFU_SESSION_TYPE_TOFU,
                        ssid_str,
                        uuid,
                        nm_active_connection_get_subject(req));
    nm_supplicant_config_suppress_credentials_for_tofu(config);

    /* Credentials are withheld until the user accepts the certificate,
     * so EAP is expected to stall past the generic association timeout
     * while waiting for wpa_supplicant's Certification signal.
     */
    *out_skip_sup_timeout = TRUE;
}