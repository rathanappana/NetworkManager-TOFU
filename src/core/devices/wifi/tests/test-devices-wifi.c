/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "devices/wifi/nm-wifi-utils.h"
#include "devices/wifi/nm-wifi-ap.h"
#include "devices/wifi/nm-device-wifi.h"
#include "devices/wifi/nm-wifi-tofu.h"
#include "libnm-crypto/nm-crypto.h"
#include "libnm-core-intern/nm-core-internal.h"

#include "nm-test-utils-core.h"

#define DEBUG 1

/*****************************************************************************/

#define COMPARE(src, expected, success, error, edomain, ecode)                             \
    {                                                                                      \
        if (expected) {                                                                    \
            if (!success) {                                                                \
                g_assert(error != NULL);                                                   \
                g_warning("Failed to complete connection: %s", error->message);            \
            }                                                                              \
            g_assert(success == TRUE);                                                     \
            g_assert(error == NULL);                                                       \
                                                                                           \
            success = nm_connection_compare(src, expected, NM_SETTING_COMPARE_FLAG_EXACT); \
            if (success == FALSE && DEBUG) {                                               \
                g_print("\n- COMPLETED ---------------------------------\n");              \
                nm_connection_dump(src);                                                   \
                g_print("+ EXPECTED ++++++++++++++++++++++++++++++++++++\n");              \
                nm_connection_dump(expected);                                              \
                g_print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");              \
            }                                                                              \
            g_assert(success == TRUE);                                                     \
        } else {                                                                           \
            if (success) {                                                                 \
                g_print("\n- COMPLETED ---------------------------------\n");              \
                nm_connection_dump(src);                                                   \
            }                                                                              \
            g_assert(success == FALSE);                                                    \
            g_assert_error(error, edomain, ecode);                                         \
        }                                                                                  \
                                                                                           \
        g_clear_error(&error);                                                             \
    }

static gboolean
complete_connection(const char   *ssid,
                    const char   *bssid,
                    _NM80211Mode  mode,
                    guint32       flags,
                    guint32       wpa_flags,
                    guint32       rsn_flags,
                    gboolean      lock_bssid,
                    NMConnection *src,
                    GError      **error)
{
    gs_unref_bytes GBytes *ssid_b = NULL;
    NMSettingWireless     *s_wifi;

    /* Add a wifi setting if one doesn't exist */
    s_wifi = nm_connection_get_setting_wireless(src);
    if (!s_wifi) {
        s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
        nm_connection_add_setting(src, NM_SETTING(s_wifi));
    }

    ssid_b = g_bytes_new(ssid, strlen(ssid));

    return nm_wifi_utils_complete_connection(ssid_b,
                                             bssid,
                                             mode,
                                             0,
                                             flags,
                                             wpa_flags,
                                             rsn_flags,
                                             src,
                                             lock_bssid,
                                             error);
}

typedef struct {
    const char *key;
    const char *str;
    guint32     uint;
} KeyData;

static void
set_items(NMSetting *setting, const KeyData *items)
{
    const KeyData *item;
    GParamSpec    *pspec;
    GBytes        *tmp;

    for (item = items; item && item->key; item++) {
        g_assert(item->key);
        pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(setting), item->key);
        g_assert(pspec);

        if (pspec->value_type == G_TYPE_STRING) {
            g_assert(item->uint == 0);
            if (item->str)
                g_object_set(G_OBJECT(setting), item->key, item->str, NULL);
        } else if (pspec->value_type == G_TYPE_UINT) {
            g_assert(item->str == NULL);
            g_object_set(G_OBJECT(setting), item->key, item->uint, NULL);
        } else if (pspec->value_type == G_TYPE_INT) {
            int foo = (int) item->uint;

            g_assert(item->str == NULL);
            g_object_set(G_OBJECT(setting), item->key, foo, NULL);
        } else if (pspec->value_type == G_TYPE_BOOLEAN) {
            gboolean foo = !!(item->uint);

            g_assert(item->str == NULL);
            g_object_set(G_OBJECT(setting), item->key, foo, NULL);
        } else if (pspec->value_type == G_TYPE_BYTES) {
            g_assert(item->str);
            tmp = g_bytes_new(item->str, strlen(item->str));
            g_object_set(G_OBJECT(setting), item->key, tmp, NULL);
            g_bytes_unref(tmp);
        } else {
            /* Special types, check based on property name */
            if (!strcmp(item->key, NM_SETTING_WIRELESS_SECURITY_PROTO))
                nm_setting_wireless_security_add_proto(NM_SETTING_WIRELESS_SECURITY(setting),
                                                       item->str);
            else if (!strcmp(item->key, NM_SETTING_WIRELESS_SECURITY_PAIRWISE))
                nm_setting_wireless_security_add_pairwise(NM_SETTING_WIRELESS_SECURITY(setting),
                                                          item->str);
            else if (!strcmp(item->key, NM_SETTING_WIRELESS_SECURITY_GROUP))
                nm_setting_wireless_security_add_group(NM_SETTING_WIRELESS_SECURITY(setting),
                                                       item->str);
            else if (!strcmp(item->key, NM_SETTING_802_1X_EAP))
                nm_setting_802_1x_add_eap_method(NM_SETTING_802_1X(setting), item->str);
        }
    }
}

static NMSettingWireless *
fill_wifi_empty(NMConnection *connection)
{
    NMSettingWireless *s_wifi;

    s_wifi = nm_connection_get_setting_wireless(connection);
    if (!s_wifi) {
        s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
        nm_connection_add_setting(connection, NM_SETTING(s_wifi));
    }
    return s_wifi;
}

static NMSettingWireless *
fill_wifi(NMConnection *connection, const KeyData items[])
{
    NMSettingWireless *s_wifi;

    s_wifi = nm_connection_get_setting_wireless(connection);
    if (!s_wifi) {
        s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
        nm_connection_add_setting(connection, NM_SETTING(s_wifi));
    }

    set_items(NM_SETTING(s_wifi), items);
    return s_wifi;
}

static NMSettingWirelessSecurity *
fill_wsec(NMConnection *connection, const KeyData items[])
{
    NMSettingWirelessSecurity *s_wsec;

    s_wsec = nm_connection_get_setting_wireless_security(connection);
    if (!s_wsec) {
        s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new();
        nm_connection_add_setting(connection, NM_SETTING(s_wsec));
    }

    set_items(NM_SETTING(s_wsec), items);
    return s_wsec;
}

static NMSetting8021x *
fill_8021x(NMConnection *connection, const KeyData items[])
{
    NMSetting8021x *s_8021x;

    s_8021x = nm_connection_get_setting_802_1x(connection);
    if (!s_8021x) {
        s_8021x = (NMSetting8021x *) nm_setting_802_1x_new();
        nm_connection_add_setting(connection, NM_SETTING(s_8021x));
    }

    set_items(NM_SETTING(s_8021x), items);
    return s_8021x;
}

static NMConnection *
create_basic(const char *ssid, const char *bssid, _NM80211Mode mode)
{
    NMConnection      *connection;
    NMSettingWireless *s_wifi = NULL;
    GBytes            *tmp;

    connection = nm_simple_connection_new();

    s_wifi = (NMSettingWireless *) nm_setting_wireless_new();
    nm_connection_add_setting(connection, NM_SETTING(s_wifi));

    /* SSID */
    tmp = g_bytes_new(ssid, strlen(ssid));
    g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_SSID, tmp, NULL);
    g_bytes_unref(tmp);

    /* BSSID */
    if (bssid)
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_BSSID, bssid, NULL);

    if (mode == _NM_802_11_MODE_INFRA)
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_MODE, "infrastructure", NULL);
    else if (mode == _NM_802_11_MODE_ADHOC)
        g_object_set(G_OBJECT(s_wifi), NM_SETTING_WIRELESS_MODE, "adhoc", NULL);
    else
        g_assert_not_reached();

    return connection;
}

/*****************************************************************************/

static void
test_lock_bssid(void)
{
    NMConnection *src, *expected;
    const char   *bssid = "01:02:03:04:05:06";
    const char   *ssid  = "blahblah";
    gboolean      success;
    GError       *error = NULL;

    src      = nm_simple_connection_new();
    success  = complete_connection(ssid,
                                   bssid,
                                   _NM_802_11_MODE_INFRA,
                                   NM_802_11_AP_FLAGS_NONE,
                                   NM_802_11_AP_SEC_NONE,
                                   NM_802_11_AP_SEC_NONE,
                                   TRUE,
                                   src,
                                   &error);
    expected = create_basic(ssid, bssid, _NM_802_11_MODE_INFRA);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_open_ap_empty_connection(void)
{
    NMConnection *src, *expected;
    const char   *bssid = "01:02:03:04:05:06";
    const char   *ssid  = "blahblah";
    gboolean      success;
    GError       *error = NULL;

    /* Test that an empty source connection is correctly filled with the
     * SSID and Infra modes of the given AP details.
     */

    src      = nm_simple_connection_new();
    success  = complete_connection(ssid,
                                   bssid,
                                   _NM_802_11_MODE_INFRA,
                                   NM_802_11_AP_FLAGS_NONE,
                                   NM_802_11_AP_SEC_NONE,
                                   NM_802_11_AP_SEC_NONE,
                                   FALSE,
                                   src,
                                   &error);
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_open_ap_leap_connection_1(gconstpointer add_wifi)
{
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, "Bill Smith", 0},
                                {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that a basic connection filled with a LEAP username is
     * rejected when completion is attempted with an open AP.  LEAP requires
     * the AP to have the Privacy bit set.
     */

    src = nm_simple_connection_new();
    if (add_wifi)
        fill_wifi_empty(src);
    fill_wsec(src, src_wsec);

    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_open_ap_leap_connection_2(void)
{
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0}, {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that a basic connection specifying IEEE8021x security (ie, Dynamic
     * WEP or LEAP) is rejected when completion is attempted with an open AP.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);

    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_open_ap_wep_connection(gconstpointer add_wifi)
{
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {
        {NM_SETTING_WIRELESS_SECURITY_WEP_KEY0, "11111111111111111111111111", 0},
        {NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, NULL, 0},
        {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
        {NULL}};
    gboolean success;
    GError  *error = NULL;

    /* Test that a static WEP connection is rejected when completion is
     * attempted with an open AP.
     */

    src = nm_simple_connection_new();
    if (add_wifi)
        fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_ap_wpa_psk_connection_base(const char   *key_mgmt,
                                const char   *auth_alg,
                                guint32       flags,
                                guint32       wpa_flags,
                                guint32       rsn_flags,
                                gboolean      add_wifi,
                                guint         error_code,
                                NMConnection *expected)
{
    NMConnection *src;
    const char   *ssid        = "blahblah";
    const char   *bssid       = "01:02:03:04:05:06";
    const KeyData exp_wifi[]  = {{NM_SETTING_WIRELESS_SSID, ssid, 0},
                                 {NM_SETTING_WIRELESS_MODE, "infrastructure", 0},
                                 {NULL}};
    const KeyData both_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt, 0},
                                 {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, auth_alg, 0},
                                 {NM_SETTING_WIRELESS_SECURITY_PSK, "asdfasdfasdfasdfasdfafs", 0},
                                 {NULL}};
    gboolean      success;
    GError       *error = NULL;

    src = nm_simple_connection_new();
    if (add_wifi)
        fill_wifi_empty(src);
    fill_wsec(src, both_wsec);
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  flags,
                                  wpa_flags,
                                  rsn_flags,
                                  FALSE,
                                  src,
                                  &error);
    if (expected) {
        fill_wifi(expected, exp_wifi);
        fill_wsec(expected, both_wsec);
    }
    COMPARE(src, expected, success, error, NM_CONNECTION_ERROR, error_code);

    g_object_unref(src);
}

static void
test_open_ap_wpa_psk_connection_1(void)
{
    /* Test that a WPA-PSK connection filling only the PSK itself and *not*
     * filling the wifi setting is rejected when completion is attempted with
     * an open AP.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_SETTING,
                                    NULL);
}

static void
test_open_ap_wpa_psk_connection_2(void)
{
    /* Test that a WPA-PSK connection filling only the PSK itself and also
     * filling the wifi setting is rejected when completion is attempted with
     * an open AP.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    TRUE,
                                    NM_CONNECTION_ERROR_INVALID_SETTING,
                                    NULL);
}

static void
test_open_ap_wpa_psk_connection_3(void)
{
    /* Test that a WPA-PSK connection filling the PSK and setting the auth alg
     * to 'open' is rejected when completion is attempted with an open AP.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    "open",
                                    NM_802_11_AP_FLAGS_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_SETTING,
                                    NULL);
}

static void
test_open_ap_wpa_psk_connection_4(void)
{
    /* Test that a WPA-PSK connection filling the PSK and setting the auth alg
     * to 'shared' is rejected when completion is attempted with an open AP.
     * Shared auth cannot be used with WPA.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    "shared",
                                    NM_802_11_AP_FLAGS_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_SETTING,
                                    NULL);
}

static void
test_open_ap_wpa_psk_connection_5(void)
{
    /* Test that a WPA-PSK connection filling the PSK, the auth algorithm, and
     * key management is rejected when completion is attempted with an open AP.
     */
    test_ap_wpa_psk_connection_base("wpa-psk",
                                    "open",
                                    NM_802_11_AP_FLAGS_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_SETTING,
                                    NULL);
}

/*****************************************************************************/

static void
test_ap_wpa_eap_connection_base(const char *key_mgmt,
                                const char *auth_alg,
                                guint32     flags,
                                guint32     wpa_flags,
                                guint32     rsn_flags,
                                gboolean    add_wifi,
                                guint       error_code)
{
    NMConnection *src;
    const char   *bssid       = "01:02:03:04:05:06";
    const KeyData src_empty[] = {{NULL}};
    const KeyData src_wsec[]  = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, key_mgmt, 0},
                                 {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, auth_alg, 0},
                                 {NULL}};
    gboolean      success;
    GError       *error = NULL;

    src = nm_simple_connection_new();
    if (add_wifi)
        fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    fill_8021x(src, src_empty);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  flags,
                                  wpa_flags,
                                  rsn_flags,
                                  FALSE,
                                  src,
                                  &error);
    /* Failure expected */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, error_code);

    g_object_unref(src);
}

enum {
    IDX_NONE = 0,
    IDX_OPEN,
    IDX_PRIV,
    IDX_WPA_PSK_PTKIP_GTKIP,
    IDX_WPA_PSK_PTKIP_PCCMP_GTKIP,
    IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP,
    IDX_WPA_RSN_PSK_PCCMP_GCCMP,
    IDX_RSN_PSK_PCCMP_GCCMP,
    IDX_RSN_PSK_PTKIP_PCCMP_GTKIP,
    IDX_WPA_8021X,
    IDX_RSN_8021X,
};

static guint32
flags_for_idx(guint32 idx)
{
    if (idx == IDX_OPEN)
        return NM_802_11_AP_FLAGS_NONE;
    else if (idx == IDX_PRIV || idx == IDX_WPA_PSK_PTKIP_GTKIP
             || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP || idx == IDX_RSN_PSK_PCCMP_GCCMP
             || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP || idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP
             || idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP || idx == IDX_WPA_8021X || idx == IDX_RSN_8021X)
        return NM_802_11_AP_FLAGS_PRIVACY;
    else
        g_assert_not_reached();
}

static guint32
wpa_flags_for_idx(guint32 idx)
{
    if (idx == IDX_OPEN || idx == IDX_PRIV || idx == IDX_RSN_8021X || idx == IDX_RSN_PSK_PCCMP_GCCMP
        || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP)
        return NM_802_11_AP_SEC_NONE;
    else if (idx == IDX_WPA_PSK_PTKIP_GTKIP)
        return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_GROUP_TKIP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP)
        return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (NM_IN_SET(idx, IDX_WPA_PSK_PTKIP_PCCMP_GTKIP, IDX_WPA_RSN_PSK_PCCMP_GCCMP))
        return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_WPA_8021X)
        return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_GROUP_TKIP
               | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
    else
        g_assert_not_reached();
}

static guint32
rsn_flags_for_idx(guint32 idx)
{
    if (idx == IDX_OPEN || idx == IDX_PRIV || idx == IDX_WPA_8021X || idx == IDX_WPA_PSK_PTKIP_GTKIP
        || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP)
        return NM_802_11_AP_SEC_NONE;
    else if (idx == IDX_RSN_PSK_PCCMP_GCCMP)
        return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP)
        return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP)
        return NM_802_11_AP_SEC_PAIR_TKIP | NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_TKIP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP)
        return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP
               | NM_802_11_AP_SEC_KEY_MGMT_PSK;
    else if (idx == IDX_RSN_8021X)
        return NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP
               | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
    else
        g_assert_not_reached();
}

static guint32
error_code_for_idx(guint32 idx, guint num)
{
    if (idx == IDX_OPEN)
        return NM_CONNECTION_ERROR_INVALID_SETTING;
    else if (idx == IDX_PRIV) {
        if (num <= 3)
            return NM_CONNECTION_ERROR_MISSING_PROPERTY;
        else
            return NM_CONNECTION_ERROR_INVALID_PROPERTY;
    } else if (idx == IDX_WPA_PSK_PTKIP_GTKIP || idx == IDX_WPA_PSK_PTKIP_PCCMP_GTKIP
               || idx == IDX_WPA_RSN_PSK_PCCMP_GCCMP || idx == IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP
               || idx == IDX_RSN_PSK_PTKIP_PCCMP_GTKIP || idx == IDX_RSN_PSK_PCCMP_GCCMP)
        if (num == 4)
            return NM_CONNECTION_ERROR_INVALID_PROPERTY;
        else
            return NM_CONNECTION_ERROR_INVALID_SETTING;
    else
        g_assert_not_reached();
}

static void
test_ap_wpa_eap_connection_1(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);

    test_ap_wpa_eap_connection_base(NULL,
                                    NULL,
                                    flags_for_idx(idx),
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    error_code_for_idx(idx, 1));
}

static void
test_ap_wpa_eap_connection_2(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);

    test_ap_wpa_eap_connection_base(NULL,
                                    NULL,
                                    flags_for_idx(idx),
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    TRUE,
                                    error_code_for_idx(idx, 2));
}

static void
test_ap_wpa_eap_connection_3(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);

    test_ap_wpa_eap_connection_base(NULL,
                                    "open",
                                    flags_for_idx(idx),
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    error_code_for_idx(idx, 3));
}

static void
test_ap_wpa_eap_connection_4(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);

    test_ap_wpa_eap_connection_base(NULL,
                                    "shared",
                                    flags_for_idx(idx),
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    error_code_for_idx(idx, 4));
}

static void
test_ap_wpa_eap_connection_5(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);

    test_ap_wpa_eap_connection_base("wpa-eap",
                                    "open",
                                    flags_for_idx(idx),
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    error_code_for_idx(idx, 5));
}

/*****************************************************************************/

static void
test_priv_ap_empty_connection(void)
{
    NMConnection *src, *expected;
    const char   *bssid      = "01:02:03:04:05:06";
    const char   *ssid       = "blahblah";
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", 0}, {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that an empty connection is completed to a valid Static WEP
     * connection when completed with an AP with the Privacy bit set.
     */

    src     = nm_simple_connection_new();
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);

    /* Static WEP connection expected */
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    fill_wsec(expected, exp_wsec);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_priv_ap_leap_connection_1(gconstpointer add_wifi)
{
    NMConnection *src, *expected;
    const char   *ssid          = "blahblah";
    const char   *bssid         = "01:02:03:04:05:06";
    const char   *leap_username = "Bill Smith";
    const KeyData src_wsec[]    = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                   {NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0},
                                   {NULL}};
    const KeyData exp_wsec[]    = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                   {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0},
                                   {NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0},
                                   {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that an minimal LEAP connection specifying only key management and
     * the LEAP username is completed to a full LEAP connection when completed
     * with an AP with the Privacy bit set.
     */

    src = nm_simple_connection_new();
    if (add_wifi)
        fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* We expect success here; since LEAP APs just set the 'privacy' flag
     * there's no way to determine from the AP's beacon whether it's static WEP,
     * dynamic WEP, or LEAP.
     */
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    fill_wsec(expected, exp_wsec);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_priv_ap_leap_connection_2(void)
{
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0},
                                {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that an minimal LEAP connection specifying only key management and
     * the LEAP auth alg is completed to a full LEAP connection when completed
     * with an AP with the Privacy bit set.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure here, we need a LEAP username */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_priv_ap_dynamic_wep_1(void)
{
    NMConnection *src, *expected;
    const char   *ssid         = "blahblah";
    const char   *bssid        = "01:02:03:04:05:06";
    const KeyData src_wsec[]   = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                  {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                  {NULL}};
    const KeyData both_8021x[] = {{NM_SETTING_802_1X_EAP, "peap", 0},
                                  {NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0},
                                  {NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0},
                                  {NULL}};
    const KeyData exp_wsec[]   = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                  {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                  {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that an minimal Dynamic WEP connection specifying key management,
     * the auth algorithm, and valid 802.1x setting is completed to a valid
     * Dynamic WEP connection when completed with an AP with the Privacy bit set.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    fill_8021x(src, both_8021x);
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);

    /* We expect a completed Dynamic WEP connection */
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    fill_wsec(expected, exp_wsec);
    fill_8021x(expected, both_8021x);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_priv_ap_dynamic_wep_2(void)
{
    NMConnection *src, *expected;
    const char   *ssid         = "blahblah";
    const char   *bssid        = "01:02:03:04:05:06";
    const KeyData src_wsec[]   = {{NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0}, {NULL}};
    const KeyData both_8021x[] = {{NM_SETTING_802_1X_EAP, "peap", 0},
                                  {NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0},
                                  {NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0},
                                  {NULL}};
    const KeyData exp_wsec[]   = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                  {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                  {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that an minimal Dynamic WEP connection specifying only the auth
     * algorithm and a valid 802.1x setting is completed to a valid Dynamic
     * WEP connection when completed with an AP with the Privacy bit set.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    fill_8021x(src, both_8021x);
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);

    /* We expect a completed Dynamic WEP connection */
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    fill_wsec(expected, exp_wsec);
    fill_8021x(expected, both_8021x);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_priv_ap_dynamic_wep_3(void)
{
    NMConnection *src;
    const char   *bssid       = "01:02:03:04:05:06";
    const KeyData src_wsec[]  = {{NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", 0}, {NULL}};
    const KeyData src_8021x[] = {{NM_SETTING_802_1X_EAP, "peap", 0},
                                 {NM_SETTING_802_1X_IDENTITY, "Bill Smith", 0},
                                 {NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2", 0},
                                 {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Ensure that a basic connection specifying 'shared' auth and an 802.1x
     * setting is rejected, as 802.1x is incompatible with 'shared' auth.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    fill_8021x(src, src_8021x);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  NM_802_11_AP_SEC_NONE,
                                  NM_802_11_AP_SEC_NONE,
                                  FALSE,
                                  src,
                                  &error);
    /* Expect failure; shared is not compatible with dynamic WEP */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_priv_ap_wpa_psk_connection_1(void)
{
    /* Test that a basic WPA-PSK connection is rejected when completion is
     * attempted with an AP with just the Privacy bit set.  Lack of WPA/RSN
     * flags means the AP provides Static/Dynamic WEP or LEAP, not WPA.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

static void
test_priv_ap_wpa_psk_connection_2(void)
{
    /* Test that a basic WPA-PSK connection is rejected when completion is
     * attempted with an AP with just the Privacy bit set.  Lack of WPA/RSN
     * flags means the AP provides Static/Dynamic WEP or LEAP, not WPA.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    TRUE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

static void
test_priv_ap_wpa_psk_connection_3(void)
{
    /* Test that a basic WPA-PSK connection specifying only the auth algorithm
     * is rejected when completion is attempted with an AP with just the Privacy
     * bit set.  Lack of WPA/RSN flags means the AP provides Static/Dynamic WEP
     * or LEAP, not WPA.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    "open",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

static void
test_priv_ap_wpa_psk_connection_4(void)
{
    /* Test that a basic WPA-PSK connection specifying only the auth algorithm
     * is rejected when completion is attempted with an AP with just the Privacy
     * bit set.  Lack of WPA/RSN flags means the AP provides Static/Dynamic WEP
     * or LEAP, not WPA.  Second, 'shared' auth is incompatible with WPA.
     */
    test_ap_wpa_psk_connection_base(NULL,
                                    "shared",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

static void
test_priv_ap_wpa_psk_connection_5(void)
{
    /* Test that a WPA-PSK connection specifying both the key management and
     * auth algorithm is rejected when completion is attempted with an AP with
     * just the Privacy bit set.  Lack of WPA/RSN flags means the AP provides
     * Static/Dynamic WEP or LEAP, not WPA.
     */
    test_ap_wpa_psk_connection_base("wpa-psk",
                                    "open",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    NM_802_11_AP_SEC_NONE,
                                    NM_802_11_AP_SEC_NONE,
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

/*****************************************************************************/

static void
test_wpa_ap_empty_connection(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *src, *expected;
    const char   *bssid      = "01:02:03:04:05:06";
    const char   *ssid       = "blahblah";
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that a basic WPA-PSK connection specifying just key management and
     * the auth algorithm is completed successfully when given an AP with WPA
     * or RSN flags.
     */

    src     = nm_simple_connection_new();
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  wpa_flags_for_idx(idx),
                                  rsn_flags_for_idx(idx),
                                  FALSE,
                                  src,
                                  &error);

    /* WPA connection expected */
    expected = create_basic(ssid, NULL, _NM_802_11_MODE_INFRA);
    fill_wsec(expected, exp_wsec);
    COMPARE(src, expected, success, error, 0, 0);

    g_object_unref(src);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_wpa_ap_leap_connection_1(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *src;
    const char   *ssid          = "blahblah";
    const char   *bssid         = "01:02:03:04:05:06";
    const char   *leap_username = "Bill Smith";
    const KeyData src_wsec[]    = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                   {NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username, 0},
                                   {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that completion of a LEAP connection with a WPA-enabled AP is
     * rejected since WPA APs (usually) do not support LEAP.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection(ssid,
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  wpa_flags_for_idx(idx),
                                  rsn_flags_for_idx(idx),
                                  FALSE,
                                  src,
                                  &error);
    /* Expect failure here; WPA APs don't support old-school LEAP */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_wpa_ap_leap_connection_2(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap", 0},
                                {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that completion of a LEAP connection with a WPA-enabled AP is
     * rejected since WPA APs (usually) do not support LEAP.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  wpa_flags_for_idx(idx),
                                  rsn_flags_for_idx(idx),
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure here, we need a LEAP username */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_wpa_ap_dynamic_wep_connection(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *src;
    const char   *bssid      = "01:02:03:04:05:06";
    const KeyData src_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", 0}, {NULL}};
    gboolean      success;
    GError       *error = NULL;

    /* Test that completion of a Dynamic WEP connection with a WPA-enabled AP is
     * rejected since WPA APs (usually) do not support Dynamic WEP.
     */

    src = nm_simple_connection_new();
    fill_wifi_empty(src);
    fill_wsec(src, src_wsec);
    success = complete_connection("blahblah",
                                  bssid,
                                  _NM_802_11_MODE_INFRA,
                                  NM_802_11_AP_FLAGS_PRIVACY,
                                  wpa_flags_for_idx(idx),
                                  rsn_flags_for_idx(idx),
                                  FALSE,
                                  src,
                                  &error);
    /* We expect failure here since Dynamic WEP is incompatible with WPA */
    COMPARE(src, NULL, success, error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);

    g_object_unref(src);
}

/*****************************************************************************/

static void
test_wpa_ap_wpa_psk_connection_1(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *expected;
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                {NULL}};

    expected = nm_simple_connection_new();
    fill_wsec(expected, exp_wsec);
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    expected);
    g_object_unref(expected);
}

static void
test_wpa_ap_wpa_psk_connection_2(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *expected;
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                {NULL}};

    expected = nm_simple_connection_new();
    fill_wsec(expected, exp_wsec);
    test_ap_wpa_psk_connection_base(NULL,
                                    NULL,
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    TRUE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    expected);
    g_object_unref(expected);
}

static void
test_wpa_ap_wpa_psk_connection_3(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *expected;
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                {NULL}};

    expected = nm_simple_connection_new();
    fill_wsec(expected, exp_wsec);
    test_ap_wpa_psk_connection_base(NULL,
                                    "open",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    expected);
    g_object_unref(expected);
}

static void
test_wpa_ap_wpa_psk_connection_4(gconstpointer data)
{
    guint idx = GPOINTER_TO_UINT(data);
    test_ap_wpa_psk_connection_base(NULL,
                                    "shared",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    NULL);
}

static void
test_wpa_ap_wpa_psk_connection_5(gconstpointer data)
{
    guint         idx = GPOINTER_TO_UINT(data);
    NMConnection *expected;
    const KeyData exp_wsec[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", 0},
                                {NULL}};

    expected = nm_simple_connection_new();
    fill_wsec(expected, exp_wsec);
    test_ap_wpa_psk_connection_base("wpa-psk",
                                    "open",
                                    NM_802_11_AP_FLAGS_PRIVACY,
                                    wpa_flags_for_idx(idx),
                                    rsn_flags_for_idx(idx),
                                    FALSE,
                                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                    expected);
    g_object_unref(expected);
}

/*****************************************************************************/

static void
test_strength_dbm(void)
{
    /* boundary conditions first */
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-1), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-40), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-30), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-100), ==, 0);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-200), ==, 0);

    g_assert_cmpint(nm_wifi_utils_level_to_quality(-81), ==, 32);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-92), ==, 14);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-74), ==, 44);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-81), ==, 32);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(-66), ==, 57);
}

static void
test_strength_percent(void)
{
    int i;

    /* boundary conditions first */
    g_assert_cmpint(nm_wifi_utils_level_to_quality(0), ==, 0);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(100), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(110), ==, 100);

    for (i = 0; i <= 100; i++)
        g_assert_cmpint(nm_wifi_utils_level_to_quality(i), ==, i);
}

static void
test_strength_wext(void)
{
    /* boundary conditions that we assume aren't WEXT first */
    g_assert_cmpint(nm_wifi_utils_level_to_quality(256), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(110), ==, 100);

    /* boundary conditions that we assume are WEXT */
    g_assert_cmpint(nm_wifi_utils_level_to_quality(111), ==, 0);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(150), ==, 0);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(225), ==, 100);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(255), ==, 100);

    g_assert_cmpint(nm_wifi_utils_level_to_quality(157), ==, 2);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(200), ==, 74);
    g_assert_cmpint(nm_wifi_utils_level_to_quality(215), ==, 99);
}

#define _assert_strength_in_range(x)  \
    ({                                \
        guint32 _x = (x);             \
        g_assert_cmpint(_x, >=, 0);   \
        g_assert_cmpint(_x, <=, 100); \
    })

static void
test_strength_all(void)
{
    int val;

    for (val = -200; val < 300; val++)
        _assert_strength_in_range(nm_wifi_utils_level_to_quality(val));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MININT));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MAXINT));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MININT32));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MAXINT32));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MININT16));
    _assert_strength_in_range(nm_wifi_utils_level_to_quality(G_MAXINT16));
}

/*****************************************************************************/

static void
do_test_ssids_options_to_ptrarray(const char *const *ssids)
{
    GVariantBuilder              builder;
    gs_unref_variant GVariant   *variant   = NULL;
    gs_unref_ptrarray GPtrArray *ssids_arr = NULL;
    gs_free_error GError        *error     = NULL;
    gsize                        len;
    gsize                        i;

    g_assert(ssids);

    len = NM_PTRARRAY_LEN(ssids);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("aay"));
    for (i = 0; i < len; i++) {
        const char *ssid = ssids[i];

        g_variant_builder_add(
            &builder,
            "@ay",
            g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, ssid, strlen(ssid), 1));
    }
    variant = g_variant_builder_end(&builder);

    if (nmtst_get_rand_bool())
        g_variant_ref_sink(variant);

    ssids_arr = nmtst_ssids_options_to_ptrarray(variant, &error);
    g_assert(!error);
    if (len == 0) {
        g_assert(!ssids_arr);
        return;
    }
    g_assert_cmpint(len, ==, ssids_arr->len);
    for (i = 0; i < len; i++) {
        const char *ssid  = ssids[i];
        GBytes     *bytes = ssids_arr->pdata[i];

        g_assert(nm_g_bytes_equal_mem(bytes, ssid, strlen(ssid)));
    }
}

static void
test_ssids_options_to_ptrarray(void)
{
    do_test_ssids_options_to_ptrarray(NM_PTRARRAY_EMPTY(const char *));
    do_test_ssids_options_to_ptrarray(NM_MAKE_STRV("ab"));
    do_test_ssids_options_to_ptrarray(NM_MAKE_STRV("ab", "cd", "fsdfdsf"));
}

/*****************************************************************************/

static void
test_wps_key_to_psk(void)
{
    static const struct {
        const char *key;
        gsize       key_len;
        gboolean    valid;
    } cases[] = {
        {"12345678", 8, TRUE},
        {"supersecret123", 14, TRUE},
        {"caf\xc3\xa9_key", 9, TRUE},
        {"123456789012345678901234567890123456789012345678901234567890123", 63, TRUE},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, TRUE},
        {"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdeF", 64, TRUE},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", 64, FALSE},
        {"", 0, FALSE},
        {"1234567", 7, FALSE},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", 65, FALSE},
        {"abc\xff"
         "def123",
         10,
         FALSE},
        {"0123456789abcdef0123456789abcdef\0"
         "23456789abcdef0123456789abcdef0",
         64,
         FALSE},
    };
    gsize i;

    for (i = 0; i < G_N_ELEMENTS(cases); i++) {
        char     psk[65];
        gboolean ok;

        ok = nm_wifi_utils_wps_key_to_psk((const guint8 *) cases[i].key, cases[i].key_len, &psk);
        g_assert_cmpint(ok, ==, cases[i].valid);
        if (ok) {
            g_assert_cmpmem(psk, cases[i].key_len, cases[i].key, cases[i].key_len);
            g_assert_cmpint(psk[cases[i].key_len], ==, '\0');
        }
    }
}

/*****************************************************************************/

static void
test_ap_check_compatible_band(void)
{
    gs_unref_object NMWifiAP     *ap_no_freq    = NULL;
    gs_unref_object NMWifiAP     *ap_open       = NULL;
    gs_unref_object NMWifiAP     *ap_rsn        = NULL;
    gs_unref_object NMConnection *conn_ap       = NULL;
    gs_unref_object NMConnection *conn          = NULL;
    const KeyData                 band_a[]      = {{NM_SETTING_WIRELESS_BAND, "a", 0}, {NULL}};
    const KeyData                 band_bg[]     = {{NM_SETTING_WIRELESS_BAND, "bg", 0}, {NULL}};
    const KeyData                 band_a_ch36[] = {{NM_SETTING_WIRELESS_BAND, "a", 0},
                                                   {NM_SETTING_WIRELESS_CHANNEL, NULL, 36},
                                                   {NULL}};
    const KeyData                 band_a_ch40[] = {{NM_SETTING_WIRELESS_BAND, "a", 0},
                                                   {NM_SETTING_WIRELESS_CHANNEL, NULL, 40},
                                                   {NULL}};
    const KeyData wsec_psk[] = {{NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", 0},
                                {NM_SETTING_WIRELESS_SECURITY_PROTO, "rsn", 0},
                                {NULL}};

    /* An AP with unknown frequency never matches a profile that requires a band. */
    conn       = create_basic("hidden", NULL, _NM_802_11_MODE_INFRA);
    ap_no_freq = nm_wifi_ap_new_fake_from_connection(conn);
    g_assert(ap_no_freq);

    fill_wifi(conn, band_a);
    g_assert(!nm_wifi_ap_check_compatible(ap_no_freq, conn));

    conn_ap = create_basic("hidden", NULL, _NM_802_11_MODE_INFRA);
    fill_wifi(conn_ap, band_a_ch36);
    ap_open = nm_wifi_ap_new_fake_from_connection(conn_ap);
    g_assert(ap_open);

    g_assert(nm_wifi_ap_check_compatible(ap_open, conn));

    fill_wifi(conn, band_bg);
    g_assert(!nm_wifi_ap_check_compatible(ap_open, conn));

    /* A matching band must not skip the channel check. */
    fill_wifi(conn, band_a_ch40);
    g_assert(!nm_wifi_ap_check_compatible(ap_open, conn));

    /* A matching band must not skip the security check. */
    fill_wsec(conn_ap, wsec_psk);
    ap_rsn = nm_wifi_ap_new_fake_from_connection(conn_ap);
    g_assert(ap_rsn);

    fill_wifi(conn, band_a_ch36);
    g_assert(nm_wifi_ap_check_compatible(ap_open, conn));
    g_assert(!nm_wifi_ap_check_compatible(ap_rsn, conn));
}

/*****************************************************************************/

/*****************************************************************************/

static GVariant *
_cert_info_bytes(guint32 depth, const char *subject, GBytes *cert, const char *const *altsubject)
{
    GVariantBuilder builder;

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&builder, "{sv}", "depth", g_variant_new_uint32(depth));
    g_variant_builder_add(&builder, "{sv}", "subject", g_variant_new_string(subject));
    if (altsubject)
        g_variant_builder_add(&builder, "{sv}", "altsubject", g_variant_new_strv(altsubject, -1));
    if (cert)
        g_variant_builder_add(&builder, "{sv}", "cert", nm_g_bytes_to_variant_ay(cert));
    return g_variant_ref_sink(g_variant_builder_end(&builder));
}

static GVariant *
_cert_info(guint32 depth, const char *subject, const char *cert, const char *const *altsubject)
{
    gs_unref_bytes GBytes *bytes = cert ? g_bytes_new(cert, strlen(cert)) : NULL;

    return _cert_info_bytes(depth, subject, bytes, altsubject);
}

static void
test_tofu_certificate(void)
{
    nm_auto_free_wifi_tofu NMWifiTofu *tofu        = nm_wifi_tofu_new(NULL);
    gs_unref_variant GVariant         *root        = NULL;
    gs_unref_variant GVariant         *issuer      = NULL;
    gs_unref_variant GVariant         *no_cert     = NULL;
    gs_unref_variant GVariant         *server      = NULL;
    gs_unref_variant GVariant         *server2     = NULL;
    gs_unref_variant GVariant         *certificate = NULL;
    gs_unref_variant GVariant         *der         = NULL;
    gs_unref_variant GVariant         *cas         = NULL;
    gs_unref_variant GVariant         *ssid        = NULL;
    gs_unref_bytes GBytes             *ssid_bytes  = nmtst_gbytes_from_str("eduroam");
    gs_free const char               **alt_out     = NULL;
    const char *const                  alt[]       = {"DNS:radius.example.com", NULL};
    const char                        *str;
    gboolean                           b;
    gsize                              len;

    root    = _cert_info(2, "/O=Example/CN=Example Root CA", "root", NULL);
    issuer  = _cert_info(1, "/C=BE/O=Example/CN=Example Issuing CA", "issuer", NULL);
    no_cert = _cert_info(0, "/C=BE/O=Example Org/CN=radius.example.com", NULL, alt);
    server  = _cert_info(0, "/C=BE/O=Example Org/CN=radius.example.com", "hello", alt);
    server2 = _cert_info(0, "/CN=evil", "evil", NULL);

    g_assert(!nm_wifi_tofu_add_certificate(tofu, root));
    g_assert(!nm_wifi_tofu_add_certificate(tofu, issuer));
    g_assert(!nm_wifi_tofu_add_certificate(tofu, no_cert));
    g_assert(!nm_wifi_tofu_has_server_cert(tofu));
    g_assert(nm_wifi_tofu_add_certificate(tofu, server));
    g_assert(nm_wifi_tofu_has_server_cert(tofu));

    /* only the first server certificate counts */
    g_assert(!nm_wifi_tofu_add_certificate(tofu, server2));

    /* these are no valid certificates, only the fingerprint can be trusted */
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT);

    certificate = g_variant_ref_sink(nm_wifi_tofu_get_certificate(tofu, ssid_bytes, TRUE));
    g_assert(g_variant_lookup(certificate, "fingerprint", "&s", &str));
    g_assert_cmpstr(str,
                    ==,
                    "2C:F2:4D:BA:5F:B0:A3:0E:26:E8:3B:2A:C5:B9:E2:9E:1B:16:1E:5C:1F:A7:42:5E:73:04:"
                    "33:62:93:8B:98:24");
    g_assert(g_variant_lookup(certificate, "subject", "&s", &str));
    g_assert_cmpstr(str, ==, "/C=BE/O=Example Org/CN=radius.example.com");
    g_assert(g_variant_lookup(certificate, "altsubject", "^a&s", &alt_out));
    g_assert(nm_strv_equal(alt_out, alt));
    der = g_variant_lookup_value(certificate, "certificate", G_VARIANT_TYPE_BYTESTRING);
    g_assert(der);
    g_assert_cmpmem(g_variant_get_fixed_array(der, &len, 1), len, "hello", 5);
    cas = g_variant_lookup_value(certificate, "ca-certificates", G_VARIANT_TYPE("aay"));
    g_assert(cas);
    g_assert_cmpint(g_variant_n_children(cas), ==, 2);
    ssid = g_variant_lookup_value(certificate, "ssid", G_VARIANT_TYPE_BYTESTRING);
    g_assert(ssid);
    g_assert_cmpmem(g_variant_get_fixed_array(ssid, &len, 1), len, "eduroam", 7);
    g_assert(g_variant_lookup(certificate, "system-trusted", "b", &b));
    g_assert(!b);
    g_assert(g_variant_lookup(certificate, "changed", "b", &b));
    g_assert(b);
    g_assert(g_variant_lookup(certificate, "trust-anchor", "&s", &str));
    g_assert_cmpstr(str, ==, "server-certificate");
}

static void
test_tofu_certificate_minimal(void)
{
    nm_auto_free_wifi_tofu NMWifiTofu *tofu        = nm_wifi_tofu_new(NULL);
    gs_unref_variant GVariant         *server      = NULL;
    gs_unref_variant GVariant         *certificate = NULL;
    gs_unref_variant GVariant         *cas         = NULL;
    gboolean                           changed;

    /* a self-signed server certificate without SAN */
    server = _cert_info(0, "/O=Example", "hello", NULL);
    g_assert(nm_wifi_tofu_add_certificate(tofu, server));

    certificate = g_variant_ref_sink(nm_wifi_tofu_get_certificate(tofu, NULL, FALSE));
    g_assert(g_variant_lookup(certificate, "fingerprint", "&s", NULL));
    g_assert(g_variant_lookup(certificate, "certificate", "ay", NULL));
    cas = g_variant_lookup_value(certificate, "ca-certificates", G_VARIANT_TYPE("aay"));
    g_assert_cmpint(g_variant_n_children(cas), ==, 0);
    g_assert(!g_variant_lookup(certificate, "altsubject", "as", NULL));
    g_assert(!g_variant_lookup(certificate, "ssid", "ay", NULL));
    g_assert(g_variant_lookup(certificate, "changed", "b", &changed));
    g_assert(!changed);
}

static void
test_tofu_certificate_invalid(void)
{
    nm_auto_free_wifi_tofu NMWifiTofu *tofu = nm_wifi_tofu_new(NULL);
    GVariantBuilder                    builder;
    gs_unref_variant GVariant         *info = NULL;

    /* wrongly typed values are ignored, without warnings */
    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&builder, "{sv}", "depth", g_variant_new_string("0"));
    g_variant_builder_add(&builder, "{sv}", "cert", g_variant_new_string("hello"));
    info = g_variant_ref_sink(g_variant_builder_end(&builder));
    g_assert(!nm_wifi_tofu_add_certificate(tofu, info));
    g_clear_pointer(&info, g_variant_unref);

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&builder, "{sv}", "depth", g_variant_new_uint32(100));
    g_variant_builder_add(&builder, "{sv}", "cert", nm_g_bytes_to_variant_ay(NULL));
    info = g_variant_ref_sink(g_variant_builder_end(&builder));
    g_assert(!nm_wifi_tofu_add_certificate(tofu, info));

    g_assert(!nm_wifi_tofu_has_server_cert(tofu));
}

#define TOFU_CERT_DIR NM_BUILD_SRCDIR "/src/libnm-core-impl/tests/certs/"

static GBytes *
_load_cert(const char *file)
{
    gs_unref_ptrarray GPtrArray *certs = nm_crypto_load_x509_certificates(file);

    g_assert_cmpint(certs->len, ==, 1);
    return g_bytes_ref(certs->pdata[0]);
}

#define SUBJECT "/O=Example Org/CN=radius.example.com"

static NMWifiTofu *
_tofu_with_chain(const char *system_ca_path,
                 gboolean    send_root,
                 const char *subject,
                 gboolean    with_dns_name)
{
    NMWifiTofu                *tofu   = nm_wifi_tofu_new(system_ca_path);
    gs_unref_bytes GBytes     *server = _load_cert(TOFU_CERT_DIR "test-tofu-server.pem");
    gs_unref_bytes GBytes     *root   = _load_cert(TOFU_CERT_DIR "test-tofu-root-ca.pem");
    gs_unref_variant GVariant *info0  = NULL;
    gs_unref_variant GVariant *info1  = NULL;
    const char *const          alt[]  = {"DNS:radius.example.com", NULL};

    if (send_root) {
        info1 = _cert_info_bytes(1, "/O=Example Org/CN=Example Root CA", root, NULL);
        g_assert(!nm_wifi_tofu_add_certificate(tofu, info1));
    }
    info0 = _cert_info_bytes(0, subject, server, with_dns_name ? alt : NULL);
    g_assert(nm_wifi_tofu_add_certificate(tofu, info0));
    return tofu;
}

static void
test_tofu_trust_anchor(void)
{
    gs_unref_object NMSetting8021x *s_8021x = NM_SETTING_802_1X(nm_setting_802_1x_new());
    gs_unref_bytes GBytes          *root    = _load_cert(TOFU_CERT_DIR "test-tofu-root-ca.pem");
    gs_unref_bytes GBytes          *ca_cert = NULL;
    NMWifiTofu                     *tofu;

    nm_setting_802_1x_add_eap_method(s_8021x, "peap");
    g_object_set(s_8021x,
                 NM_SETTING_802_1X_IDENTITY,
                 "bob",
                 NM_SETTING_802_1X_PHASE2_AUTH,
                 "mschapv2",
                 NM_SETTING_802_1X_TRUST_ON_FIRST_USE,
                 TRUE,
                 NULL);

    /* the system trusts the CA of the server: only that CA is trusted */
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-root-ca.pem", FALSE, SUBJECT, TRUE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_SYSTEM_CA);
    nm_wifi_tofu_set_trust_anchor(tofu, s_8021x);
    g_object_get(s_8021x, NM_SETTING_802_1X_CA_CERT, &ca_cert, NULL);
    g_assert(g_bytes_equal(ca_cert, root));
    g_clear_pointer(&ca_cert, g_bytes_unref);
    g_assert(!nm_setting_802_1x_get_system_ca_certs(s_8021x));
    g_assert_cmpstr(nm_setting_802_1x_get_domain_match(s_8021x), ==, "radius.example.com");
    g_assert_cmpstr(nm_setting_802_1x_get_server_cert_hash(s_8021x), ==, NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_8021x));
    nm_wifi_tofu_free(tofu);

    /* the server sent its own root CA, which the system does not trust */
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-other-ca.pem", TRUE, SUBJECT, TRUE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_ROOT_CA);
    nm_wifi_tofu_set_trust_anchor(tofu, s_8021x);
    g_object_get(s_8021x, NM_SETTING_802_1X_CA_CERT, &ca_cert, NULL);
    g_assert(g_bytes_equal(ca_cert, root));
    g_clear_pointer(&ca_cert, g_bytes_unref);
    g_assert(!nm_setting_802_1x_get_system_ca_certs(s_8021x));
    g_assert_cmpstr(nm_setting_802_1x_get_domain_match(s_8021x), ==, "radius.example.com");
    g_assert_cmpstr(nm_setting_802_1x_get_server_cert_hash(s_8021x), ==, NULL);
    nmtst_assert_setting_verifies(NM_SETTING(s_8021x));
    nm_wifi_tofu_free(tofu);

    /* no CA to rely on: the server certificate itself, replacing the CA and a
     * CA path */
    g_object_set(s_8021x, NM_SETTING_802_1X_CA_PATH, "/etc/ssl/certs", NULL);
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-other-ca.pem", FALSE, SUBJECT, TRUE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT);
    nm_wifi_tofu_set_trust_anchor(tofu, s_8021x);
    g_assert_cmpint(nm_setting_802_1x_get_ca_cert_scheme(s_8021x),
                    ==,
                    NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);
    g_assert_cmpstr(nm_setting_802_1x_get_ca_path(s_8021x), ==, NULL);
    g_assert(!nm_setting_802_1x_get_system_ca_certs(s_8021x));
    g_assert_cmpstr(nm_setting_802_1x_get_domain_match(s_8021x), ==, NULL);
    g_assert(nm_setting_802_1x_get_server_cert_hash(s_8021x));
    nmtst_assert_setting_verifies(NM_SETTING(s_8021x));
    nm_wifi_tofu_free(tofu);

    /* without a DNS name, the common name is the server name, like for the
     * domain-match of wpa_supplicant */
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-other-ca.pem", TRUE, SUBJECT, FALSE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_ROOT_CA);
    nm_wifi_tofu_set_trust_anchor(tofu, s_8021x);
    g_assert_cmpstr(nm_setting_802_1x_get_domain_match(s_8021x), ==, "radius.example.com");
    nm_wifi_tofu_free(tofu);

    /* without a server name, a CA would trust any of its certificates */
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-root-ca.pem", TRUE, "/O=Example Org", FALSE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT);
    nm_wifi_tofu_free(tofu);

    /* not a host name */
    tofu = _tofu_with_chain(TOFU_CERT_DIR "test-tofu-root-ca.pem",
                            TRUE,
                            "/O=Example Org/CN=Example RADIUS server",
                            FALSE);
    g_assert_cmpint(nm_wifi_tofu_get_trust_anchor(tofu), ==, NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT);
    nm_wifi_tofu_free(tofu);
}

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    gsize i;

    nmtst_init_assert_logging(&argc, &argv, "INFO", "DEFAULT");

    g_test_add_func("/wifi/lock_bssid", test_lock_bssid);

    g_test_add_func("/wifi/tofu/certificate", test_tofu_certificate);
    g_test_add_func("/wifi/tofu/certificate_minimal", test_tofu_certificate_minimal);
    g_test_add_func("/wifi/tofu/certificate_invalid", test_tofu_certificate_invalid);
    g_test_add_func("/wifi/tofu/trust_anchor", test_tofu_trust_anchor);

    /* Open AP tests; make sure that connections to be completed that have
     * various security-related settings already set cause the completion
     * to fail.
     */
    g_test_add_func("/wifi/open_ap/empty_connection", test_open_ap_empty_connection);
    g_test_add_data_func("/wifi/open_ap/leap_connection/1",
                         (gconstpointer) TRUE,
                         test_open_ap_leap_connection_1);
    g_test_add_data_func("/wifi/open_ap/leap_connection/1_no_add_wifi",
                         (gconstpointer) FALSE,
                         test_open_ap_leap_connection_1);
    g_test_add_func("/wifi/open_ap/leap_connection/2", test_open_ap_leap_connection_2);
    g_test_add_data_func("/wifi/open_ap/wep_connection_true",
                         (gconstpointer) TRUE,
                         test_open_ap_wep_connection);
    g_test_add_data_func("/wifi/open_ap/wep_connection_false",
                         (gconstpointer) FALSE,
                         test_open_ap_wep_connection);

    g_test_add_func("/wifi/open_ap/wpa_psk_connection/1", test_open_ap_wpa_psk_connection_1);
    g_test_add_func("/wifi/open_ap/wpa_psk_connection/2", test_open_ap_wpa_psk_connection_2);
    g_test_add_func("/wifi/open_ap/wpa_psk_connection/3", test_open_ap_wpa_psk_connection_3);
    g_test_add_func("/wifi/open_ap/wpa_psk_connection/4", test_open_ap_wpa_psk_connection_4);
    g_test_add_func("/wifi/open_ap/wpa_psk_connection/5", test_open_ap_wpa_psk_connection_5);

    g_test_add_data_func("/wifi/open_ap/wpa_eap_connection/1",
                         (gconstpointer) IDX_OPEN,
                         test_ap_wpa_eap_connection_1);
    g_test_add_data_func("/wifi/open_ap/wpa_eap_connection/2",
                         (gconstpointer) IDX_OPEN,
                         test_ap_wpa_eap_connection_2);
    g_test_add_data_func("/wifi/open_ap/wpa_eap_connection/3",
                         (gconstpointer) IDX_OPEN,
                         test_ap_wpa_eap_connection_3);
    g_test_add_data_func("/wifi/open_ap/wpa_eap_connection/4",
                         (gconstpointer) IDX_OPEN,
                         test_ap_wpa_eap_connection_4);
    g_test_add_data_func("/wifi/open_ap/wpa_eap_connection/5",
                         (gconstpointer) IDX_OPEN,
                         test_ap_wpa_eap_connection_5);

    /* WEP AP tests */
    g_test_add_func("/wifi/priv_ap/empty_connection", test_priv_ap_empty_connection);
    g_test_add_data_func("/wifi/priv_ap/leap_connection/1",
                         (gconstpointer) FALSE,
                         test_priv_ap_leap_connection_1);
    g_test_add_func("/wifi/priv_ap/leap_connection/2", test_priv_ap_leap_connection_2);

    g_test_add_func("/wifi/priv_ap/dynamic_wep/1", test_priv_ap_dynamic_wep_1);
    g_test_add_func("/wifi/priv_ap/dynamic_wep/2", test_priv_ap_dynamic_wep_2);
    g_test_add_func("/wifi/priv_ap/dynamic_wep/3", test_priv_ap_dynamic_wep_3);

    g_test_add_func("/wifi/priv_ap/wpa_psk_connection/1", test_priv_ap_wpa_psk_connection_1);
    g_test_add_func("/wifi/priv_ap/wpa_psk_connection/2", test_priv_ap_wpa_psk_connection_2);
    g_test_add_func("/wifi/priv_ap/wpa_psk_connection/3", test_priv_ap_wpa_psk_connection_3);
    g_test_add_func("/wifi/priv_ap/wpa_psk_connection/4", test_priv_ap_wpa_psk_connection_4);
    g_test_add_func("/wifi/priv_ap/wpa_psk_connection/5", test_priv_ap_wpa_psk_connection_5);

    g_test_add_data_func("/wifi/priv_ap/wpa_eap_connection/1",
                         (gconstpointer) IDX_PRIV,
                         test_ap_wpa_eap_connection_1);
    g_test_add_data_func("/wifi/priv_ap/wpa_eap_connection/2",
                         (gconstpointer) IDX_PRIV,
                         test_ap_wpa_eap_connection_2);
    g_test_add_data_func("/wifi/priv_ap/wpa_eap_connection/3",
                         (gconstpointer) IDX_PRIV,
                         test_ap_wpa_eap_connection_3);
    g_test_add_data_func("/wifi/priv_ap/wpa_eap_connection/4",
                         (gconstpointer) IDX_PRIV,
                         test_ap_wpa_eap_connection_4);
    g_test_add_data_func("/wifi/priv_ap/wpa_eap_connection/5",
                         (gconstpointer) IDX_PRIV,
                         test_ap_wpa_eap_connection_5);

#define ADD_FUNC(func)                                                                  \
    do {                                                                                \
        char *name_idx = g_strdup_printf("/wifi/wpa_psk/" G_STRINGIFY(func) "/%zd", i); \
        g_test_add_data_func(name_idx, (gconstpointer) i, func);                        \
        g_free(name_idx);                                                               \
    } while (0)

    /* WPA-PSK tests */
    for (i = IDX_WPA_PSK_PTKIP_GTKIP; i <= IDX_WPA_RSN_PSK_PCCMP_GCCMP; i++) {
        ADD_FUNC(test_wpa_ap_empty_connection);
        ADD_FUNC(test_wpa_ap_leap_connection_1);
        ADD_FUNC(test_wpa_ap_leap_connection_2);
        ADD_FUNC(test_wpa_ap_dynamic_wep_connection);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_1);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_2);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_3);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_4);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_5);
        ADD_FUNC(test_ap_wpa_eap_connection_1);
        ADD_FUNC(test_ap_wpa_eap_connection_2);
        ADD_FUNC(test_ap_wpa_eap_connection_3);
        ADD_FUNC(test_ap_wpa_eap_connection_4);
        ADD_FUNC(test_ap_wpa_eap_connection_5);
    }

#undef ADD_FUNC
#define ADD_FUNC(func)                                                                  \
    do {                                                                                \
        char *name_idx = g_strdup_printf("/wifi/rsn_psk/" G_STRINGIFY(func) "/%zd", i); \
        g_test_add_data_func(name_idx, (gconstpointer) i, func);                        \
        g_free(name_idx);                                                               \
    } while (0)

    /* RSN-PSK tests */
    for (i = IDX_WPA_RSN_PSK_PTKIP_PCCMP_GTKIP; i <= IDX_RSN_PSK_PTKIP_PCCMP_GTKIP; i++) {
        ADD_FUNC(test_wpa_ap_empty_connection);
        ADD_FUNC(test_wpa_ap_leap_connection_1);
        ADD_FUNC(test_wpa_ap_leap_connection_2);
        ADD_FUNC(test_wpa_ap_dynamic_wep_connection);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_1);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_2);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_3);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_4);
        ADD_FUNC(test_wpa_ap_wpa_psk_connection_5);
        ADD_FUNC(test_ap_wpa_eap_connection_1);
        ADD_FUNC(test_ap_wpa_eap_connection_2);
        ADD_FUNC(test_ap_wpa_eap_connection_3);
        ADD_FUNC(test_ap_wpa_eap_connection_4);
        ADD_FUNC(test_ap_wpa_eap_connection_5);
    }

#undef ADD_FUNC

    /* Scanned signal strength conversion tests */
    g_test_add_func("/wifi/strength/dbm", test_strength_dbm);
    g_test_add_func("/wifi/strength/percent", test_strength_percent);
    g_test_add_func("/wifi/strength/wext", test_strength_wext);
    g_test_add_func("/wifi/strength/all", test_strength_all);

    g_test_add_func("/wifi/ssids_options_to_ptrarray", test_ssids_options_to_ptrarray);

    g_test_add_func("/wifi/wps_key_to_psk", test_wps_key_to_psk);

    g_test_add_func("/wifi/ap/check_compatible_band", test_ap_check_compatible_band);

    return g_test_run();
}
