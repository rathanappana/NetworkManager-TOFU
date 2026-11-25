/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_WIFI_TOFU_H__
#define __NM_WIFI_TOFU_H__

/* Trust on first use (TOFU) of the 802.1X authentication server certificate.
 *
 * If a profile sets 802-1x.trust-on-first-use but has no way yet to verify
 * the server, the device first connects with ca_cert="probe://".
 * wpa_supplicant then reports the certificate chain of the server and aborts
 * the TLS handshake, without sending any credentials. The user confirms the
 * server certificate through a certificate agent, a trust anchor for it is
 * stored in the profile and the activation restarts with it.
 *
 * Once the server is trusted, wpa_supplicant verifies it alone. If it rejects
 * the server later, for example after a certificate change, the certificate
 * chain is probed again and the user is asked whether to trust the new
 * certificate. */

typedef enum {
    /* the SHA-256 fingerprint of the server certificate */
    NM_WIFI_TOFU_TRUST_ANCHOR_SERVER_CERT,
    /* the root CA sent by the server, and the server name */
    NM_WIFI_TOFU_TRUST_ANCHOR_ROOT_CA,
    /* the root CA of the system that the chain leads to, and the server name */
    NM_WIFI_TOFU_TRUST_ANCHOR_SYSTEM_CA,
} NMWifiTofuTrustAnchor;

typedef struct _NMWifiTofu NMWifiTofu;

typedef void (*NMWifiTofuCallback)(NMWifiTofu *tofu,
                                   gboolean    trusted,
                                   GError     *error,
                                   gpointer    user_data);

NMWifiTofu *nm_wifi_tofu_new(const char *system_ca_path);
void        nm_wifi_tofu_free(NMWifiTofu *tofu);

NM_AUTO_DEFINE_FCN0(NMWifiTofu *, _nm_auto_free_wifi_tofu, nm_wifi_tofu_free);
#define nm_auto_free_wifi_tofu nm_auto(_nm_auto_free_wifi_tofu)

gboolean nm_wifi_tofu_add_certificate(NMWifiTofu *tofu, GVariant *cert_info);
gboolean nm_wifi_tofu_has_server_cert(NMWifiTofu *tofu);

NMWifiTofuTrustAnchor nm_wifi_tofu_get_trust_anchor(NMWifiTofu *tofu);
void                  nm_wifi_tofu_set_trust_anchor(NMWifiTofu *tofu, NMSetting8021x *s_8021x);

GVariant *nm_wifi_tofu_get_certificate(NMWifiTofu *tofu, GBytes *ssid, gboolean changed);

void nm_wifi_tofu_confirm(NMWifiTofu        *tofu,
                          NMActRequest      *req,
                          gboolean           changed,
                          NMWifiTofuCallback callback,
                          gpointer           user_data);

#endif /* __NM_WIFI_TOFU_H__ */
