/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-certificate-agent.h"

#include <gio/gio.h>

#include "libnmt-newt/nmt-newt.h"

/*****************************************************************************/

#define CERT_AGENT_OBJECT_PATH "/org/freedesktop/NetworkManager/CertificateAgent"
#define CERT_AGENT_IFACE       "org.freedesktop.NetworkManager.CertificateAgent"

static const char cert_agent_xml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<node name=\"/\">"
    "  <interface name=\"org.freedesktop.NetworkManager.CertificateAgent\">"
    "    <method name=\"CertificateVerificationRequest\">"
    "      <arg name=\"ssid\"             type=\"s\" direction=\"in\"/>"
    "      <arg name=\"certificate_name\" type=\"s\" direction=\"in\"/>"
    "      <arg name=\"issuer_name\"      type=\"s\" direction=\"in\"/>"
    "      <arg name=\"organization\"     type=\"s\" direction=\"in\"/>"
    "      <arg name=\"sha256_hex\"       type=\"s\" direction=\"in\"/>"
    "      <arg name=\"expiration_str\"   type=\"s\" direction=\"in\"/>"
    "      <arg name=\"str_disclaimer\"   type=\"s\" direction=\"in\"/>"
    "      <arg name=\"best_url\"         type=\"s\" direction=\"in\"/>"
    "      <arg name=\"response\"         type=\"b\" direction=\"out\"/>"
    "    </method>"
    "    <method name=\"CertificateVerificationFailure\">"
    "      <arg name=\"ssid\"          type=\"s\" direction=\"in\"/>"
    "      <arg name=\"error_message\" type=\"s\" direction=\"in\"/>"
    "    </method>"
    "  </interface>"
    "</node>";

static GDBusConnection *s_conn   = NULL;
static guint            s_reg_id = 0;

/*****************************************************************************/

static void
trust_activated_cb(NmtNewtWidget *widget, gpointer user_data)
{
    NmtNewtForm *form = NMT_NEWT_FORM(user_data);

    g_object_set_data(G_OBJECT(form), "cert-accepted", GINT_TO_POINTER(TRUE));
    nmt_newt_form_quit(form);
}

static gboolean
run_cert_dialog(const char *ssid,
                const char *cn,
                const char *issuer,
                const char *org,
                const char *sha256,
                const char *exp,
                const char *disclaimer,
                const char *url)
{
    NmtNewtForm   *form;
    NmtNewtWidget *widget;
    NmtNewtGrid   *grid;
    NmtNewtWidget *bbox;
    NmtNewtWidget *trust_btn, *reject_btn;
    gs_free char  *text = NULL;
    gboolean       accepted;

    text = g_strdup_printf(_("Network:      %s\n"
                             "Certificate:  %s\n"
                             "Issuer:       %s\n"
                             "Organization: %s\n"
                             "SHA-256:      %s\n"
                             "Expires:      %s\n"
                             "URL:          %s\n"
                             "\n%s"),
                           ssid       ?: "",
                           cn         ?: "",
                           issuer     ?: "",
                           org        ?: "",
                           sha256     ?: "",
                           exp        ?: "",
                           url        ?: "",
                           disclaimer ?: "");

    form = nmt_newt_form_new(_("Certificate Verification"));

    widget = nmt_newt_grid_new();
    nmt_newt_form_set_content(form, widget);
    grid = NMT_NEWT_GRID(widget);

    widget = nmt_newt_textbox_new(0, 72);
    nmt_newt_textbox_set_text(NMT_NEWT_TEXTBOX(widget), text);
    nmt_newt_grid_add(grid, widget, 0, 0);

    bbox = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_HORIZONTAL);
    nmt_newt_grid_add(grid, bbox, 0, 1);
    nmt_newt_widget_set_padding(bbox, 0, 1, 0, 0);

    reject_btn = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), _("Reject"));
    nmt_newt_widget_set_exit_on_activate(reject_btn, TRUE);

    trust_btn = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), _("Trust"));
    g_signal_connect(trust_btn, "activated", G_CALLBACK(trust_activated_cb), form);

    nmt_newt_form_run_sync(form);

    accepted = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(form), "cert-accepted"));
    g_object_unref(form);
    return accepted;
}

/*****************************************************************************/

static void
handle_method_call(GDBusConnection       *conn,
                   const gchar           *sender,
                   const gchar           *object_path,
                   const gchar           *iface,
                   const gchar           *method_name,
                   GVariant              *params,
                   GDBusMethodInvocation *invocation,
                   gpointer               user_data)
{
    if (nm_streq(method_name, "CertificateVerificationRequest")) {
        const char *ssid, *cn, *issuer, *org, *sha256, *exp, *disclaimer, *url;
        gboolean    accepted;

        g_variant_get(params,
                      "(&s&s&s&s&s&s&s&s)",
                      &ssid,
                      &cn,
                      &issuer,
                      &org,
                      &sha256,
                      &exp,
                      &disclaimer,
                      &url);

        accepted = run_cert_dialog(ssid, cn, issuer, org, sha256, exp, disclaimer, url);
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", accepted));
    } else if (nm_streq(method_name, "CertificateVerificationFailure")) {
        const char *ssid, *msg;

        g_variant_get(params, "(&s&s)", &ssid, &msg);
        nmt_newt_message_dialog(_("Certificate verification failed for '%s':\n%s"), ssid, msg);
        g_dbus_method_invocation_return_value(invocation, NULL);
    } else {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_UNKNOWN_METHOD,
                                              "Unknown method: %s",
                                              method_name);
    }
}

static const GDBusInterfaceVTable cert_agent_vtable = {
    .method_call = handle_method_call,
};

/*****************************************************************************/

gboolean
nmt_certificate_agent_register(void)
{
    GDBusNodeInfo      *node_info;
    GDBusInterfaceInfo *iface_info;
    gs_free_error GError      *error = NULL;
    gs_unref_variant GVariant *reply = NULL;

    s_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!s_conn) {
        g_warning("CertificateAgent: cannot get system bus: %s", error->message);
        return FALSE;
    }

    node_info = g_dbus_node_info_new_for_xml(cert_agent_xml, &error);
    if (!node_info) {
        g_warning("CertificateAgent: bad introspection XML: %s", error->message);
        g_clear_object(&s_conn);
        return FALSE;
    }

    iface_info = g_dbus_node_info_lookup_interface(node_info, CERT_AGENT_IFACE);

    s_reg_id = g_dbus_connection_register_object(s_conn,
                                                  CERT_AGENT_OBJECT_PATH,
                                                  iface_info,
                                                  &cert_agent_vtable,
                                                  NULL,
                                                  NULL,
                                                  &error);
    g_dbus_node_info_unref(node_info);

    if (!s_reg_id) {
        g_warning("CertificateAgent: register object failed: %s", error->message);
        g_clear_object(&s_conn);
        return FALSE;
    }

    reply = g_dbus_connection_call_sync(s_conn,
                                        "org.freedesktop.NetworkManager",
                                        "/org/freedesktop/NetworkManager",
                                        "org.freedesktop.NetworkManager",
                                        "RegisterCertificateAgent",
                                        g_variant_new("(o)", CERT_AGENT_OBJECT_PATH),
                                        NULL,
                                        G_DBUS_CALL_FLAGS_NONE,
                                        5000,
                                        NULL,
                                        &error);
    if (!reply) {
        g_warning("CertificateAgent: RegisterCertificateAgent failed: %s", error->message);
        g_dbus_connection_unregister_object(s_conn, s_reg_id);
        s_reg_id = 0;
        g_clear_object(&s_conn);
        return FALSE;
    }

    return TRUE;
}

void
nmt_certificate_agent_unregister(void)
{
    if (!s_conn)
        return;

    g_dbus_connection_call_sync(s_conn,
                                "org.freedesktop.NetworkManager",
                                "/org/freedesktop/NetworkManager",
                                "org.freedesktop.NetworkManager",
                                "UnregisterCertificateAgent",
                                NULL,
                                NULL,
                                G_DBUS_CALL_FLAGS_NONE,
                                2000,
                                NULL,
                                NULL);

    if (s_reg_id) {
        g_dbus_connection_unregister_object(s_conn, s_reg_id);
        s_reg_id = 0;
    }

    g_clear_object(&s_conn);
}
