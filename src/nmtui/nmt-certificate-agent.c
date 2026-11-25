/* SPDX-License-Identifier: GPL-2.0-or-later */

/**
 * SECTION:nmt-certificate-agent
 * @short_description: Lets the user trust 802.1X server certificates
 *
 * Implements the org.freedesktop.NetworkManager.CertificateAgent D-Bus
 * interface. It must be exported on the connection of a secret agent that
 * registered with %NM_SECRET_AGENT_CAPABILITY_TRUST_ON_FIRST_USE.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmt-certificate-agent.h"

#include "libnmt-newt/nmt-newt.h"
#include "nmtui.h"

static const char introspection_xml[] =
    "<node>"
    "  <interface name='" NM_DBUS_INTERFACE_CERTIFICATE_AGENT "'>"
    "    <method name='ConfirmServerCertificate'>"
    "      <arg name='connection_path' type='o' direction='in'/>"
    "      <arg name='certificate' type='a{sv}' direction='in'/>"
    "      <arg name='trusted' type='b' direction='out'/>"
    "    </method>"
    "    <method name='CancelConfirmServerCertificate'>"
    "      <arg name='connection_path' type='o' direction='in'/>"
    "    </method>"
    "  </interface>"
    "</node>";

/* The request whose dialog is shown. Only one is handled at a time. */
static struct {
    char        *connection_path;
    NmtNewtForm *form;
    gboolean     cancelled;
} pending;

/* The values come from the network. Don't let them add lines to the dialog. */
static void
append_field(GString *text, const char *label, const char *value)
{
    gsize start;

    if (!value || !value[0])
        return;

    g_string_append_printf(text, "%-14s ", label);
    start = text->len;
    g_string_append(text, value);
    for (; start < text->len; start++) {
        if (g_ascii_iscntrl(text->str[start]))
            text->str[start] = ' ';
    }
    g_string_append_c(text, '\n');
}

/* "AA:BB:...": 32 pairs, too long for one line of the dialog. */
static void
append_fingerprint(GString *text, const char *fingerprint)
{
    if (!fingerprint || strlen(fingerprint) != 32 * 3 - 1)
        return;

    g_string_append_printf(text,
                           "%s\n  %.47s\n  %s\n",
                           _("SHA-256 fingerprint:"),
                           fingerprint,
                           &fingerprint[48]);
}

static char *
get_dns_names(GVariant *certificate)
{
    gs_free const char **altsubject = NULL;
    GString             *names      = g_string_new(NULL);
    guint                i;

    if (g_variant_lookup(certificate, "altsubject", "^a&s", &altsubject)) {
        for (i = 0; altsubject[i]; i++) {
            if (g_str_has_prefix(altsubject[i], "DNS:")) {
                if (names->len)
                    g_string_append(names, ", ");
                g_string_append(names, &altsubject[i][NM_STRLEN("DNS:")]);
            }
        }
    }
    return g_string_free(names, FALSE);
}

static void
trust_activated(NmtNewtWidget *button, gpointer user_data)
{
    gboolean *trusted = user_data;

    *trusted = TRUE;
}

static gboolean
ask_to_trust(const char *connection_path, GVariant *certificate)
{
    nm_auto_free_gstring GString *text           = g_string_new(NULL);
    gs_unref_variant GVariant    *ssid           = NULL;
    gs_free char                 *ssid_str       = NULL;
    gs_free char                 *dns_names      = NULL;
    const char                   *fingerprint    = NULL;
    const char                   *subject        = NULL;
    const char                   *anchor         = NULL;
    gboolean                      changed        = FALSE;
    gboolean                      system_trusted = FALSE;
    NMRemoteConnection           *connection;
    NmtNewtWidget                *grid, *textbox, *bbox, *button;
    gboolean                      trusted = FALSE;

    connection = nm_client_get_connection_by_path(nm_client, connection_path);
    ssid       = g_variant_lookup_value(certificate, "ssid", G_VARIANT_TYPE_BYTESTRING);
    if (ssid) {
        gsize         len;
        gconstpointer data = g_variant_get_fixed_array(ssid, &len, 1);

        ssid_str = nm_utils_ssid_to_utf8(data, len);
    }
    g_variant_lookup(certificate, "fingerprint", "&s", &fingerprint);
    g_variant_lookup(certificate, "subject", "&s", &subject);
    g_variant_lookup(certificate, "trust-anchor", "&s", &anchor);
    g_variant_lookup(certificate, "changed", "b", &changed);
    g_variant_lookup(certificate, "system-trusted", "b", &system_trusted);
    dns_names = get_dns_names(certificate);

    if (changed) {
        g_string_append(text,
                        _("WARNING: the authentication server presented a different certificate "
                          "than the one you trusted before. Servers renew their certificates, "
                          "but this may also be an attacker impersonating the network.\n\n"));
    } else {
        g_string_append(text,
                        _("The authentication server presented a certificate that cannot be "
                          "verified yet.\n\n"));
    }
    g_string_append(text,
                    _("Only trust it if its fingerprint matches the one published by your "
                      "network administrator.\n\n"));
    append_fingerprint(text, fingerprint);
    append_field(text,
                 _("Connection:"),
                 connection ? nm_connection_get_id(NM_CONNECTION(connection)) : NULL);
    append_field(text, _("Network:"), ssid_str);
    append_field(text, _("Server:"), dns_names);
    append_field(text, _("Subject:"), subject);

    if (system_trusted) {
        g_string_append(text,
                        _("\nThe certificate is issued by a CA that this system trusts. This "
                          "supports, but does not prove, that the server is genuine.\n"));
    }
    if (nm_streq0(anchor, "server-certificate")) {
        g_string_append(text,
                        _("\nIf you trust it, only this certificate will be accepted. You will "
                          "be asked again when the server changes it.\n"));
    } else if (anchor) {
        g_string_append(text,
                        _("\nIf you trust it, certificates for this server name from the same "
                          "CA will be accepted, so that the server can renew it.\n"));
    }

    pending.form = nmt_newt_form_new(changed ? _("Server certificate changed!")
                                             : _("Trust server certificate?"));
    grid         = nmt_newt_grid_new();
    nmt_newt_form_set_content(pending.form, grid);

    textbox = nmt_newt_textbox_new(0, 72);
    nmt_newt_textbox_set_text(NMT_NEWT_TEXTBOX(textbox), text->str);
    nmt_newt_grid_add(NMT_NEWT_GRID(grid), textbox, 0, 0);

    bbox = nmt_newt_button_box_new(NMT_NEWT_BUTTON_BOX_HORIZONTAL);
    nmt_newt_widget_set_padding(bbox, 0, 1, 0, 0);
    nmt_newt_grid_add(NMT_NEWT_GRID(grid), bbox, 0, 1);

    button = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), _("Reject"));
    nmt_newt_widget_set_exit_on_activate(button, TRUE);

    button = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), _("Trust"));
    nmt_newt_widget_set_exit_on_activate(button, TRUE);
    g_signal_connect(button, "activated", G_CALLBACK(trust_activated), &trusted);

    nmt_newt_form_run_sync(pending.form);
    g_clear_object(&pending.form);
    return trusted;
}

static void
method_call(GDBusConnection       *dbus_connection,
            const char            *sender,
            const char            *object_path,
            const char            *interface_name,
            const char            *method_name,
            GVariant              *parameters,
            GDBusMethodInvocation *invocation,
            gpointer               user_data)
{
    gs_unref_variant GVariant *certificate = NULL;
    const char                *connection_path;
    gboolean                   trusted;

    if (!nm_streq0(sender, nm_client_get_dbus_name_owner(nm_client))) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      G_DBUS_ERROR,
                                                      G_DBUS_ERROR_ACCESS_DENIED,
                                                      "Only NetworkManager may call this method");
        return;
    }

    if (nm_streq(method_name, "CancelConfirmServerCertificate")) {
        g_variant_get(parameters, "(&o)", &connection_path);
        if (pending.form && nm_streq0(pending.connection_path, connection_path)) {
            pending.cancelled = TRUE;
            nmt_newt_form_quit(pending.form);
        }
        g_dbus_method_invocation_return_value(invocation, NULL);
        return;
    }

    if (pending.form) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      G_DBUS_ERROR,
                                                      G_DBUS_ERROR_LIMITS_EXCEEDED,
                                                      "Another certificate is being confirmed");
        return;
    }

    g_variant_get(parameters, "(&o@a{sv})", &connection_path, &certificate);
    pending.connection_path = g_strdup(connection_path);
    pending.cancelled       = FALSE;

    trusted = ask_to_trust(connection_path, certificate);

    nm_clear_g_free(&pending.connection_path);
    if (pending.cancelled) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      G_IO_ERROR,
                                                      G_IO_ERROR_CANCELLED,
                                                      "Cancelled by NetworkManager");
        return;
    }
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", trusted));
}

/**
 * nmt_certificate_agent_export:
 * @dbus_connection: the D-Bus connection of the secret agent
 *
 * Exports the certificate agent object on @dbus_connection.
 *
 * Returns: the registration id for g_dbus_connection_unregister_object(),
 *   or 0 on failure.
 */
guint
nmt_certificate_agent_export(GDBusConnection *dbus_connection)
{
    static const GDBusInterfaceVTable vtable    = {.method_call = method_call};
    gs_free_error GError             *error     = NULL;
    GDBusNodeInfo                    *node_info = NULL;
    guint                             id;

    node_info = g_dbus_node_info_new_for_xml(introspection_xml, NULL);
    nm_assert(node_info);

    id = g_dbus_connection_register_object(dbus_connection,
                                           NM_DBUS_PATH_CERTIFICATE_AGENT,
                                           node_info->interfaces[0],
                                           &vtable,
                                           NULL,
                                           NULL,
                                           &error);
    g_dbus_node_info_unref(node_info);

    if (!id)
        g_warning("Could not export the certificate agent: %s", error->message);
    return id;
}
