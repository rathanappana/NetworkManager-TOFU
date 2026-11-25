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

#define LABEL_WIDTH 14

/* The values come from the network. Don't let them add lines to the dialog. */
static void
append_value(GString *text, const char *value)
{
    gsize start = text->len;

    g_string_append(text, value);
    for (; start < text->len; start++) {
        if (g_ascii_iscntrl(text->str[start]))
            text->str[start] = ' ';
    }
}

static void
append_field(GString *text, const char *label, const char *value)
{
    if (!value || !value[0])
        return;

    g_string_append_printf(text, "%-*s ", LABEL_WIDTH, label);
    append_value(text, value);
    g_string_append_c(text, '\n');
}

static void
append_section(GString *text, const char *title)
{
    g_string_append_printf(text, "\n-- %s --\n", title);
}

/* "AA:BB:...": 32 pairs, too long for one line of the dialog. */
static void
append_fingerprint(GString *text, const char *fingerprint)
{
    if (!fingerprint || strlen(fingerprint) != 32 * 3 - 1)
        return;

    g_string_append_printf(text,
                           "%-*s %.47s\n%-*s %s\n",
                           LABEL_WIDTH,
                           _("SHA-256"),
                           fingerprint,
                           LABEL_WIDTH,
                           "",
                           &fingerprint[48]);
}

/* Returns the value of @key in a subject like "/C=BE/O=Example/CN=radius". */
static char *
get_subject_entry(const char *subject, const char *key)
{
    gs_strfreev char **entries = NULL;
    const char        *value   = NULL;
    gsize              len     = strlen(key);
    guint              i;

    if (!subject)
        return NULL;

    entries = g_strsplit(subject, "/", -1);
    for (i = 0; entries[i]; i++) {
        if (strncmp(entries[i], key, len) == 0 && entries[i][len] == '=')
            value = &entries[i][len + 1];
    }
    return g_strdup(value);
}

/* Returns up to two DNS names of the certificate after the first one, which
 * is returned in @out_first. */
static char *
get_dns_names(GVariant *certificate, char **out_first)
{
    gs_free const char **altsubject = NULL;
    GString             *names      = g_string_new(NULL);
    guint                n_names    = 0;
    guint                i;

    if (g_variant_lookup(certificate, "altsubject", "^a&s", &altsubject)) {
        for (i = 0; altsubject[i]; i++) {
            if (!g_str_has_prefix(altsubject[i], "DNS:"))
                continue;
            if (!*out_first) {
                *out_first = g_strdup(&altsubject[i][NM_STRLEN("DNS:")]);
                continue;
            }
            if (n_names++ == 2) {
                g_string_append(names, _(", ..."));
                break;
            }
            if (names->len)
                g_string_append(names, ", ");
            g_string_append(names, &altsubject[i][NM_STRLEN("DNS:")]);
        }
    }
    return g_string_free(names, FALSE);
}

static char *
get_chain_description(GVariant *certificate)
{
    gs_unref_variant GVariant *cas = NULL;
    gsize                      n   = 0;

    cas = g_variant_lookup_value(certificate, "ca-certificates", G_VARIANT_TYPE("aay"));
    if (cas)
        n = g_variant_n_children(cas);

    if (n == 0)
        return g_strdup(_("server certificate only"));
    return g_strdup_printf(g_dngettext(GETTEXT_PACKAGE,
                                       "server certificate and %u CA certificate",
                                       "server certificate and %u CA certificates",
                                       n),
                           (guint) n);
}

typedef enum {
    ANSWER_NONE,
    ANSWER_REJECTED,
    ANSWER_TRUSTED,
} Answer;

static void
answer_activated(NmtNewtWidget *button, gpointer user_data)
{
    Answer *answer = user_data;

    *answer = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "answer"));
}

/* Leaving the dialog without pressing a button is no answer. */
static Answer
ask_to_trust(const char *connection_path, GVariant *certificate)
{
    nm_auto_free_gstring GString *text              = g_string_new(NULL);
    gs_unref_variant GVariant    *ssid              = NULL;
    gs_free char                 *ssid_str          = NULL;
    gs_free char                 *dns_names         = NULL;
    gs_free char                 *server_name       = NULL;
    gs_free char                 *name              = NULL;
    gs_free char                 *organization      = NULL;
    gs_free char                 *unit              = NULL;
    gs_free char                 *country           = NULL;
    gs_free char                 *chain             = NULL;
    gs_free char                 *remembered        = NULL;
    gs_free char                 *organization_line = NULL;
    const char                   *connection_id     = NULL;
    const char                   *fingerprint       = NULL;
    const char                   *subject           = NULL;
    const char                   *anchor            = NULL;
    gboolean                      changed           = FALSE;
    gboolean                      system_trusted    = FALSE;
    NMRemoteConnection           *connection;
    NmtNewtWidget                *grid, *textbox, *bbox, *button;
    Answer                        answer = ANSWER_NONE;

    connection = nm_client_get_connection_by_path(nm_client, connection_path);
    if (connection)
        connection_id = nm_connection_get_id(NM_CONNECTION(connection));
    ssid = g_variant_lookup_value(certificate, "ssid", G_VARIANT_TYPE_BYTESTRING);
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
    dns_names    = get_dns_names(certificate, &server_name);
    name         = get_subject_entry(subject, "CN");
    organization = get_subject_entry(subject, "O");
    unit         = get_subject_entry(subject, "OU");
    country      = get_subject_entry(subject, "C");
    chain        = get_chain_description(certificate);
    if (!server_name)
        server_name = g_strdup(name);

    /* Keep it within 24 lines of the terminal, together with the buttons. */
    if (changed) {
        g_string_append(text,
                        _("WARNING: the server renewed it, or someone is impersonating it.\n\n"));
    }

    append_field(text, _("Network"), ssid_str);
    if (!nm_streq0(connection_id, ssid_str))
        append_field(text, _("Connection"), connection_id);

    append_section(text, _("Server certificate"));
    /* The name that is remembered with a CA, like NetworkManager chooses it. */
    append_field(text, _("Server"), server_name);
    if (!nm_streq0(name, server_name))
        append_field(text, _("Certificate"), name);
    append_field(text, _("Also valid for"), dns_names);
    if (organization) {
        organization_line =
            g_strjoin(", ", organization, unit ?: country, unit ? country : NULL, NULL);
        append_field(text, _("Organization"), organization_line);
    }
    /* Without the usual entries, show the subject as it is. */
    if (!name && !organization)
        append_field(text, _("Subject"), subject);
    append_fingerprint(text, fingerprint);
    append_field(text, _("Sent"), chain);
    if (system_trusted)
        append_field(text, _("Issued by"), _("a CA this system trusts (not a proof)"));

    /* What NetworkManager stores in the profile if the user trusts it. */
    if (anchor) {
        g_string_append_c(text, '\n');
        if (nm_streq(anchor, "server-certificate")) {
            append_field(text, _("If trusted"), _("this certificate, until the server renews it"));
        } else {
            append_field(text,
                         _("If trusted"),
                         nm_streq(anchor, "system-ca") ? _("the CA of this system that issued it")
                                                       : _("the root CA that the server sent"));
            if (server_name) {
                remembered = g_strdup_printf(_("for the server name %s"), server_name);
                append_field(text, "", remembered);
            }
        }
    }

    g_string_append(text,
                    _("\nTrust it only if the fingerprint matches your network administrator's."));

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

    /* NetworkManager deletes a connection that was never trusted, if the
     * user rejects its server. */
    button = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox),
                                         changed ? _("Reject") : _("Reject and Forget"));
    nmt_newt_widget_set_exit_on_activate(button, TRUE);
    g_object_set_data(G_OBJECT(button), "answer", GINT_TO_POINTER(ANSWER_REJECTED));
    g_signal_connect(button, "activated", G_CALLBACK(answer_activated), &answer);

    button = nmt_newt_button_box_add_end(NMT_NEWT_BUTTON_BOX(bbox), _("Trust"));
    nmt_newt_widget_set_exit_on_activate(button, TRUE);
    g_object_set_data(G_OBJECT(button), "answer", GINT_TO_POINTER(ANSWER_TRUSTED));
    g_signal_connect(button, "activated", G_CALLBACK(answer_activated), &answer);

    nmt_newt_form_run_sync(pending.form);
    g_clear_object(&pending.form);
    return answer;
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
    Answer                     answer;

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

    answer = ask_to_trust(connection_path, certificate);

    nm_clear_g_free(&pending.connection_path);
    if (pending.cancelled) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      G_IO_ERROR,
                                                      G_IO_ERROR_CANCELLED,
                                                      "Cancelled by NetworkManager");
        return;
    }
    if (answer == ANSWER_NONE) {
        g_dbus_method_invocation_return_error_literal(invocation,
                                                      NM_SECRET_AGENT_ERROR,
                                                      NM_SECRET_AGENT_ERROR_USER_CANCELED,
                                                      "Dismissed by the user");
        return;
    }
    g_dbus_method_invocation_return_value(invocation,
                                          g_variant_new("(b)", answer == ANSWER_TRUSTED));
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
