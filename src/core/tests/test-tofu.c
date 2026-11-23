/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-test-utils-core.h"
#include "tofu/nm-tofu.h"

#define TEST_CERT_PATH NM_BUILD_SRCDIR "/src/libnm-core-impl/tests/certs/test_ca_cert.der"

static void
test_session_state(void)
{
    NMToFuSession *session = nm_tofu_session_get();
    gpointer       logging;

    logging = nmtst_logging_disable(TRUE);

    nm_tofu_session_reset(session);
    g_assert_cmpint(nm_tofu_session_get_session_type(session), ==, NM_TOFU_SESSION_TYPE_DEFAULT);

    nm_tofu_session_set(session, NM_TOFU_SESSION_TYPE_TOFU, "test-ssid", "test-uuid", NULL);
    g_assert_cmpint(nm_tofu_session_get_session_type(session), ==, NM_TOFU_SESSION_TYPE_TOFU);
    g_assert_cmpstr(nm_tofu_session_get_ssid(session), ==, "test-ssid");
    g_assert_cmpstr(nm_tofu_session_get_uuid(session), ==, "test-uuid");

    nm_tofu_session_reset(session);
    g_assert_cmpint(nm_tofu_session_get_session_type(session), ==, NM_TOFU_SESSION_TYPE_DEFAULT);
    g_assert_null(nm_tofu_session_get_ssid(session));
    g_assert_null(nm_tofu_session_get_uuid(session));

    nmtst_logging_reenable(logging);
}

static GVariant *
build_cert_signal(guint depth, const char *subject, const char *hash, GBytes *cert_data)
{
    GVariantBuilder builder;
    gsize           cert_len;
    gconstpointer   cert_bytes;

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&builder, "{sv}", "depth", g_variant_new_uint32(depth));
    if (subject)
        g_variant_builder_add(&builder, "{sv}", "subject", g_variant_new_string(subject));
    if (hash)
        g_variant_builder_add(&builder, "{sv}", "cert_hash", g_variant_new_string(hash));
    if (cert_data) {
        cert_bytes = g_bytes_get_data(cert_data, &cert_len);
        g_variant_builder_add(
            &builder,
            "{sv}",
            "cert",
            g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, cert_bytes, cert_len, sizeof(guint8)));
    }

    return g_variant_new("(@a{sv})", g_variant_builder_end(&builder));
}

static void
stage3_ready_cb(NMToFuSession *session, gpointer user_data)
{
    guint *count = user_data;

    (*count)++;
}

static void
test_certificate_collection(void)
{
    gs_free char              *contents               = NULL;
    gs_unref_bytes GBytes     *cert_data              = NULL;
    gs_unref_variant GVariant *invalid_signal         = NULL;
    gs_unref_variant GVariant *missing_subject_signal = NULL;
    gs_unref_variant GVariant *intermediate_signal    = NULL;
    gs_unref_variant GVariant *cert_signal            = NULL;
    gs_free char              *cn                     = NULL;
    gs_free char              *issuer                 = NULL;
    gs_free char              *org                    = NULL;
    gs_free char              *sha256                 = NULL;
    gs_free char              *expiration             = NULL;
    gs_free char              *url                    = NULL;
    NMToFuSession             *session                = nm_tofu_session_get();
    GBytes                    *root_der;
    const char                *leaf_hash;
    gs_free char              *domain = NULL;
    gsize                      contents_len;
    guint                      stage3_ready_count = 0;
    gulong                     signal_id;
    gpointer                   logging;

    g_assert_true(g_file_get_contents(TEST_CERT_PATH, &contents, &contents_len, NULL));
    cert_data = g_bytes_new(contents, contents_len);

    logging = nmtst_logging_disable(TRUE);

    nm_tofu_session_reset(session);
    nm_tofu_session_set(session, NM_TOFU_SESSION_TYPE_TOFU, "test-ssid", "test-uuid", NULL);
    signal_id =
        g_signal_connect(session, "stage3-ready", G_CALLBACK(stage3_ready_cb), &stage3_ready_count);

    invalid_signal = build_cert_signal(0, "CN=test", NULL, cert_data);
    nm_tofu_stage2_cert_signal(session, invalid_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 0);

    missing_subject_signal = build_cert_signal(0, NULL, "test-cert-hash", cert_data);
    nm_tofu_stage2_cert_signal(session, missing_subject_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 0);

    intermediate_signal = build_cert_signal(1, "CN=test", "test-root-hash", cert_data);
    nm_tofu_stage2_cert_signal(session, intermediate_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 0);

    cert_signal = build_cert_signal(0, "CN=test", "test-cert-hash", cert_data);
    nm_tofu_stage2_cert_signal(session, cert_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 1);

    nm_tofu_stage2_cert_signal(session, cert_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 1);

    g_assert_true(nm_tofu_session_get_display_fields(session,
                                                     &cn,
                                                     &issuer,
                                                     &org,
                                                     &sha256,
                                                     &expiration,
                                                     &url));
    g_assert_cmpstr(cn, ==, "test");
    g_assert_cmpstr(issuer, ==, "test");
    g_assert_cmpstr(org, ==, "My Company Ltd");
    g_assert_cmpuint(strlen(sha256), ==, 64);
    g_assert_nonnull(expiration);
    g_assert_cmpstr(url, ==, "test");

    nm_tofu_session_get_pin_data(session, &root_der, &leaf_hash, (const char **) &domain);
    g_assert_nonnull(root_der);
    g_assert_true(g_bytes_equal(root_der, cert_data));
    g_assert_cmpstr(leaf_hash, ==, "test-cert-hash");
    g_assert_cmpstr(domain, ==, "test");

    g_signal_handler_disconnect(session, signal_id);
    nm_tofu_session_reset(session);
    nm_clear_g_free(&domain);
    g_assert_false(nm_tofu_session_get_display_fields(session, NULL, NULL, NULL, NULL, NULL, NULL));

    stage3_ready_count = 0;
    nm_tofu_stage2_cert_signal(session, cert_signal);
    g_assert_cmpuint(stage3_ready_count, ==, 0);
    nmtst_logging_reenable(logging);
}

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init_assert_logging(&argc, &argv, "INFO", "DEFAULT");

    g_test_add_func("/tofu/session-state", test_session_state);
    g_test_add_func("/tofu/certificate-collection", test_certificate_collection);

    return g_test_run();
}
