/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#ifndef NM_CERTIFICATE_AGENT_H
#define NM_CERTIFICATE_AGENT_H

#include <gio/gio.h>

/* Timeout waiting for the agent UI to respond: 3 minutes. */
#define NM_CERT_AGENT_TIMEOUT_MS 180000

/**
 * NMCertAgentResponseFunc:
 * @accepted: TRUE if the user accepted the certificate, FALSE otherwise
 * @ssid: the network SSID this response is for
 * @user_data: caller-supplied data
 *
 * Callback invoked when the certificate agent returns a response or
 * when the call fails (in which case @accepted is FALSE).
 */
typedef void (*NMCertAgentResponseFunc)(gboolean    accepted,
                                        const char *ssid,
                                        gpointer    user_data);

gboolean nm_certificate_agent_register(GDBusConnection       *conn,
                                       const char            *sender_unique,
                                       const char            *object_path,
                                       GDBusMethodInvocation *invocation);

gboolean nm_certificate_agent_unregister(GDBusConnection       *conn,
                                         const char            *sender_unique,
                                         GDBusMethodInvocation *invocation);

/* Pick the best registered agent.  Returns FALSE if none available. */
gboolean nm_certificate_agent_pick(char **out_unique, char **out_object_path);

/* Async call to CertificateVerificationRequest on the best agent. */
void nm_certificate_agent_call_request(GDBusConnection        *conn,
                                       const char             *ssid,
                                       const char             *cn,
                                       const char             *issuer,
                                       const char             *org,
                                       const char             *sha256,
                                       const char             *exp,
                                       const char             *disclaimer,
                                       const char             *url,
                                       NMCertAgentResponseFunc callback,
                                       gpointer                user_data);

/* Fire-and-forget notification to the agent that verification failed. */
void nm_certificate_agent_notify_failure(GDBusConnection *conn,
                                         const char      *ssid,
                                         const char      *message);

#endif /* NM_CERTIFICATE_AGENT_H */
