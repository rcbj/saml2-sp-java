// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

/** Options for {@link ServiceProvider#login}. Unset strings stay null and booleans stay false. */
public class LoginOptions {
    public String relayState;
    public boolean forceAuthn;
    public boolean isPassive;
    public String subjectHint;
    public String subjectHintFormat;
    public String requestBinding;
    public String responseBinding;
    public String nonce;
}
