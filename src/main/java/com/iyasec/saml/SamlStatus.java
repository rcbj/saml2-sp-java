// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

/** A non-success status an identity provider answered with. */
public class SamlStatus {
    public final String code;
    public String subCode;
    public String message;

    public SamlStatus(String code) {
        this.code = code;
    }
}
