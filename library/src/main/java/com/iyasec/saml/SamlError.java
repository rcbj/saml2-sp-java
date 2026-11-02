// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

/** Every failure this package reports is one of these. */
public class SamlError extends RuntimeException {
    public final String code;
    public final SamlStatus status;

    public SamlError(String code, String message) {
        this(code, message, null, null);
    }

    public SamlError(String code, String message, Throwable cause) {
        this(code, message, cause, null);
    }

    public SamlError(String code, String message, SamlStatus status) {
        this(code, message, null, status);
    }

    public SamlError(String code, String message, Throwable cause, SamlStatus status) {
        super(message, cause);
        this.code = code;
        this.status = status;
    }
}
