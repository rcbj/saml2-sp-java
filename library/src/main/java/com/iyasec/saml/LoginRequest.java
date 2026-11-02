// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.util.Map;

/** A signed AuthnRequest, either as a redirect URL or as an HTTP-POST form. */
public class LoginRequest {
    public String id;
    public String binding;
    public String responseBinding;
    public String url;
    public String xml;
    public Map<String, String> fields;
    public String html;
}
