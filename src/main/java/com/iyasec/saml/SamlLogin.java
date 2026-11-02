// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** What a successful assertion consumer call returns. */
public class SamlLogin {
    public String nameId;
    public String nameIdFormat;
    public String nameQualifier;
    public String spNameQualifier;
    public String sessionIndex;
    public Instant sessionNotOnOrAfter;
    public Instant authnInstant;
    public String authnContextClassRef;
    public Map<String, List<String>> attributes = new LinkedHashMap<>();
    public Map<String, String> attributeFriendlyNames = new LinkedHashMap<>();
    public String issuer;
    public String inResponseTo;
    public String relayState;
    public String binding;
    public boolean encrypted;
    public String responseId;
    public String assertionId;
}
