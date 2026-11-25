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

    /**
     * Attributes the subject's id is read from, in order: {@code username},
     * else {@code preferred_username}, else iya-sts's spellings of the username
     * (the X.500 {@code uid} OID, the bare {@code uid}, and the AD FS name claim).
     */
    public static final List<String> USERNAME_ATTRIBUTES = List.of(
        "username",
        "preferred_username",
        "urn:oid:0.9.2342.19200300.100.1.1",
        "uid",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    );

    /**
     * The username: the first non-empty value of the first of
     * {@link #USERNAME_ATTRIBUTES} the assertion carries, or null when it
     * carries none. A transient NameID is not a username.
     */
    public String username() {
        if (attributes == null) return null;
        for (String name : USERNAME_ATTRIBUTES) {
            List<String> values = attributes.get(name);
            if (values == null) continue;
            for (String value : values) {
                if (value != null && !value.isEmpty()) return value;
            }
        }
        return null;
    }
}
