// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.ssf;

import com.iyasec.saml.SamlLogin;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Which of the application's own sessions belong to which person and identity-provider session. */
public final class MemorySessionIndex {
    public static final String DEFAULT_SUBJECT_ATTRIBUTE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    public static final List<String> MAIL_ATTRIBUTES = List.of(
        "urn:oid:0.9.2342.19200300.100.1.3",
        "mail",
        "email",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    );
    public static final String EMAIL_NAMEID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    private final Map<String, Tracked> sessions = new LinkedHashMap<>();
    private final int max;
    private final Object lock = new Object();

    public MemorySessionIndex() { this(100_000); }

    public MemorySessionIndex(int max) { this.max = max; }

    public void add(Tracked session) {
        synchronized (lock) {
            if (sessions.size() >= max && !sessions.containsKey(session.localId)) {
                long now = Instant.now().toEpochMilli();
                List<String> expired = new ArrayList<>();
                sessions.forEach((key, value) -> {
                    if (value.expiresAt != null && value.expiresAt.toEpochMilli() <= now) expired.add(key);
                });
                expired.forEach(sessions::remove);
                while (sessions.size() >= max) sessions.remove(sessions.keySet().iterator().next());
            }
            sessions.put(session.localId, session.email == null ? session : session.withEmail(session.email.toLowerCase()));
        }
    }

    public void remove(String localId) {
        synchronized (lock) { sessions.remove(localId); }
    }

    public List<String> byPerson(String person) {
        synchronized (lock) { return find(session -> person.equals(session.person)); }
    }

    public List<String> byEmail(String email) {
        String wanted = email.toLowerCase();
        synchronized (lock) { return find(session -> wanted.equals(session.email)); }
    }

    public List<String> byIdpSession(String idpSession) {
        synchronized (lock) { return find(session -> idpSession.equals(session.idpSession)); }
    }

    private List<String> find(Predicate<Tracked> match) {
        long now = Instant.now().toEpochMilli();
        List<String> out = new ArrayList<>();
        List<String> expired = new ArrayList<>();
        sessions.forEach((key, value) -> {
            if (value.expiresAt != null && value.expiresAt.toEpochMilli() <= now) expired.add(key);
            else if (match.test(value)) out.add(key);
        });
        expired.forEach(sessions::remove);
        return out;
    }

    public static Tracked trackedFrom(String localId, SamlLogin login, String subjectAttribute, Instant expiresAt) {
        String attribute = subjectAttribute == null || subjectAttribute.isEmpty() ? DEFAULT_SUBJECT_ATTRIBUTE : subjectAttribute;
        String person = first(login, attribute);
        String email = null;
        for (String name : MAIL_ATTRIBUTES) {
            String value = first(login, name);
            if (value != null) {
                email = value;
                break;
            }
        }
        if (email == null && EMAIL_NAMEID.equals(login.nameIdFormat)) email = login.nameId;
        return new Tracked(localId, person, email, login.sessionIndex, expiresAt != null ? expiresAt : login.sessionNotOnOrAfter);
    }

    private static String first(SamlLogin login, String name) {
        if (login.attributes == null) return null;
        List<String> values = login.attributes.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    public record Tracked(String localId, String person, String email, String idpSession, Instant expiresAt) {
        Tracked withEmail(String lowered) {
            return new Tracked(localId, person, lowered, idpSession, expiresAt);
        }
    }
}
