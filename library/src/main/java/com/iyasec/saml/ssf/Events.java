// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CAEP, RISC and SSF event types, and what an event's subject names. */
public final class Events {
    public static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    public static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";
    public static final String SSF = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static final Map<String, String> EVENT = new LinkedHashMap<>();
    public static final List<String> CAEP_EVENTS;
    public static final List<String> RISC_EVENTS;
    public static final List<String> DEFAULT_EVENTS_REQUESTED;
    public static final List<String> DEFAULT_ENDING_EVENTS;

    static {
        EVENT.put("session_revoked", CAEP + "session-revoked");
        EVENT.put("token_claims_change", CAEP + "token-claims-change");
        EVENT.put("credential_change", CAEP + "credential-change");
        EVENT.put("assurance_level_change", CAEP + "assurance-level-change");
        EVENT.put("device_compliance_change", CAEP + "device-compliance-change");
        EVENT.put("session_established", CAEP + "session-established");
        EVENT.put("session_presented", CAEP + "session-presented");
        EVENT.put("risk_level_change", CAEP + "risk-level-change");
        EVENT.put("account_credential_change_required", RISC + "account-credential-change-required");
        EVENT.put("account_purged", RISC + "account-purged");
        EVENT.put("account_disabled", RISC + "account-disabled");
        EVENT.put("account_enabled", RISC + "account-enabled");
        EVENT.put("identifier_changed", RISC + "identifier-changed");
        EVENT.put("identifier_recycled", RISC + "identifier-recycled");
        EVENT.put("credential_compromise", RISC + "credential-compromise");
        EVENT.put("opt_in", RISC + "opt-in");
        EVENT.put("opt_out_initiated", RISC + "opt-out-initiated");
        EVENT.put("opt_out_cancelled", RISC + "opt-out-cancelled");
        EVENT.put("opt_out_effective", RISC + "opt-out-effective");
        EVENT.put("recovery_activated", RISC + "recovery-activated");
        EVENT.put("recovery_information_changed", RISC + "recovery-information-changed");
        EVENT.put("sessions_revoked", RISC + "sessions-revoked");
        EVENT.put("verification", SSF + "verification");
        EVENT.put("stream_updated", SSF + "stream-updated");
        CAEP_EVENTS = EVENT.values().stream().filter(value -> value.startsWith(CAEP)).toList();
        RISC_EVENTS = EVENT.values().stream().filter(value -> value.startsWith(RISC)).toList();
        DEFAULT_EVENTS_REQUESTED = List.of(
            EVENT.get("session_revoked"), EVENT.get("credential_change"), EVENT.get("assurance_level_change"),
            EVENT.get("token_claims_change"), EVENT.get("account_disabled"), EVENT.get("account_enabled"),
            EVENT.get("account_purged"), EVENT.get("credential_compromise"), EVENT.get("sessions_revoked"),
            EVENT.get("account_credential_change_required")
        );
        DEFAULT_ENDING_EVENTS = List.of(
            EVENT.get("session_revoked"), EVENT.get("account_disabled"), EVENT.get("account_purged"),
            EVENT.get("credential_compromise"), EVENT.get("sessions_revoked")
        );
    }

    private Events() {}

    public static Map<String, String> subjectOf(Object subId, String issuer) {
        if (!(subId instanceof Map<?, ?> subject)) return Map.of();
        String form = str(subject.get("format"), subject.get("subject_type"));
        if ("complex".equals(form) || (form.isEmpty() && (subject.get("user") != null || subject.get("session") != null))) {
            Map<String, String> user = simple(subject.get("user"), issuer);
            Map<String, String> session = simple(subject.get("session"), issuer);
            Map<String, String> out = new LinkedHashMap<>();
            if (user.get("sub") != null) out.put("person", user.get("sub"));
            if (user.get("email") != null) out.put("email", user.get("email"));
            String sessionId = session.get("opaque") != null ? session.get("opaque") : session.get("sub");
            if (sessionId != null) out.put("idpSession", sessionId);
            return out;
        }
        Map<String, String> one = simple(subject, issuer);
        Map<String, String> out = new LinkedHashMap<>();
        if (one.get("sub") != null) out.put("person", one.get("sub"));
        if (one.get("email") != null) out.put("email", one.get("email"));
        return out;
    }

    private static Map<String, String> simple(Object identifier, String issuer) {
        if (!(identifier instanceof Map<?, ?> map)) return Map.of();
        String form = str(map.get("format"), map.get("subject_type"));
        Map<String, String> out = new LinkedHashMap<>();
        if ("iss_sub".equals(form) && map.get("sub") instanceof String sub && (map.get("iss") == null || issuer.equals(map.get("iss")))) {
            out.put("sub", sub);
        } else if ("email".equals(form) && map.get("email") instanceof String email) {
            out.put("email", email);
        } else if ("opaque".equals(form) && map.get("id") instanceof String id) {
            out.put("opaque", id);
        } else if ("aliases".equals(form) && map.get("identifiers") instanceof List<?> identifiers) {
            for (Object item : identifiers) out.putAll(simple(item, issuer));
        }
        return out;
    }

    private static String str(Object first, Object second) {
        Object value = first != null ? first : second;
        return value == null ? "" : String.valueOf(value);
    }

    static List<String> copy(List<String> values) {
        return new ArrayList<>(values);
    }
}
