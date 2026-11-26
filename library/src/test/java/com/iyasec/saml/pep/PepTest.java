// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.pep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.saml.Config;
import com.iyasec.saml.Keys;
import com.iyasec.saml.SamlError;
import com.iyasec.saml.SamlLogin;
import com.iyasec.saml.ServiceProvider;
import com.iyasec.saml.StubIdp;
import com.iyasec.saml.ssf.MemorySessionIndex;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The embedded PEP's SAML wiring. Nothing here calls {@code Pep.start}. */
class PepTest {
    @Test
    void usernamePrefersTheFirstAttributeThenFallsThrough() {
        SamlLogin login = new SamlLogin();
        assertNull(login.username());
        login.attributes.put("uid", List.of(""));
        login.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", List.of("adfs"));
        assertEquals("adfs", login.username());
        login.attributes.put("preferred_username", List.of("preferred"));
        assertEquals("preferred", login.username());
        login.attributes.put("username", List.of("real"));
        assertEquals("real", login.username());
        login.attributes.put("urn:oid:0.9.2342.19200300.100.1.1", List.of("ldap"));
        assertEquals("real", login.username());
    }

    @Test
    void subjectIdIsTheUsernameElseTheNameId() {
        SamlLogin login = new SamlLogin();
        login.nameId = "transient-handle";
        login.attributes.put("mail", List.of("a@b.test"));
        login.attributeFriendlyNames.put("mail", "email");
        login.authnContextClassRef = "urn:example:acr";
        login.authnInstant = Instant.ofEpochSecond(1_700_000_000L);
        login.attributes.put("amr", List.of("pwd"));
        var subject = SamlPep.subjectOf(login);
        assertEquals("transient-handle", subject.id);
        assertEquals("a@b.test", subject.properties.get("mail").asText());
        assertEquals("a@b.test", subject.properties.get("email").asText());
        assertEquals("urn:example:acr", subject.properties.get("acr").asText());
        assertEquals(1_700_000_000L, subject.properties.get("auth_time").asLong());
        assertEquals("pwd", subject.properties.get("amr").get(0).asText());
        login.attributes.put("uid", List.of("alice"));
        assertEquals("alice", SamlPep.subjectOf(login).id);
    }

    @Test
    void pepSectionDefaultsDoNotBuildAPep() throws Exception {
        Path dir = Files.createTempDirectory("saml-pep");
        String ca = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        Map<String, Object> config = base();
        config.put("idpCa", ca);
        config.put("ssf", Map.of("transmitter", "https://idp.test"));
        config.put("pep", Map.of("name", "pep-test", "assertionKey", "generated/pep-key.pem"));
        Config.Resolved resolved = Config.resolveConfig(config, dir.toString());
        assertEquals(Boolean.TRUE, resolved.pep.get("signals"));
        assertEquals(ca, resolved.pep.get("tlsCa"));
        assertTrue(String.valueOf(resolved.pep.get("assertionKey")).endsWith("/generated/pep-key.pem"));
        config.put("signals", false);
        assertEquals(Boolean.FALSE, Config.resolveConfig(config, dir.toString()).pep.get("signals"));
        config.remove("pep");
        assertNull(Config.resolveConfig(config, dir.toString()).pep);
        config.put("pep", "no");
        SamlError bad = assertThrows(SamlError.class, () -> Config.resolveConfig(config, dir.toString()));
        assertTrue(bad.getMessage().contains("pep must be an object"));
    }

    @Test
    void ssfClientCertificateAndKeyGoTogether() {
        Map<String, Object> missing = base();
        missing.put("ssf", Map.of("transmitter", "https://idp.test", "clientKey", StubIdp.SP_KEY));
        SamlError alone = assertThrows(SamlError.class, () -> Config.resolveConfig(missing, null));
        assertTrue(alone.getMessage().contains("go together"));
        Map<String, Object> both = base();
        both.put("ssf", Map.of("transmitter", "https://idp.test", "clientCertificate", StubIdp.SP_CERT, "clientKey", StubIdp.SP_KEY));
        Config.Resolved resolved = Config.resolveConfig(both, null);
        assertTrue(resolved.ssfClientKey.contains("PRIVATE KEY"));
        assertTrue(resolved.ssfClientCertificate.contains("CERTIFICATE"));
    }

    @Test
    void thePepKeyMustDifferFromTheSpKeyAndTheReceiverKey() throws Exception {
        Path dir = Files.createTempDirectory("saml-pep-key");
        Path key = dir.resolve("pep-key.pem");
        Files.writeString(key, StubIdp.SP_KEY);
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-test");
        section.put("assertionKey", key.toString());
        SamlError sp = assertThrows(SamlError.class, () -> SamlPep.build(section, "https://idp.test/saml2", StubIdp.SP_ENTITY, StubIdp.SP_KEY, null));
        assertTrue(sp.getMessage().contains("privateKey"), sp.getMessage());
        String other = Keys.createSelfSigned("other.test", 1, 2048).privateKeyPem();
        SamlError receiver = assertThrows(SamlError.class, () -> SamlPep.build(section, "https://idp.test/saml2", StubIdp.SP_ENTITY, other, StubIdp.SP_KEY));
        assertTrue(receiver.getMessage().contains("ssf.clientKey"), receiver.getMessage());
    }

    @Test
    void anUntrackedOrExpiredSessionIsDeniedWithoutAPep() {
        ServiceProvider sp = ServiceProvider.create(base());
        assertNull(sp.pep());
        SamlLogin login = new SamlLogin();
        login.nameId = "alice";
        MemorySessionIndex sessions = new MemorySessionIndex();
        Decision missing = sp.decideSession(sessions, "sid", login, Access.of("read", "order", "42"));
        assertEquals(403, missing.httpStatus());
        assertEquals("no signed-in session", missing.why());
        sessions.add(new MemorySessionIndex.Tracked("sid", "alice", null, null, Instant.now().minusSeconds(5)));
        Decision expired = sp.decideSession(sessions, "sid", login, Access.of("read", "order", "42"));
        assertEquals("no signed-in session", expired.why());
        sessions.add(new MemorySessionIndex.Tracked("live", "alice", null, null, null));
        Decision open = sp.decideSession(sessions, "live", login, Access.of("read", "order", "42"));
        assertEquals(403, open.httpStatus());
        assertEquals("no pep section is configured", open.why());
        assertFalse(open.isPermit());
    }

    private static Map<String, Object> base() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entityId", StubIdp.SP_ENTITY);
        out.put("acsUrl", StubIdp.ACS);
        out.put("privateKey", StubIdp.SP_KEY);
        out.put("certificate", StubIdp.SP_CERT);
        out.put("idpMetadata", StubIdp.idpMetadata(null));
        return out;
    }
}
