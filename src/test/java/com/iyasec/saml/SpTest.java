// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

class SpTest {
    private static StubIdp.Ars ars;

    @BeforeAll
    static void up() throws Exception { ars = StubIdp.startArs(); }

    @AfterAll
    static void down() { if (ars != null) ars.close(); }

    @Test
    void refusesAConfigurationWithoutAKeyOrWithAnotherCertificate() {
        Map<String, Object> bad = config(null);
        bad.put("privateKey", null);
        rejects(() -> ServiceProvider.create(bad), "config", "privateKey");
        rejects(() -> ServiceProvider.create(config(Map.of("certificate", StubIdp.IDP_CERT))), "config", "not for the private key");
    }

    @Test
    void readsTheIdentityProviderFromItsMetadata() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        assertEquals(StubIdp.IDP_ENTITY, sp.idp().entityId);
        assertEquals("https://idp.test/saml2/sso", sp.idp().ssoUrls.get("redirect"));
        assertEquals(1, sp.idp().signingCertificates.size());
    }

    @Test
    void writesMetadataWithASignedRequestsKeyAndTheAcsOnAllThreeBindings() {
        String xml = ServiceProvider.create(config(null)).metadata();
        List<Element> services = Xml.descendants(Xml.parse(xml, "metadata").getDocumentElement(), Xml.MD, "AssertionConsumerService");
        assertEquals(List.of("HTTP-POST", "HTTP-Redirect", "HTTP-Artifact"), services.stream().map(item -> item.getAttribute("Binding").substring(item.getAttribute("Binding").lastIndexOf(':') + 1)).toList());
        assertTrue(services.stream().allMatch(item -> StubIdp.ACS.equals(item.getAttribute("Location"))));
        assertTrue(xml.contains("AuthnRequestsSigned=\"true\""));
        assertTrue(Pattern.compile("<md:KeyDescriptor use=\"encryption\">[\\s\\S]*xmlenc11#aes256-gcm[\\s\\S]*</md:KeyDescriptor>").matcher(xml).find());
    }

    @Test
    void omitsSignalsUnlessItIsFalse() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        assertFalse(sp.config.contains("signals"));
        assertEquals(StubIdp.SP_ENTITY, sp.config.entityId);
        assertEquals(StubIdp.ACS, sp.config.acsUrl);
        assertEquals("redirect", sp.config.requestBinding);
        assertEquals("post", sp.config.responseBinding);
        ServiceProvider explicit = ServiceProvider.create(config(Map.of("signals", true)));
        assertFalse(explicit.config.contains("signals"));
        assertEquals(sp.config.entityId, explicit.config.entityId);
        assertEquals(sp.config.acsUrl, explicit.config.acsUrl);
    }

    @Test
    void recordsSignalsFalseAndStillResolvesTheSamlFields() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("signals", false, "wantAssertionsEncrypted", true)));
        assertEquals(Boolean.FALSE, sp.config.signals);
        assertEquals(StubIdp.SP_ENTITY, sp.config.entityId);
        assertEquals(StubIdp.ACS, sp.config.acsUrl);
        assertEquals("redirect", sp.config.requestBinding);
        assertEquals("post", sp.config.responseBinding);
        assertTrue(sp.config.wantAssertionsSigned);
        assertTrue(sp.config.wantAssertionsEncrypted);
        assertFalse(sp.config.allowUnsolicited);
        assertEquals(60_000, sp.config.clockSkewMs);
        assertEquals(StubIdp.IDP_ENTITY, sp.idp().entityId);
    }

    @Test
    void refusesASignalsValueThatIsNotTrueOrFalse() {
        rejects(() -> ServiceProvider.create(config(Map.of("signals", "no"))), "config", "^signals must be true or false$");
    }

    @Test
    void redirectAuthnRequestIsDeflatedAndSigned() throws Exception {
        ServiceProvider sp = ServiceProvider.create(config(null));
        LoginOptions options = new LoginOptions();
        options.relayState = "/home";
        LoginRequest req = sp.login(options);
        assertEquals("redirect", req.binding);
        String raw = req.url.split("\\?", 2)[1];
        String[] parts = raw.split("&Signature=", 2);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(StubIdp.SP.certificate());
        signature.update(parts[0].getBytes(StandardCharsets.UTF_8));
        assertTrue(signature.verify(Base64.getDecoder().decode(java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8))));
        String xml = new String(Bindings.inflateRaw(Base64.getDecoder().decode(query(raw).get("SAMLRequest"))), StandardCharsets.UTF_8);
        assertTrue(xml.contains("ID=\"" + req.id + "\""));
        assertTrue(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assertTrue(xml.contains("Destination=\"https://idp.test/saml2/sso\""));
        assertEquals("/home", query(raw).get("RelayState"));
        assertTrue(req.url.startsWith("https://idp.test/saml2/sso?"));
    }

    @Test
    void postAuthnRequestIsAnEnvelopedSignatureInAForm() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("requestBinding", "post")));
        LoginOptions options = new LoginOptions();
        options.responseBinding = "artifact";
        options.nonce = "abc";
        LoginRequest req = sp.login(options);
        assertEquals("post", req.binding);
        String xml = new String(Base64.getDecoder().decode(req.fields.get("SAMLRequest")), StandardCharsets.UTF_8);
        assertTrue(Pattern.compile("<saml:Issuer>[^<]+</saml:Issuer><ds:Signature").matcher(xml).find(), xml);
        assertTrue(xml.contains("HTTP-Artifact"));
        assertTrue(XmlSignature.verifySigned(Xml.parse(xml, "the AuthnRequest").getDocumentElement(), List.of(StubIdp.SP.certificate()), "the message") != null);
        assertTrue(req.html.contains("<script nonce=\"abc\">"));
        assertTrue(req.html.contains("<button type=\"submit\">"));
    }

    @Test
    void subjectHintFollowsTheIssuerAndItsSignature() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("requestBinding", "post")));
        LoginOptions options = new LoginOptions();
        options.subjectHint = "alice<&>";
        options.subjectHintFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        options.forceAuthn = true;
        LoginRequest req = sp.login(options);
        String xml = new String(Base64.getDecoder().decode(req.fields.get("SAMLRequest")), StandardCharsets.UTF_8);
        assertTrue(xml.contains("</ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy"), xml);
        assertTrue(xml.contains("ForceAuthn=\"true\""));
        assertTrue(XmlSignature.verifySigned(Xml.parse(xml, "the AuthnRequest").getDocumentElement(), List.of(StubIdp.SP.certificate()), "the message") != null);
        assertFalse(sp.login().xml.contains("<saml:Subject>"));
    }

    @Test
    void refusesARelayStateOver80Bytes() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        LoginOptions options = new LoginOptions();
        options.relayState = "x".repeat(81);
        SamlError err = assertThrows(SamlError.class, () -> sp.login(options));
        assertTrue(err.getMessage().contains("80 bytes"));
    }

    @Test
    void signedResponseAndSignedAssertion() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        SamlLogin who = post(sp, StubIdp.responseXml(map("inResponseTo", "_req1", "sign", true)), "_req1", "/home");
        assertEquals("alice-1234", who.nameId);
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", who.nameIdFormat);
        assertEquals("_session1", who.sessionIndex);
        assertEquals("/home", who.relayState);
        assertEquals("post", who.binding);
        assertEquals(List.of("staff", "admins"), who.attributes.get("groups"));
        assertEquals(List.of("alice@example.com"), who.attributes.get("urn:oid:0.9.2342.19200300.100.1.3"));
        assertEquals("mail", who.attributeFriendlyNames.get("urn:oid:0.9.2342.19200300.100.1.3"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", who.authnContextClassRef);
    }

    @Test
    void acceptsASignedAssertionInAnUnsignedResponse() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        assertEquals("alice-1234", post(sp, StubIdp.responseXml(map("inResponseTo", "_req1")), "_req1", null).nameId);
    }

    @Test
    void refusesAnUnsignedAssertionByDefault() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        Map<String, String> made = StubIdp.assertionXml(Map.of("inResponseTo", "_r"));
        String xml = StubIdp.responseXml(map("inResponseTo", "_r", "sign", true, "assertion", made.get("xml")));
        rejects(() -> post(sp, xml, "_r", null), "validation", "not signed");
        ServiceProvider lax = ServiceProvider.create(config(Map.of("wantAssertionsSigned", false)));
        assertEquals("alice-1234", post(lax, xml, "_r", null).nameId);
    }

    @Test
    void refusesAResponseWithNothingSigned() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("wantAssertionsSigned", false)));
        Map<String, String> made = StubIdp.assertionXml(Map.of("inResponseTo", "_r"));
        String xml = StubIdp.responseXml(map("inResponseTo", "_r", "assertion", made.get("xml")));
        rejects(() -> post(sp, xml, "_r", null), "validation", "neither");
    }

    @Test
    void refusesAnAssertionAlteredAfterItWasSigned() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String xml = StubIdp.responseXml(map("inResponseTo", "_r")).replace("alice-1234", "mallory");
        rejects(() -> post(sp, xml, "_r", null), "signature", null);
    }

    @Test
    void refusesASignatureByAnotherKey() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        Map<String, String> made = StubIdp.assertionXml(Map.of("inResponseTo", "_r"));
        String xml = StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signXml(made.get("xml"), made.get("id"), StubIdp.SP)));
        rejects(() -> post(sp, xml, "_r", null), "signature", "does not verify");
    }

    @Test
    void isNotFooledBySignatureWrapping() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        Map<String, String> signed = StubIdp.signedAssertion(Map.of("inResponseTo", "_r"));
        String forged = StubIdp.assertionXml(Map.of("inResponseTo", "_r", "nameId", "mallory")).get("xml");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", forged + signed.get("xml"))), "_r", null), "validation", "exactly one");
        String hidden = forged.replaceFirst("ID=\"[^\"]+\"", "ID=\"" + signed.get("id") + "\"").replace("</saml:Assertion>", "<saml:Advice>" + signed.get("xml") + "</saml:Advice></saml:Assertion>");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", hidden)), "_r", null), "signature", "two elements");
        String sig = Pattern.compile("<ds:Signature[\\s\\S]*</ds:Signature>").matcher(signed.get("xml")).results().findFirst().orElseThrow().group();
        String moved = forged.replaceFirst("</saml:Issuer>", "</saml:Issuer>" + sig);
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", moved)), "_r", null), "signature", "refers to");
    }

    @Test
    void refusesAResponseForAnotherAudienceAcsOrThatHasExpired() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signedAssertion(Map.of("inResponseTo", "_r", "audience", "https://other.test")).get("xml"))), "_r", null), "validation", "not for");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signedAssertion(Map.of("inResponseTo", "_r", "recipient", "https://other.test/acs")).get("xml"))), "_r", null), "validation", "Recipient");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signedAssertion(Map.of("inResponseTo", "_r", "notOnOrAfterMs", "-120000")).get("xml"))), "_r", null), "validation", "expired");
        Map<String, Object> destination = new LinkedHashMap<>();
        destination.put("inResponseTo", "_r");
        destination.put("destination", "https://other.test/acs");
        rejects(() -> post(sp, StubIdp.responseXml(destination), "_r", null), "validation", "addressed to");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signedAssertion(Map.of("inResponseTo", "_r", "issuer", "https://evil.test")).get("xml"))), "_r", null), "validation", "issued by");
    }

    @Test
    void refusesAnAnswerToAnotherRequestAndAnUnsolicitedOne() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r")), "_other", null), "validation", "not a request this browser");
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r")), null, null), "validation", "not a request this browser");
        rejects(() -> post(sp, StubIdp.responseXml(Map.of()), null, null), "validation", "unsolicited");
        ServiceProvider open = ServiceProvider.create(config(Map.of("allowUnsolicited", true)));
        assertNull(post(open, StubIdp.responseXml(Map.of()), null, null).inResponseTo);
    }

    @Test
    void refusesTheSameAssertionTwice() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String xml = StubIdp.responseXml(map("inResponseTo", "_r", "sign", true));
        post(sp, xml, "_r", null);
        rejects(() -> post(sp, xml, "_r", null), "replay", null);
    }

    @Test
    void reportsANonSuccessStatus() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        SamlError err = assertThrows(SamlError.class, () -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "status", "urn:oasis:names:tc:SAML:2.0:status:Responder")), "_r", null));
        assertEquals("status", err.code);
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder", err.status.code);
    }

    @Test
    void refusesADoctype() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String xml = "<!DOCTYPE x [<!ENTITY e \"x\">]>" + StubIdp.responseXml(map("inResponseTo", "_r"));
        rejects(() -> post(sp, xml, "_r", null), "xml", "DOCTYPE");
    }

    @Test
    void decryptsAnEncryptedAssertion() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        for (String cipher : List.of("aes-256-gcm", "aes-128-cbc")) {
            String made = StubIdp.signedAssertion(Map.of("inResponseTo", "_r")).get("xml");
            SamlLogin who = post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "sign", true, "assertion", StubIdp.encryptAssertion(made, cipher, "mgf1p", "EncryptedAssertion"))), "_r", null);
            assertEquals("alice-1234", who.nameId);
            assertTrue(who.encrypted);
        }
        String made = StubIdp.signedAssertion(Map.of("inResponseTo", "_r")).get("xml");
        assertEquals("alice-1234", post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.encryptAssertion(made, "aes-256-gcm", "oaep256", "EncryptedAssertion"))), "_r", null).nameId);
    }

    @Test
    void refusesAPlaintextAssertionWhenEncryptionIsRequired() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("wantAssertionsEncrypted", true)));
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "sign", true)), "_r", null), "validation", "not encrypted");
        String made = StubIdp.signedAssertion(Map.of("inResponseTo", "_r")).get("xml");
        assertTrue(post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.encryptAssertion(made, "aes-256-gcm", "mgf1p", "EncryptedAssertion"))), "_r", null).encrypted);
    }

    @Test
    void refusesAnEncryptedAssertionWhoseCiphertextWasAltered() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String enc = StubIdp.encryptAssertion(StubIdp.signedAssertion(Map.of("inResponseTo", "_r")).get("xml"), "aes-256-gcm", "mgf1p", "EncryptedAssertion");
        java.util.regex.Matcher matcher = Pattern.compile("<xenc:CipherValue>([^<]+)</xenc:CipherValue>").matcher(enc);
        String last = "";
        while (matcher.find()) last = matcher.group(1);
        byte[] blob = Base64.getDecoder().decode(last);
        blob[20] ^= 1;
        String altered = enc.replace(last, Base64.getEncoder().encodeToString(blob));
        rejects(() -> post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", altered)), "_r", null), "decryption", null);
    }

    @Test
    void decryptsAnEncryptedAttribute() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String secret = StubIdp.encryptAssertion(
            "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>",
            "aes-256-gcm", "oaep256", "EncryptedAttribute");
        Map<String, String> made = StubIdp.assertionXml(Map.of("inResponseTo", "_r", "extraAttributes", secret));
        SamlLogin who = post(sp, StubIdp.responseXml(map("inResponseTo", "_r", "assertion", StubIdp.signXml(made.get("xml"), made.get("id"), StubIdp.IDP))), "_r", null);
        assertEquals(List.of("E-42"), who.attributes.get("employeeNumber"));
    }

    @Test
    void redirectResponseVerifiesTheQuerySignature() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String query = StubIdp.redirectResponseQuery(StubIdp.responseXml(map("inResponseTo", "_r")), "/there", StubIdp.IDP);
        SamlLogin who = sp.acs("GET", "/saml/acs?" + query, null, "_r");
        assertEquals("redirect", who.binding);
        assertEquals("/there", who.relayState);
    }

    @Test
    void refusesAQuerySignatureByAnotherKeyAndAChangedRelayState() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        String forged = StubIdp.redirectResponseQuery(StubIdp.responseXml(map("inResponseTo", "_r")), "/x", StubIdp.SP);
        rejects(() -> sp.acs("GET", "/saml/acs?" + forged, null, "_r"), "signature", null);
        String changed = StubIdp.redirectResponseQuery(StubIdp.responseXml(map("inResponseTo", "_r")), "/x", StubIdp.IDP).replace("RelayState=%2Fx", "RelayState=%2Fy");
        rejects(() -> sp.acs("GET", "/saml/acs?" + changed, null, "_r"), "signature", null);
    }

    @Test
    void resolvesTheArtifact() {
        ServiceProvider sp = ServiceProvider.create(config(Map.of("responseBinding", "artifact"), ars.url));
        LoginRequest req = sp.login();
        assertTrue(req.xml.contains("HTTP-Artifact"));
        ars.resolved.clear();
        String artifact = StubIdp.artifactFor(StubIdp.IDP_ENTITY);
        ars.put(artifact, StubIdp.responseXml(map("inResponseTo", req.id)));
        SamlLogin who = sp.acs("GET", "/saml/acs?SAMLart=" + URLEncoder.encode(artifact, StandardCharsets.UTF_8) + "&RelayState=%2Fa", null, req.id);
        assertEquals("artifact", who.binding);
        assertEquals("/a", who.relayState);
        assertEquals("alice-1234", who.nameId);
        assertEquals(List.of(artifact), ars.resolved);
    }

    @Test
    void acceptsTheArtifactOnAPostAndFailsWhenAlreadyUsed() {
        ServiceProvider sp = ServiceProvider.create(config(null, ars.url));
        String artifact = StubIdp.artifactFor(StubIdp.IDP_ENTITY);
        ars.put(artifact, StubIdp.responseXml(map("inResponseTo", "_r")));
        SamlLogin who = sp.acs("POST", "/saml/acs", "SAMLart=" + URLEncoder.encode(artifact, StandardCharsets.UTF_8), "_r");
        assertEquals("artifact", who.binding);
        rejects(() -> sp.acs("POST", "/saml/acs", Map.of("SAMLart", artifact), "_r"), "artifact", "did not resolve");
    }

    @Test
    void refusesAnArtifactFromAnotherIdentityProvider() {
        ServiceProvider sp = ServiceProvider.create(config(null, ars.url));
        String artifact = StubIdp.artifactFor("https://evil.test");
        rejects(() -> sp.acs("GET", "/saml/acs?SAMLart=" + URLEncoder.encode(artifact, StandardCharsets.UTF_8), null, "_r"), "artifact", "not issued by");
    }

    @Test
    void refusesARequestWithNoSamlMessage() {
        ServiceProvider sp = ServiceProvider.create(config(null));
        rejects(() -> sp.acs("GET", "/saml/acs"), "binding", null);
    }

    private static Map<String, Object> config(Map<String, Object> extra) {
        return config(extra, null);
    }

    private static Map<String, Object> config(Map<String, Object> extra, String arsUrl) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entityId", StubIdp.SP_ENTITY);
        out.put("acsUrl", StubIdp.ACS);
        out.put("privateKey", StubIdp.SP_KEY);
        out.put("certificate", StubIdp.SP_CERT);
        out.put("idpMetadata", StubIdp.idpMetadata(arsUrl));
        if (extra != null) out.putAll(extra);
        return out;
    }

    private static SamlLogin post(ServiceProvider sp, String xml, String requestId, String relayState) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("SAMLResponse", Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8)));
        if (relayState != null) body.put("RelayState", relayState);
        return sp.acs("POST", "/saml/acs", body, requestId);
    }

    private static Map<String, Object> map(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) out.put(String.valueOf(pairs[i]), pairs[i + 1]);
        return out;
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            out.put(java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8), java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    private static void rejects(org.junit.jupiter.api.function.Executable fn, String code, String pattern) {
        SamlError err = assertThrows(SamlError.class, fn);
        assertEquals(code, err.code, err.getMessage());
        if (pattern != null) assertTrue(Pattern.compile(pattern).matcher(err.getMessage()).find(), err.getMessage());
    }
}
