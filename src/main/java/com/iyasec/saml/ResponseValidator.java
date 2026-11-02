// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** Validating a samlp:Response under the Web Browser SSO profile. */
public final class ResponseValidator {
    private static final Pattern DATETIME = Pattern.compile("^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(\\.\\d+)?Z$");
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    public record Received(String xml, Element response, String binding, String relayState, boolean authenticatedByBinding) {}

    public record Context(String entityId, String acsUrl, String idpEntityId, List<X509Certificate> idpCertificates,
                          PrivateKey decryptionKey, int clockSkewMs, boolean wantAssertionsSigned, boolean wantAssertionsEncrypted,
                          boolean allowUnsolicited, MemoryReplayCache replayCache, List<String> expectedRequestIds, Instant now) {}

    private ResponseValidator() {}

    public static SamlLogin validate(Received received, Context ctx) {
        long now = (ctx.now == null ? Instant.now() : ctx.now).toEpochMilli();
        int skew = ctx.clockSkewMs;
        Element response = received.response;
        Xml.assertUniqueIds(response.getOwnerDocument());
        if (!(Xml.SAMLP.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName()))) {
            invalid("the message is a <" + response.getLocalName() + ">, not a Response");
        }
        String signed = XmlSignature.verifySigned(response, ctx.idpCertificates, "the Response");
        if (signed != null) response = Xml.parse(signed, "the signed Response").getDocumentElement();
        boolean responseAuthenticated = signed != null || received.authenticatedByBinding;
        if (!"2.0".equals(Xml.attr(response, "Version"))) {
            invalid("the Response is version " + orNone(Xml.attr(response, "Version")) + ", not 2.0");
        }
        String responseId = Xml.attr(response, "ID");
        if (responseId == null || responseId.isEmpty()) invalid("the Response has no ID");
        issuerOf(response, false, ctx.idpEntityId, "the Response");
        String destination = Xml.attr(response, "Destination");
        if (destination != null && !destination.equals(ctx.acsUrl)) {
            invalid("the Response is addressed to " + destination + ", not to " + ctx.acsUrl);
        }
        if (destination == null && responseAuthenticated && !"artifact".equals(received.binding)) {
            invalid("the Response is signed but has no Destination");
        }
        String inResponseTo = Xml.attr(response, "InResponseTo");
        List<String> expected = ctx.expectedRequestIds == null ? List.of() : ctx.expectedRequestIds;
        if (inResponseTo != null) {
            if (!expected.contains(inResponseTo)) {
                invalid("the Response answers " + inResponseTo + ", which is not a request this browser has outstanding");
            }
        } else if (!ctx.allowUnsolicited) {
            invalid("the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted");
        }
        SamlStatus status = statusOf(response);
        if (!Xml.STATUS_SUCCESS.equals(status.code)) {
            String detail = status.subCode != null && !status.subCode.isEmpty() ? status.subCode : status.code;
            String suffix = status.message != null && !status.message.isEmpty() ? ": " + status.message : "";
            throw new SamlError("status", "the identity provider answered " + detail + suffix, status);
        }
        List<Element> plain = Xml.children(response, Xml.SAML, "Assertion");
        List<Element> encrypted = Xml.children(response, Xml.SAML, "EncryptedAssertion");
        if (plain.size() + encrypted.size() != 1) {
            invalid("the Response holds " + (plain.size() + encrypted.size()) + " assertions; exactly one is accepted");
        }
        Element assertion;
        if (!encrypted.isEmpty()) {
            String assertionXml = XmlEncryption.decryptElement(encrypted.get(0), ctx.decryptionKey);
            var doc = Xml.parse(assertionXml, "the decrypted assertion");
            Xml.assertUniqueIds(doc);
            assertion = doc.getDocumentElement();
            if (!(Xml.SAML.equals(assertion.getNamespaceURI()) && "Assertion".equals(assertion.getLocalName()))) {
                invalid("the EncryptedAssertion does not hold an Assertion");
            }
        } else {
            if (ctx.wantAssertionsEncrypted) invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on");
            assertion = plain.get(0);
        }
        String signedAssertion = XmlSignature.verifySigned(assertion, ctx.idpCertificates, "the assertion");
        if (signedAssertion != null) assertion = Xml.parse(signedAssertion, "the signed assertion").getDocumentElement();
        else if (ctx.wantAssertionsSigned) invalid("the assertion is not signed, and wantAssertionsSigned is on");
        else if (!responseAuthenticated) invalid("neither the Response nor its assertion is signed");
        if (!"2.0".equals(Xml.attr(assertion, "Version"))) invalid("the assertion is not version 2.0");
        String assertionId = Xml.attr(assertion, "ID");
        if (assertionId == null || assertionId.isEmpty()) invalid("the assertion has no ID");
        issuerOf(assertion, true, ctx.idpEntityId, "the assertion");
        Element subject = Xml.child(assertion, Xml.SAML, "Subject");
        if (subject == null) invalid("the assertion has no Subject");
        Element nameId = Xml.child(subject, Xml.SAML, "NameID");
        Element encryptedId = Xml.child(subject, Xml.SAML, "EncryptedID");
        if (nameId == null && encryptedId != null) {
            nameId = Xml.parse(XmlEncryption.decryptElement(encryptedId, ctx.decryptionKey), "the decrypted NameID").getDocumentElement();
            if (!(Xml.SAML.equals(nameId.getNamespaceURI()) && "NameID".equals(nameId.getLocalName()))) {
                invalid("the EncryptedID does not hold a NameID");
            }
        }
        if (nameId == null || Xml.text(nameId).isEmpty()) invalid("the assertion's Subject has no NameID");
        List<String> reasons = new ArrayList<>();
        Instant confirmedUntil = null;
        for (Element confirmation : Xml.children(subject, Xml.SAML, "SubjectConfirmation")) {
            if (!Xml.BEARER.equals(Xml.attr(confirmation, "Method"))) {
                reasons.add("method " + Xml.attr(confirmation, "Method"));
                continue;
            }
            Element data = Xml.child(confirmation, Xml.SAML, "SubjectConfirmationData");
            if (data == null) {
                reasons.add("no SubjectConfirmationData");
                continue;
            }
            String recipient = Xml.attr(data, "Recipient");
            Instant notOnOrAfter = instant(Xml.attr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
            String notBefore = Xml.attr(data, "NotBefore");
            String scInResponseTo = Xml.attr(data, "InResponseTo");
            if (recipient == null || !recipient.equals(ctx.acsUrl)) reasons.add("Recipient " + (recipient == null ? "(none)" : recipient));
            else if (notOnOrAfter == null) reasons.add("no NotOnOrAfter");
            else if (notOnOrAfter.toEpochMilli() <= now - skew) reasons.add("expired at " + STAMP.format(notOnOrAfter));
            else if (notBefore != null) reasons.add("a NotBefore, which a bearer confirmation must not have");
            else if ((scInResponseTo == null && inResponseTo != null) || (scInResponseTo != null && !scInResponseTo.equals(inResponseTo))) {
                reasons.add("InResponseTo " + (scInResponseTo == null ? "(none)" : scInResponseTo));
            } else {
                confirmedUntil = notOnOrAfter;
                break;
            }
        }
        if (confirmedUntil == null) {
            invalid("no bearer SubjectConfirmation of the assertion fits: " + (reasons.isEmpty() ? "there is none" : String.join("; ", reasons)));
        }
        Element conditions = Xml.child(assertion, Xml.SAML, "Conditions");
        if (conditions == null) invalid("the assertion has no Conditions, so it names no audience");
        Instant notBeforeC = instant(Xml.attr(conditions, "NotBefore"), "Conditions NotBefore");
        Instant notOnOrAfterC = instant(Xml.attr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter");
        if (notBeforeC != null && notBeforeC.toEpochMilli() > now + skew) {
            invalid("the assertion is not valid before " + STAMP.format(notBeforeC));
        }
        if (notOnOrAfterC != null && notOnOrAfterC.toEpochMilli() <= now - skew) {
            invalid("the assertion expired at " + STAMP.format(notOnOrAfterC));
        }
        List<Element> restrictions = Xml.children(conditions, Xml.SAML, "AudienceRestriction");
        if (restrictions.isEmpty()) invalid("the assertion has no AudienceRestriction");
        for (Element restriction : restrictions) {
            boolean hit = false;
            for (Element audience : Xml.children(restriction, Xml.SAML, "Audience")) {
                if (ctx.entityId.equals(Xml.text(audience))) hit = true;
            }
            if (!hit) invalid("the assertion is not for " + ctx.entityId);
        }
        List<Element> authnStatements = Xml.children(assertion, Xml.SAML, "AuthnStatement");
        if (authnStatements.isEmpty()) invalid("the assertion has no AuthnStatement");
        Element authn = authnStatements.get(0);
        Instant authnInstant = instant(Xml.attr(authn, "AuthnInstant"), "AuthnInstant");
        if (authnInstant == null) invalid("the AuthnStatement has no AuthnInstant");
        Instant sessionNotOnOrAfter = instant(Xml.attr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter");
        if (sessionNotOnOrAfter != null && sessionNotOnOrAfter.toEpochMilli() <= now - skew) {
            invalid("the identity provider's session has already ended");
        }
        Element context = Xml.child(authn, Xml.SAML, "AuthnContext");
        String classRef = context == null ? "" : Xml.text(Xml.child(context, Xml.SAML, "AuthnContextClassRef"));
        var attributes = new java.util.LinkedHashMap<String, List<String>>();
        var friendly = new java.util.LinkedHashMap<String, String>();
        for (Element statement : Xml.children(assertion, Xml.SAML, "AttributeStatement")) {
            List<Element> decrypted = new ArrayList<>();
            for (Element enc : Xml.children(statement, Xml.SAML, "EncryptedAttribute")) {
                Element element = Xml.parse(XmlEncryption.decryptElement(enc, ctx.decryptionKey), "the decrypted attribute").getDocumentElement();
                if (!(Xml.SAML.equals(element.getNamespaceURI()) && "Attribute".equals(element.getLocalName()))) {
                    invalid("an EncryptedAttribute does not hold an Attribute");
                }
                decrypted.add(element);
            }
            List<Element> all = new ArrayList<>(Xml.children(statement, Xml.SAML, "Attribute"));
            all.addAll(decrypted);
            for (Element attribute : all) {
                String name = Xml.attr(attribute, "Name");
                if (name == null || name.isEmpty()) continue;
                List<String> values = attributes.computeIfAbsent(name, key -> new ArrayList<>());
                for (Element value : Xml.children(attribute, Xml.SAML, "AttributeValue")) values.add(value.getTextContent());
                String friend = Xml.attr(attribute, "FriendlyName");
                if (friend != null && !friend.isEmpty()) friendly.put(name, friend);
            }
        }
        long keepUntilMs = Math.max(confirmedUntil.toEpochMilli(), notOnOrAfterC == null ? 0 : notOnOrAfterC.toEpochMilli()) + skew;
        if (ctx.replayCache.checkAndRecord(ctx.idpEntityId + " " + assertionId, Instant.ofEpochMilli(keepUntilMs))) {
            throw new SamlError("replay", "the assertion " + assertionId + " has been accepted before");
        }
        SamlLogin login = new SamlLogin();
        login.nameId = Xml.text(nameId);
        login.nameIdFormat = Xml.attr(nameId, "Format");
        login.nameQualifier = Xml.attr(nameId, "NameQualifier");
        login.spNameQualifier = Xml.attr(nameId, "SPNameQualifier");
        login.sessionIndex = Xml.attr(authn, "SessionIndex");
        login.sessionNotOnOrAfter = sessionNotOnOrAfter;
        login.authnInstant = authnInstant;
        login.authnContextClassRef = classRef.isEmpty() ? null : classRef;
        login.attributes = attributes;
        login.attributeFriendlyNames = friendly;
        login.issuer = ctx.idpEntityId;
        login.inResponseTo = inResponseTo;
        login.relayState = received.relayState;
        login.binding = received.binding;
        login.encrypted = !encrypted.isEmpty();
        login.responseId = responseId;
        login.assertionId = assertionId;
        return login;
    }

    private static void issuerOf(Element element, boolean required, String expected, String what) {
        Element issuer = Xml.child(element, Xml.SAML, "Issuer");
        if (issuer == null) {
            if (required) invalid(what + " has no Issuer");
            return;
        }
        String form = Xml.attr(issuer, "Format");
        if (form != null && !form.isEmpty() && !"urn:oasis:names:tc:SAML:2.0:nameid-format:entity".equals(form)) {
            invalid(what + "'s Issuer has the Format " + form);
        }
        if (!expected.equals(Xml.text(issuer))) invalid(what + " was issued by " + Xml.text(issuer) + ", not by " + expected);
    }

    private static SamlStatus statusOf(Element response) {
        Element status = Xml.child(response, Xml.SAMLP, "Status");
        if (status == null) invalid("the Response has no Status");
        Element top = Xml.child(status, Xml.SAMLP, "StatusCode");
        if (top == null) invalid("the Response has no StatusCode");
        Element sub = Xml.child(top, Xml.SAMLP, "StatusCode");
        SamlStatus out = new SamlStatus(orEmpty(Xml.attr(top, "Value")));
        if (sub != null && Xml.attr(sub, "Value") != null && !Xml.attr(sub, "Value").isEmpty()) out.subCode = Xml.attr(sub, "Value");
        String message = Xml.text(Xml.child(status, Xml.SAMLP, "StatusMessage"));
        if (!message.isEmpty()) out.message = message;
        return out;
    }

    private static Instant instant(String value, String what) {
        if (value == null) return null;
        if (!DATETIME.matcher(value).matches()) invalid(what + " is not a UTC dateTime: " + value);
        try {
            String text = value.endsWith("Z") ? value.substring(0, value.length() - 1) : value;
            if (!text.contains(".")) return Instant.parse(text + "Z").truncatedTo(ChronoUnit.MILLIS);
            String[] parts = text.split("\\.", 2);
            String fraction = parts[1];
            if (fraction.length() > 9) fraction = fraction.substring(0, 9);
            while (fraction.length() < 9) fraction = fraction + "0";
            return Instant.parse(parts[0] + "." + fraction + "Z");
        } catch (RuntimeException err) {
            invalid(what + " is not a dateTime: " + value);
            return null;
        }
    }

    private static String orNone(String value) {
        return value == null || value.isEmpty() ? "(none)" : value;
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void invalid(String message) {
        throw new SamlError("validation", message);
    }
}
