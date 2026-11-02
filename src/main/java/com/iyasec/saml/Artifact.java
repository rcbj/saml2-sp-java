// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/** The HTTP-Artifact binding, as the receiving side of a Response. */
public final class Artifact {
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    public record Parsed(int endpointIndex, byte[] sourceId) {}

    public record Resolved(String xml, Element response) {}

    private Artifact() {}

    public static Parsed parseArtifact(String samlArt) {
        byte[] raw = Base64.getMimeDecoder().decode(samlArt.replaceAll("\\s+", ""));
        int type = ((raw.length > 1 ? raw[0] & 0xff : 0) << 8) | (raw.length > 1 ? raw[1] & 0xff : 0);
        if (raw.length != 44 || type != 0x0004) throw new SamlError("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact");
        int index = ((raw[2] & 0xff) << 8) | (raw[3] & 0xff);
        byte[] source = new byte[20];
        System.arraycopy(raw, 4, source, 0, 20);
        return new Parsed(index, source);
    }

    public static Resolved resolveArtifact(String artifact, String entityId, String idpEntityId,
                                           Map<Integer, String> services, List<X509Certificate> idpCertificates,
                                           PrivateKey key, X509Certificate certificate, Map<String, String> tls) {
        Parsed parsed = parseArtifact(artifact);
        byte[] expected;
        try {
            expected = MessageDigest.getInstance("SHA-1").digest(idpEntityId.getBytes(StandardCharsets.UTF_8));
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("artifact", "the artifact source id could not be computed", err);
        }
        if (!MessageDigest.isEqual(parsed.sourceId, expected)) {
            throw new SamlError("artifact", "the artifact was not issued by " + idpEntityId);
        }
        String location = services.get(parsed.endpointIndex);
        if (location == null && parsed.endpointIndex == 0 && !services.isEmpty()) location = services.values().iterator().next();
        if (location == null || location.isEmpty()) {
            throw new SamlError("artifact", "the identity provider's metadata has no SOAP ArtifactResolutionService with index " + parsed.endpointIndex);
        }
        byte[] random = new byte[20];
        new SecureRandom().nextBytes(random);
        String elementId = "_" + HexFormat.of().formatHex(random);
        String unsigned = "<samlp:ArtifactResolve xmlns:samlp=\"" + Xml.SAMLP + "\" xmlns:saml=\"" + Xml.SAML + "\" ID=\"" + elementId
            + "\" Version=\"2.0\" IssueInstant=\"" + ISO.format(Instant.now()) + "\" Destination=\"" + Xml.escape(location) + "\">"
            + "<saml:Issuer>" + Xml.escape(entityId) + "</saml:Issuer><samlp:Artifact>" + Xml.escape(artifact) + "</samlp:Artifact></samlp:ArtifactResolve>";
        String signed = XmlSignature.signEnveloped(unsigned, elementId, key, certificate);
        String envelope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"" + Xml.SOAP + "\"><soap:Body>"
            + signed + "</soap:Body></soap:Envelope>";
        Backchannel.Answer answer = Backchannel.send(location, "POST", Map.of(
            "content-type", "text/xml; charset=utf-8",
            "soapaction", "\"http://www.oasis-open.org/committees/security\"",
            "accept", "text/xml"
        ), envelope, tls == null ? Map.of() : tls, "artifact");
        if (answer.status() != 200) throw new SamlError("artifact", "the artifact resolution service answered HTTP " + answer.status());
        Element root = Xml.parse(answer.body(), "the ArtifactResponse").getDocumentElement();
        Xml.assertUniqueIds(root.getOwnerDocument());
        Element body = Xml.SOAP.equals(root.getNamespaceURI()) && "Envelope".equals(root.getLocalName()) ? Xml.child(root, Xml.SOAP, "Body") : null;
        Element artifactResponse = body == null ? null : Xml.child(body, Xml.SAMLP, "ArtifactResponse");
        if (artifactResponse == null) throw new SamlError("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse");
        String xml = answer.body();
        String signedResponse = XmlSignature.verifySigned(artifactResponse, idpCertificates, "the ArtifactResponse");
        if (signedResponse != null) {
            xml = signedResponse;
            artifactResponse = Xml.parse(signedResponse, "the signed ArtifactResponse").getDocumentElement();
        }
        if (!elementId.equals(Xml.attr(artifactResponse, "InResponseTo"))) {
            throw new SamlError("artifact", "the ArtifactResponse does not answer this ArtifactResolve");
        }
        Element issuer = Xml.child(artifactResponse, Xml.SAML, "Issuer");
        if (issuer != null && !idpEntityId.equals(Xml.text(issuer))) {
            throw new SamlError("artifact", "the ArtifactResponse was issued by " + Xml.text(issuer));
        }
        Element status = Xml.child(artifactResponse, Xml.SAMLP, "Status");
        Element codeEl = status == null ? null : Xml.child(status, Xml.SAMLP, "StatusCode");
        String code = codeEl != null ? Xml.attr(codeEl, "Value") : (status == null ? null : Xml.attr(status, "Value"));
        if (!Xml.STATUS_SUCCESS.equals(code)) throw new SamlError("artifact", "the artifact resolution failed: " + (code == null ? "no status" : code));
        List<Element> responses = Xml.children(artifactResponse, Xml.SAMLP, "Response");
        if (responses.isEmpty()) {
            throw new SamlError("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)");
        }
        return new Resolved(xml, responses.get(0));
    }
}
