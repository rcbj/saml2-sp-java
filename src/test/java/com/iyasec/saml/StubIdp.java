// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.w3c.dom.Element;

/** A stub SAML identity provider. Signatures and decryption use the library, not a SAML toolkit. */
public final class StubIdp {
    public static final Keys.KeyPair SP = Keys.createSelfSigned("sp.test", 30, 2048);
    public static final Keys.KeyPair IDP = Keys.createSelfSigned("idp.test", 30, 2048);
    public static final String SP_KEY = SP.privateKeyPem();
    public static final String SP_CERT = SP.certificatePem();
    public static final String IDP_CERT = IDP.certificatePem();
    public static final String IDP_ENTITY = "https://idp.test/saml2";
    public static final String SP_ENTITY = "https://sp.test/saml/metadata";
    public static final String ACS = "https://sp.test/saml/acs";
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final SecureRandom RANDOM = new SecureRandom();

    private StubIdp() {}

    public static String idpMetadata(String arsUrl) {
        String url = arsUrl == null ? "https://idp.test/saml2/ars" : arsUrl;
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\""
            + IDP_ENTITY + "\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">"
            + "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + Xml.pemBody(IDP_CERT)
            + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
            + "<md:ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"" + url + "\" index=\"0\" isDefault=\"true\"/>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/saml2/sso\"/>"
            + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.test/saml2/sso\"/>"
            + "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    public static Map<String, String> assertionXml(Map<String, String> options) {
        Map<String, String> o = options == null ? Map.of() : options;
        String aid = id();
        String irt = o.containsKey("inResponseTo") ? " InResponseTo=\"" + o.get("inResponseTo") + "\"" : "";
        String notAfter = iso(Long.parseLong(o.getOrDefault("notOnOrAfterMs", "300000")));
        String xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\">"
            + "<saml:Issuer>" + o.getOrDefault("issuer", IDP_ENTITY) + "</saml:Issuer>"
            + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + o.getOrDefault("nameId", "alice-1234") + "</saml:NameID>"
            + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\""
            + o.getOrDefault("recipient", ACS) + "\" NotOnOrAfter=\"" + notAfter + "\"" + irt + "/></saml:SubjectConfirmation></saml:Subject>"
            + "<saml:Conditions NotBefore=\"" + iso(-5000) + "\" NotOnOrAfter=\"" + notAfter + "\"><saml:AudienceRestriction><saml:Audience>"
            + o.getOrDefault("audience", SP_ENTITY) + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
            + "<saml:AuthnStatement AuthnInstant=\"" + iso(-1000) + "\" SessionIndex=\"_session1\"><saml:AuthnContext>"
            + "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
            + "</saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>"
            + "<saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\" FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>"
            + "<saml:Attribute Name=\"groups\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>"
            + o.getOrDefault("extraAttributes", "") + "</saml:AttributeStatement></saml:Assertion>";
        return Map.of("xml", xml, "id", aid);
    }

    public static String signXml(String xml, String elementId, Keys.KeyPair key) {
        return XmlSignature.signEnveloped(xml, elementId, key.privateKey(), key.certificate());
    }

    public static Map<String, String> signedAssertion(Map<String, String> options) {
        Map<String, String> made = assertionXml(options);
        return Map.of("xml", signXml(made.get("xml"), made.get("id"), IDP), "id", made.get("id"));
    }

    public static String encryptAssertion(String assertion, String cipherName, String transport, String wrapper) {
        try {
            boolean gcm = "aes-256-gcm".equals(cipherName);
            byte[] key = new byte[gcm ? 32 : 16];
            RANDOM.nextBytes(key);
            byte[] blob;
            String alg;
            byte[] plain = assertion.getBytes(StandardCharsets.UTF_8);
            if (gcm) {
                byte[] iv = new byte[12];
                RANDOM.nextBytes(iv);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                blob = concat(iv, cipher.doFinal(plain));
                alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
            } else {
                byte[] iv = new byte[16];
                RANDOM.nextBytes(iv);
                int pad = 16 - (plain.length % 16);
                byte[] padded = new byte[plain.length + pad];
                System.arraycopy(plain, 0, padded, 0, plain.length);
                for (int i = plain.length; i < padded.length; i++) padded[i] = (byte) pad;
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                blob = concat(iv, cipher.doFinal(padded));
                alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
            }
            String digest = "mgf1p".equals(transport) ? "SHA-1" : "SHA-256";
            Cipher wrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
            wrap.init(Cipher.ENCRYPT_MODE, SP.certificate().getPublicKey(), new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), PSource.PSpecified.DEFAULT));
            byte[] wrapped = wrap.doFinal(key);
            String keyMethod = "mgf1p".equals(transport)
                ? "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>"
                : "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
                    + "<xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></xenc:EncryptionMethod>";
            return "<saml:" + wrapper + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                + "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
                + "<xenc:EncryptionMethod Algorithm=\"" + alg + "\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>"
                + keyMethod + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(wrapped)
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>"
                + Base64.getEncoder().encodeToString(blob) + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:" + wrapper + ">";
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    public static String responseXml(Map<String, Object> options) {
        Map<String, Object> o = options == null ? Map.of() : options;
        String rid = id();
        String irt = o.get("inResponseTo") instanceof String text && !text.isEmpty() ? " InResponseTo=\"" + text + "\"" : "";
        String dest;
        if (o.containsKey("destination") && o.get("destination") == null) dest = "";
        else dest = " Destination=\"" + (o.containsKey("destination") ? o.get("destination") : ACS) + "\"";
        String status = o.get("status") instanceof String text ? text : Xml.STATUS_SUCCESS;
        String assertion;
        if (o.containsKey("assertion")) assertion = o.get("assertion") == null ? "" : String.valueOf(o.get("assertion"));
        else if (status.endsWith("Success")) {
            Map<String, String> made = new LinkedHashMap<>();
            if (o.get("inResponseTo") instanceof String reply && !reply.isEmpty()) made.put("inResponseTo", reply);
            assertion = signedAssertion(made).get("xml");
        } else assertion = "";
        String xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""
            + rid + "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\"" + dest + irt + "><saml:Issuer>"
            + o.getOrDefault("issuer", IDP_ENTITY) + "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"" + status + "\"/></samlp:Status>"
            + assertion + "</samlp:Response>";
        return Boolean.TRUE.equals(o.get("sign")) ? signXml(xml, rid, IDP) : xml;
    }

    public static String redirectResponseQuery(String xml, String relayState, Keys.KeyPair key) {
        return Bindings.redirectQuery("SAMLResponse", xml, relayState, key.privateKey());
    }

    public static String artifactFor(String entityId) {
        try {
            byte[] out = new byte[44];
            out[1] = 4;
            byte[] source = MessageDigest.getInstance("SHA-1").digest(entityId.getBytes(StandardCharsets.UTF_8));
            System.arraycopy(source, 0, out, 4, 20);
            byte[] handle = new byte[20];
            RANDOM.nextBytes(handle);
            System.arraycopy(handle, 0, out, 24, 20);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    public static final class Ars implements AutoCloseable {
        public final Map<String, String> store = new LinkedHashMap<>();
        public final java.util.List<String> resolved = new java.util.ArrayList<>();
        public final String url;
        private final HttpServer server;

        Ars(HttpServer server, String url) {
            this.server = server;
            this.url = url;
        }

        public void put(String artifact, String response) { store.put(artifact, response); }

        public void close() {
            server.stop(0);
        }
    }

    public static Ars startArs() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        Ars[] holder = new Ars[1];
        server.createContext("/ars", exchange -> handleArs(exchange, holder[0]));
        server.setExecutor(Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "stub-ars");
            thread.setDaemon(true);
            return thread;
        }));
        server.start();
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/ars";
        holder[0] = new Ars(server, url);
        return holder[0];
    }

    private static void handleArs(HttpExchange exchange, Ars holder) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String text = new String(body, StandardCharsets.UTF_8);
        boolean ok = false;
        String resolveId = "";
        String artifact = "";
        try {
            Element root = Xml.parse(text, "the ArtifactResolve").getDocumentElement();
            Element found = null;
            for (Element candidate : Xml.descendants(root, Xml.SAMLP, "ArtifactResolve")) found = candidate;
            if (found != null) {
                resolveId = found.getAttribute("ID");
                Element art = Xml.child(found, Xml.SAMLP, "Artifact");
                artifact = art == null ? "" : art.getTextContent().trim();
                ok = XmlSignature.verifySigned(found, java.util.List.of(SP.certificate()), "the ArtifactResolve") != null;
            }
        } catch (Exception err) {
            ok = false;
        }
        String message = ok ? holder.store.remove(artifact) : null;
        if (message != null) holder.resolved.add(artifact);
        String answer = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
            + "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""
            + id() + "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\" InResponseTo=\"" + resolveId + "\"><saml:Issuer>" + IDP_ENTITY
            + "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"
            + (message == null ? "" : message) + "</samlp:ArtifactResponse></soap:Body></soap:Envelope>";
        byte[] payload = answer.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("content-type", "text/xml");
        exchange.sendResponseHeaders(200, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }

    private static String id() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return "_" + HexFormat.of().formatHex(bytes);
    }

    private static String iso(long offsetMs) {
        return ISO.format(Instant.now().plusMillis(offsetMs));
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] out = new byte[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }
}
