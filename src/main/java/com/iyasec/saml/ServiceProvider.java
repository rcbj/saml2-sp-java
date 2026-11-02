// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/** The service provider: login, the assertion consumer, and metadata. */
public final class ServiceProvider {
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final Map<String, String> BINDING_URI = Map.of(
        "post", Xml.BINDING_POST,
        "redirect", Xml.BINDING_REDIRECT,
        "artifact", Xml.BINDING_ARTIFACT
    );

    public final Config.Resolved config;
    private Metadata.IdpMetadata idp;
    private final MemoryReplayCache replayCache;

    public ServiceProvider(Config.Resolved config, Metadata.IdpMetadata idp, MemoryReplayCache replayCache) {
        this.config = config;
        this.idp = idp;
        this.replayCache = replayCache == null ? new MemoryReplayCache() : replayCache;
    }

    public static ServiceProvider create(Map<String, Object> config, String baseDir, MemoryReplayCache replayCache) {
        ServiceProvider provider = new ServiceProvider(Config.resolveConfig(config, baseDir), null, replayCache);
        provider.refreshMetadata();
        return provider;
    }

    public static ServiceProvider create(Map<String, Object> config) {
        return create(config, null, null);
    }

    public static ServiceProvider fromFile(String path, Map<String, Object> overrides, MemoryReplayCache replayCache) {
        ServiceProvider provider = new ServiceProvider(Config.readConfigFile(path, overrides), null, replayCache);
        provider.refreshMetadata();
        return provider;
    }

    public static ServiceProvider fromFile(String path) {
        return fromFile(path, null, null);
    }

    public static String postFormHtml(String action, Map<String, String> fields, String nonce) {
        return Bindings.postFormHtml(action, fields, nonce, null);
    }

    public Metadata.IdpMetadata idp() {
        if (idp == null) throw new SamlError("metadata", "the identity provider's metadata has not been loaded");
        return idp;
    }

    public Metadata.IdpMetadata refreshMetadata() {
        String source = config.idpMetadata;
        String xml;
        if (source.startsWith("<")) xml = source;
        else if (source.startsWith("http://") || source.startsWith("https://")) {
            Backchannel.Answer answer = Backchannel.send(source, "GET", Map.of(
                "accept", "application/samlmetadata+xml, application/xml, text/xml"
            ), null, tls(), "metadata");
            if (answer.status() != 200) throw new SamlError("metadata", source + " answered HTTP " + answer.status());
            xml = answer.body();
        } else {
            try {
                xml = Files.readString(Path.of(source), StandardCharsets.UTF_8);
            } catch (Exception err) {
                Caught.error(err);
                throw new SamlError("metadata", "the identity provider metadata file " + source + " cannot be read", err);
            }
        }
        idp = Metadata.readIdpMetadata(xml, config.idpEntityId);
        return idp;
    }

    public String metadata() {
        return Metadata.writeSpMetadata(config.entityId, config.acsUrl, config.certificate, config.wantAssertionsSigned, config.nameIdFormat);
    }

    public LoginRequest login() {
        return login(new LoginOptions());
    }

    public LoginRequest login(LoginOptions options) {
        if (options == null) options = new LoginOptions();
        String binding = options.requestBinding != null ? options.requestBinding : config.requestBinding;
        String response = options.responseBinding != null ? options.responseBinding : config.responseBinding;
        Metadata.IdpMetadata identity = idp();
        if ("artifact".equals(response) && identity.artifactResolutionServices.isEmpty()) {
            throw new SamlError("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact");
        }
        String destination = identity.ssoUrls.get(binding);
        if (destination == null || destination.isEmpty()) {
            String which = "post".equals(binding) ? "POST" : "Redirect";
            throw new SamlError("config", "the identity provider has no SingleSignOnService on HTTP-" + which);
        }
        if (options.relayState != null && options.relayState.getBytes(StandardCharsets.UTF_8).length > 80) {
            throw new SamlError("config", "relayState is longer than the 80 bytes the bindings allow");
        }
        byte[] random = new byte[20];
        new SecureRandom().nextBytes(random);
        String elementId = "_" + HexFormat.of().formatHex(random);
        String force = options.forceAuthn ? " ForceAuthn=\"true\"" : "";
        String passive = options.isPassive ? " IsPassive=\"true\"" : "";
        String subject = "";
        if (options.subjectHint != null) {
            String form = options.subjectHintFormat != null ? " Format=\"" + Xml.escape(options.subjectHintFormat) + "\"" : "";
            subject = "<saml:Subject><saml:NameID" + form + ">" + Xml.escape(options.subjectHint) + "</saml:NameID></saml:Subject>";
        }
        String policy = config.nameIdFormat != null
            ? "<samlp:NameIDPolicy Format=\"" + Xml.escape(config.nameIdFormat) + "\" AllowCreate=\"true\"/>"
            : "<samlp:NameIDPolicy AllowCreate=\"true\"/>";
        String xml = "<samlp:AuthnRequest xmlns:samlp=\"" + Xml.SAMLP + "\" xmlns:saml=\"" + Xml.SAML + "\" ID=\"" + elementId
            + "\" Version=\"2.0\" IssueInstant=\"" + ISO.format(Instant.now()) + "\" Destination=\"" + Xml.escape(destination)
            + "\" AssertionConsumerServiceURL=\"" + Xml.escape(config.acsUrl) + "\" ProtocolBinding=\"" + BINDING_URI.get(response)
            + "\"" + force + passive + "><saml:Issuer>" + Xml.escape(config.entityId) + "</saml:Issuer>" + subject + policy + "</samlp:AuthnRequest>";
        LoginRequest request = new LoginRequest();
        request.id = elementId;
        request.binding = binding;
        request.responseBinding = response;
        if ("redirect".equals(binding)) {
            String query = Bindings.redirectQuery("SAMLRequest", xml, options.relayState, config.privateKey);
            String join = destination.contains("?") ? "&" : "?";
            request.url = destination + join + query;
            request.xml = xml;
            return request;
        }
        String signed = XmlSignature.signEnveloped(xml, elementId, config.privateKey, config.certificate);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SAMLRequest", Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8)));
        if (options.relayState != null) fields.put("RelayState", options.relayState);
        request.url = destination;
        request.fields = fields;
        request.html = Bindings.postFormHtml(destination, fields, options.nonce, null);
        request.xml = signed;
        return request;
    }

    public SamlLogin acs(String method, String url) {
        return acs(method, url, null, null);
    }

    public SamlLogin acs(String method, String url, Object body) {
        return acs(method, url, body, null);
    }

    public SamlLogin acs(String method, String url, Object body, Object requestId) {
        Metadata.IdpMetadata identity = idp();
        String verb = method.toUpperCase();
        String rawQuery = url.contains("?") ? url.split("\\?", 2)[1].split("#", 2)[0] : "";
        Map<String, String> query = first(rawQuery);
        Map<String, String> form = "POST".equals(verb) ? formOf(body) : Map.of();
        List<String> expected = requestIds(requestId);
        ResponseValidator.Context ctx = new ResponseValidator.Context(
            config.entityId, config.acsUrl, identity.entityId, identity.signingCertificates, config.privateKey,
            config.clockSkewMs, config.wantAssertionsSigned, config.wantAssertionsEncrypted, config.allowUnsolicited,
            replayCache, expected, null
        );
        String samlArt = form.get("SAMLart") != null ? form.get("SAMLart") : query.get("SAMLart");
        if (samlArt != null) {
            Artifact.Resolved resolved = Artifact.resolveArtifact(
                samlArt, config.entityId, identity.entityId, identity.artifactResolutionServices,
                identity.signingCertificates, config.privateKey, config.certificate, tls()
            );
            String relay = form.containsKey("SAMLart") ? form.get("RelayState") : query.get("RelayState");
            return ResponseValidator.validate(new ResponseValidator.Received(
                resolved.xml(), resolved.response(), "artifact", relay, true
            ), ctx);
        }
        if ("POST".equals(verb) && form.get("SAMLResponse") != null) {
            String xml = Bindings.readPost(form.get("SAMLResponse"), "SAMLResponse");
            Element root = Xml.parse(xml, "the Response").getDocumentElement();
            return ResponseValidator.validate(new ResponseValidator.Received(xml, root, "post", form.get("RelayState"), false), ctx);
        }
        if (query.get("SAMLResponse") != null) {
            Map<String, Object> message = Bindings.readRedirect(rawQuery, "SAMLResponse", identity.signingCertificates);
            String xml = (String) message.get("xml");
            Element root = Xml.parse(xml, "the Response").getDocumentElement();
            return ResponseValidator.validate(new ResponseValidator.Received(
                xml, root, "redirect", (String) message.get("relayState"), Boolean.TRUE.equals(message.get("signed"))
            ), ctx);
        }
        throw new SamlError("binding", "the request carries no SAMLResponse or SAMLart");
    }

    private Map<String, String> tls() {
        return config.idpCa == null ? Map.of() : Map.of("ca", config.idpCa);
    }

    private static Map<String, String> first(String rawQuery) {
        Map<String, String> out = new LinkedHashMap<>();
        if (rawQuery.isEmpty()) return out;
        for (String pair : rawQuery.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = decode(eq < 0 ? pair : pair.substring(0, eq));
            String value = eq < 0 ? "" : decode(pair.substring(eq + 1));
            out.putIfAbsent(name, value);
        }
        return out;
    }

    private static Map<String, String> formOf(Object body) {
        if (body == null) return Map.of();
        if (body instanceof String text) return first(text);
        if (body instanceof Map<?, ?> map) {
            Map<String, String> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() instanceof String key && entry.getValue() instanceof String value) out.put(key, value);
            }
            return out;
        }
        return Map.of();
    }

    private static List<String> requestIds(Object requestId) {
        if (requestId == null) return List.of();
        if (requestId instanceof String text) return List.of(text);
        if (requestId instanceof Collection<?> collection) {
            List<String> out = new ArrayList<>();
            for (Object item : collection) if (item instanceof String text) out.add(text);
            return out;
        }
        return List.of();
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
