// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** The configuration: seven settings, four of them with defaults. The rest is in the identity provider's metadata. */
public final class Config {
    private static final Set<String> REQUEST = Set.of("redirect", "post");
    private static final Set<String> RESPONSE = Set.of("post", "redirect", "artifact");

    /**
     * The configuration with its files read and its defaults filled in.
     * {@code signals} is present only when CAEP and RISC are off. Omitted means on.
     */
    public static final class Resolved {
        public final String entityId;
        public final String acsUrl;
        public final PrivateKey privateKey;
        public final String privateKeyPem;
        public final X509Certificate certificate;
        public final String certificatePem;
        public final String idpMetadata;
        public final String requestBinding;
        public final String responseBinding;
        public final int clockSkewMs;
        public final boolean wantAssertionsSigned;
        public final boolean wantAssertionsEncrypted;
        public final boolean allowUnsolicited;
        public final String idpCa;
        public final String idpEntityId;
        public final String nameIdFormat;
        /** Null when the receiver stays on. {@code false} when it is off. */
        public final Boolean signals;

        Resolved(String entityId, String acsUrl, PrivateKey privateKey, String privateKeyPem, X509Certificate certificate,
                 String certificatePem, String idpMetadata, String requestBinding, String responseBinding, int clockSkewMs,
                 boolean wantAssertionsSigned, boolean wantAssertionsEncrypted, boolean allowUnsolicited, String idpCa,
                 String idpEntityId, String nameIdFormat, Boolean signals) {
            this.entityId = entityId;
            this.acsUrl = acsUrl;
            this.privateKey = privateKey;
            this.privateKeyPem = privateKeyPem;
            this.certificate = certificate;
            this.certificatePem = certificatePem;
            this.idpMetadata = idpMetadata;
            this.requestBinding = requestBinding;
            this.responseBinding = responseBinding;
            this.clockSkewMs = clockSkewMs;
            this.wantAssertionsSigned = wantAssertionsSigned;
            this.wantAssertionsEncrypted = wantAssertionsEncrypted;
            this.allowUnsolicited = allowUnsolicited;
            this.idpCa = idpCa;
            this.idpEntityId = idpEntityId;
            this.nameIdFormat = nameIdFormat;
            this.signals = signals;
        }

        public boolean contains(String key) {
            return "signals".equals(key) && signals != null;
        }
    }

    private Config() {}

    public static Resolved resolveConfig(Map<String, Object> config, String baseDir) {
        if (config == null) throw new SamlError("config", "the configuration must be an object");
        String base = baseDir == null || baseDir.isEmpty() ? Path.of("").toAbsolutePath().toString() : baseDir;
        Object entityRaw = config.get("entityId");
        if (!(entityRaw instanceof String entityId) || entityId.isBlank()) throw new SamlError("config", "entityId is required");
        String acsUrl = absoluteUrl(config.get("acsUrl"), "acsUrl");
        if (!(config.get("privateKey") instanceof String) || !(config.get("certificate") instanceof String)) {
            throw new SamlError("config", "privateKey and certificate are required: every AuthnRequest is signed");
        }
        PrivateKey privateKey;
        X509Certificate certificate;
        try {
            String keyPem = material((String) config.get("privateKey"), base, "privateKey");
            String certPem = material((String) config.get("certificate"), base, "certificate");
            privateKey = Keys.loadPrivateKey(keyPem);
            certificate = Keys.loadCertificate(certPem);
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("config", "the private key or certificate cannot be read: " + err.getMessage(), err);
        }
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new SamlError("config", "the private key is " + privateKey.getAlgorithm() + "; an RSA key is required");
        }
        if (!Keys.sameKey(privateKey, certificate)) throw new SamlError("config", "the certificate is not for the private key");
        Object idpRaw = config.get("idpMetadata");
        if (!(idpRaw instanceof String idpMetadata) || idpMetadata.isBlank()) throw new SamlError("config", "idpMetadata is required");
        idpMetadata = expand(idpMetadata.strip());
        if (!idpMetadata.matches("(?i)https?://.*") && !idpMetadata.startsWith("<")) {
            Path path = Path.of(idpMetadata);
            idpMetadata = path.isAbsolute() ? path.toString() : Path.of(base).resolve(path).normalize().toAbsolutePath().toString();
        }
        Object skewRaw = config.containsKey("clockSkewSeconds") && config.get("clockSkewSeconds") != null ? config.get("clockSkewSeconds") : 60;
        if (!(skewRaw instanceof Number skew) || skew.doubleValue() < 0 || skew.doubleValue() > 600 || !Double.isFinite(skew.doubleValue())) {
            throw new SamlError("config", "clockSkewSeconds must be a number from 0 to 600");
        }
        if (config.containsKey("signals") && !(config.get("signals") instanceof Boolean)) {
            throw new SamlError("config", "signals must be true or false");
        }
        Boolean signals = Boolean.FALSE.equals(config.get("signals")) ? Boolean.FALSE : null;
        String idpCa = config.get("idpCa") instanceof String ca && !ca.isBlank() ? material(ca, base, "idpCa") : null;
        String idpEntityId = config.get("idpEntityId") instanceof String id && !id.isBlank() ? id : null;
        String nameIdFormat = config.get("nameIdFormat") instanceof String format && !format.isBlank() ? format : null;
        return new Resolved(
            entityId, acsUrl, privateKey, Keys.privateKeyPem(privateKey), certificate, Keys.certificatePem(certificate),
            idpMetadata, oneOf(config.get("requestBinding"), REQUEST, "redirect", "requestBinding"),
            oneOf(config.get("responseBinding"), RESPONSE, "post", "responseBinding"), skew.intValue() * 1000,
            flag(config, "wantAssertionsSigned", true), flag(config, "wantAssertionsEncrypted", false),
            flag(config, "allowUnsolicited", false), idpCa, idpEntityId, nameIdFormat, signals
        );
    }

    public static Resolved readConfigFile(String path, Map<String, Object> overrides) {
        Object parsed;
        try {
            parsed = Json.parse(Files.readString(Path.of(path), StandardCharsets.UTF_8));
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("config", path + " cannot be read as JSON: " + err.getMessage(), err);
        }
        if (!(parsed instanceof Map<?, ?> object)) throw new SamlError("config", "the configuration must be an object");
        Map<String, Object> merged = new LinkedHashMap<>();
        object.forEach((key, value) -> merged.put(String.valueOf(key), value));
        if (overrides != null) {
            for (Map.Entry<String, Object> entry : overrides.entrySet()) {
                if (entry.getValue() != null) merged.put(entry.getKey(), entry.getValue());
            }
        }
        return resolveConfig(merged, Path.of(path).toAbsolutePath().getParent().toString());
    }

    static String expand(String value) {
        int seen = 0;
        while (value.startsWith("env:") || value.startsWith("file:")) {
            seen += 1;
            if (seen > 4) throw new SamlError("config", "the placeholder " + value + " is nested too deeply");
            if (value.startsWith("env:")) {
                String name = value.substring(4);
                String got = name.isEmpty() ? null : System.getenv(name);
                if (got == null) throw new SamlError("config", "environment variable " + (name.isEmpty() ? value : name) + " is not set");
                value = got;
                continue;
            }
            value = value.substring(5);
        }
        return value;
    }

    static String material(String value, String baseDir, String what) {
        value = expand(value);
        if (value.contains("-----BEGIN ")) return value;
        Path path = Path.of(value);
        Path resolved = path.isAbsolute() ? path : Path.of(baseDir).resolve(path).normalize().toAbsolutePath();
        try {
            return Files.readString(resolved, StandardCharsets.UTF_8);
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("config", what + " is neither a PEM nor a readable file (" + resolved + ")", err);
        }
    }

    private static String absoluteUrl(Object value, String what) {
        if (!(value instanceof String text) || text.isBlank()) throw new SamlError("config", what + " is required");
        if (!text.matches("(?i)https?://.*")) throw new SamlError("config", what + " must be an absolute http(s) URL, not " + text);
        return text;
    }

    private static String oneOf(Object value, Set<String> allowed, String fallback, String what) {
        if (value == null || "".equals(value)) return fallback;
        if (!allowed.contains(String.valueOf(value))) {
            throw new SamlError("config", what + " must be one of " + String.join(", ", allowed) + ", not " + value);
        }
        return String.valueOf(value);
    }

    private static boolean flag(Map<String, Object> config, String key, boolean fallback) {
        if (!config.containsKey(key) || config.get(key) == null) return fallback;
        Object value = config.get(key);
        if (!(value instanceof Boolean)) throw new SamlError("config", key + " must be true or false");
        return (Boolean) value;
    }
}
