// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.pep.PepConfig;
import com.iyasec.pep.PepException;
import com.iyasec.pep.Subject;
import com.iyasec.pep.key.SigningKey;
import com.iyasec.saml.Caught;
import com.iyasec.saml.Keys;
import com.iyasec.saml.SamlError;
import com.iyasec.saml.SamlLogin;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Wires the shared {@code com.iyasec:iya-pep} package into this service provider.
 * The PEP knows no SAML: this class fills the {@code pep} section's defaults,
 * refuses a key this library already uses, and turns a validated sign-in into
 * the PEP's subject.
 */
public final class SamlPep {
    /** Attributes read as {@code amr}, in order. The Microsoft claim is AD FS. */
    public static final List<String> AMR_ATTRIBUTES = List.of(
        "amr",
        "http://schemas.microsoft.com/claims/authnmethodsreferences"
    );

    private static final ObjectMapper JSON = new ObjectMapper();

    private SamlPep() {}

    /**
     * The {@code pep} section with this library's defaults filled in, or null
     * when there is none. {@code pdpUrl} and {@code application} are filled
     * later, once the identity provider's entityID is known.
     */
    public static Map<String, Object> section(Map<String, Object> config, String baseDir, String idpCaPem) {
        if (config == null || !config.containsKey("pep") || config.get("pep") == null) return null;
        if (!(config.get("pep") instanceof Map<?, ?> raw)) throw new SamlError("config", "pep must be an object");
        Map<String, Object> map = new LinkedHashMap<>();
        raw.forEach((key, value) -> map.put(String.valueOf(key), value));
        if (map.get("assertionKey") instanceof String key) {
            String expanded = com.iyasec.saml.Config.expand(key);
            if (!expanded.isEmpty() && !Path.of(expanded).isAbsolute()) {
                String root = baseDir == null ? "" : baseDir;
                map.put("assertionKey", Path.of(root).resolve(expanded).normalize().toAbsolutePath().toString());
            } else {
                map.put("assertionKey", expanded);
            }
        }
        if (!map.containsKey("signals")) {
            boolean receiver = config.get("ssf") instanceof Map<?, ?> && !Boolean.FALSE.equals(config.get("signals"));
            map.put("signals", receiver);
        }
        if (!map.containsKey("tlsCa") && idpCaPem != null && !idpCaPem.isEmpty()) {
            map.put("tlsCa", idpCaPem);
        }
        return map;
    }

    /**
     * Builds the PEP from the resolved section. Checks that its key is not
     * the service provider's and not the receiver's TLS client key. Sends
     * nothing; {@link Pep#start()} does.
     */
    public static Pep build(Map<String, Object> section, String idpEntityId, String entityId, String spKeyPem, String ssfClientKeyPem) {
        JsonNode node = JSON.valueToTree(section);
        PepConfig config;
        try {
            config = PepConfig.fromJson(node, idpEntityId == null ? "" : idpEntityId, entityId == null ? "" : entityId);
        } catch (PepException err) {
            String detail = err.detail();
            if (!section.containsKey("pdpUrl") && detail != null && detail.startsWith("pep.pdpUrl")) {
                detail = detail + ": the identity provider's entityID is not iya-sts's URL, so name the service in pep.pdpUrl";
            }
            throw new SamlError("config", detail, err);
        }
        Pep pep;
        try {
            pep = Pep.create(config);
        } catch (PepException err) {
            throw new SamlError("config", err.detail(), err);
        }
        if (sameThumbprint(spKeyPem, pep.keyThumbprint())) {
            throw new SamlError("config", "pep.assertionKey is the service provider's privateKey (its signing, decryption and TLS client key); the PEP needs a key of its own");
        }
        if (ssfClientKeyPem != null && sameThumbprint(ssfClientKeyPem, pep.keyThumbprint())) {
            throw new SamlError("config", "pep.assertionKey is ssf.clientKey (the Shared Signals receiver's TLS client key); the PEP needs a key of its own");
        }
        return pep;
    }

    /** Whether a receiver given this PEP asks for {@code pep-policies-changed}. */
    public static boolean wantsEvents(Pep pep) {
        PepConfig config = pep.config();
        return config.mode == Mode.LOCAL || config.permitCacheMs > 0;
    }

    /**
     * The PEP's subject for a validated SAML sign-in. The id is the username
     * ({@link SamlLogin#username()}), else the NameID. Attributes, {@code acr},
     * {@code amr} and {@code auth_time} are properties. No request header is read.
     */
    public static Subject subjectOf(SamlLogin login) {
        String id = login.username();
        if (id == null || id.isEmpty()) id = login.nameId == null ? "" : login.nameId;
        Map<String, JsonNode> properties = new LinkedHashMap<>();
        Map<String, List<String>> attributes = login.attributes == null ? Map.of() : login.attributes;
        for (String name : new TreeSet<>(attributes.keySet())) {
            properties.put(name, JSON.valueToTree(oneOrMany(attributes.get(name))));
        }
        if (login.attributeFriendlyNames != null) {
            for (String name : new TreeSet<>(attributes.keySet())) {
                String friendly = login.attributeFriendlyNames.get(name);
                if (friendly != null && !friendly.isEmpty() && !properties.containsKey(friendly)) {
                    properties.put(friendly, JSON.valueToTree(oneOrMany(attributes.get(name))));
                }
            }
        }
        for (String name : AMR_ATTRIBUTES) {
            if (attributes.containsKey(name)) {
                List<String> values = attributes.get(name);
                properties.put("amr", JSON.valueToTree(values == null ? List.of() : List.copyOf(values)));
                break;
            }
        }
        if (login.authnContextClassRef != null && !login.authnContextClassRef.isEmpty()) {
            properties.put("acr", JSON.valueToTree(login.authnContextClassRef));
        }
        if (login.authnInstant != null && login.authnInstant.toEpochMilli() > 0) {
            properties.put("auth_time", JSON.valueToTree(login.authnInstant.getEpochSecond()));
        }
        return Subject.user(id, properties);
    }

    /** A Deny that did not ask the engine: no session, or one that has ended. */
    public static Decision deny(String why) {
        return Decision.deny(why);
    }

    /** No PEP is configured, so nothing is permitted. */
    public static Decision unavailable(String why) {
        return Decision.unavailable(why);
    }

    /** The event body as the JSON the PEP's {@code onPolicyEvent} takes. */
    public static JsonNode toJson(Object value) {
        return JSON.valueToTree(value == null ? Map.of() : value);
    }

    /** {@link Pep#status()} as a map a health page can write. It holds no secret. */
    public static Map<String, Object> statusMap(Pep pep) {
        try {
            JsonNode node = JSON.valueToTree(pep.status());
            Map<String, Object> out = new LinkedHashMap<>();
            node.fields().forEachRemaining(field -> out.put(field.getKey(), JSON.convertValue(field.getValue(), Object.class)));
            return out;
        } catch (RuntimeException err) {
            Caught.warn(err);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("error", "status could not be read");
            return out;
        }
    }

    /** True when {@code pem}'s JWK thumbprint is {@code thumbprint}. */
    public static boolean sameThumbprint(String pem, String thumbprint) {
        if (pem == null || pem.isEmpty() || thumbprint == null || thumbprint.isEmpty()) return false;
        String fromPem;
        try {
            fromPem = SigningKey.pemThumbprint(pem);
        } catch (Exception err) {
            Caught.warn(err);
            fromPem = null;
        }
        if (thumbprint.equals(fromPem)) return true;
        String fromJwk = rsaJwkThumbprint(pem);
        return thumbprint.equals(fromJwk);
    }

    private static String rsaJwkThumbprint(String pem) {
        try {
            if (!(Keys.loadPrivateKey(pem) instanceof RSAPrivateCrtKey rsa)) return null;
            var jwk = JSON.createObjectNode();
            jwk.put("kty", "RSA");
            jwk.put("n", b64(unsigned(rsa.getModulus())));
            jwk.put("e", b64(unsigned(rsa.getPublicExponent())));
            return SigningKey.jwkThumbprint(jwk);
        } catch (Exception err) {
            Caught.warn(err);
            return null;
        }
    }

    private static Object oneOrMany(List<String> values) {
        if (values == null || values.isEmpty()) return List.of();
        if (values.size() == 1) return values.get(0);
        return new ArrayList<>(values);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
