// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.ssf;

import com.iyasec.saml.Caught;
import com.iyasec.saml.Json;
import com.iyasec.saml.SamlError;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Verifying a Security Event Token (a compact JWS) against the transmitter's published keys. */
public final class Jws {
    public static final List<String> SUPPORTED = List.of(
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"
    );
    private static final Map<String, String> KTY = Map.ofEntries(
        Map.entry("RS256", "RSA"), Map.entry("RS384", "RSA"), Map.entry("RS512", "RSA"),
        Map.entry("PS256", "RSA"), Map.entry("PS384", "RSA"), Map.entry("PS512", "RSA"),
        Map.entry("ES256", "EC"), Map.entry("ES384", "EC"), Map.entry("ES512", "EC"),
        Map.entry("EdDSA", "OKP"), Map.entry("Ed25519", "OKP")
    );
    private static final Set<String> RSA = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");
    private static final Set<String> EC = Set.of("ES256", "ES384", "ES512");

    public record Verified(Map<String, Object> header, Map<String, Object> payload) {}

    private Jws() {}

    public static Verified verifyCompact(String token, List<Map<String, Object>> keys) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) throw new SamlError("signature", "the SET is not a compact JWS");
        Map<String, Object> header = jsonObject(parts[0], "header");
        Map<String, Object> payload = jsonObject(parts[1], "payload");
        String alg = header.get("alg") == null ? "" : String.valueOf(header.get("alg"));
        if (!KTY.containsKey(alg)) {
            throw new SamlError("signature", "the SET is signed with " + (alg.isEmpty() ? "(no alg)" : alg)
                + ", which this receiver does not verify (" + String.join(", ", SUPPORTED) + ")");
        }
        if (header.containsKey("crit")) {
            throw new SamlError("signature", "the SET's header has a crit member this receiver does not understand");
        }
        String kid = header.get("kid") instanceof String text ? text : null;
        String kty = KTY.get(alg);
        List<Map<String, Object>> candidates = keys.stream().filter(key ->
            (kid == null || kid.equals(key.get("kid"))) && kty.equals(key.get("kty"))
                && (key.get("use") == null || "sig".equals(key.get("use")))
                && (key.get("alg") == null || alg.equals(key.get("alg")))
        ).toList();
        if (candidates.isEmpty()) {
            throw new SamlError("signature", "the transmitter publishes no " + kty + " signing key" + (kid == null ? "" : " with kid " + kid));
        }
        b64(parts[2], "signature");
        for (Map<String, Object> jwk : candidates) {
            if (verifyOne(token, alg, jwk)) return new Verified(header, payload);
        }
        throw new SamlError("signature", "the SET's signature does not verify against the transmitter's keys");
    }

    private static boolean verifyOne(String token, String alg, Map<String, Object> jwk) {
        try {
            Map<String, Object> json = new LinkedHashMap<>();
            jwk.forEach((key, item) -> json.put(String.valueOf(key), item));
            JWK parsed = JWK.parse(json);
            JWSObject object = JWSObject.parse(token);
            if (RSA.contains(alg)) return object.verify(new RSASSAVerifier((RSAKey) parsed));
            if (EC.contains(alg)) return object.verify(new ECDSAVerifier((ECKey) parsed));
            return object.verify(new Ed25519Verifier((OctetKeyPair) parsed));
        } catch (Exception err) {
            Caught.warn(err);
            return false;
        }
    }

    private static Map<String, Object> jsonObject(String part, String what) {
        try {
            Object parsed = Json.parse(new String(b64(part, what), StandardCharsets.UTF_8));
            if (!(parsed instanceof Map<?, ?> object)) throw new SamlError("signature", "the SET's header or payload is not a JSON object");
            Map<String, Object> out = new LinkedHashMap<>();
            object.forEach((key, item) -> out.put(String.valueOf(key), item));
            return out;
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("signature", "the SET's header or payload is not JSON", err);
        }
    }

    private static byte[] b64(String value, String what) {
        if (!value.matches("[A-Za-z0-9_-]*")) throw new SamlError("signature", "the SET's " + what + " is not base64url");
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (Exception err) {
            Caught.error(err);
            throw new SamlError("signature", "the SET's " + what + " is not base64url", err);
        }
    }
}
