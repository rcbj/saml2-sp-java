// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.saml.ssf.Events;
import com.iyasec.saml.ssf.Jws;
import com.iyasec.saml.ssf.MemorySessionIndex;
import com.iyasec.saml.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SsfTest {
    private static java.security.KeyPair privateKey;
    private static java.security.KeyPair other;
    private static Map<String, Object> jwk;
    private static Transmitter stub;

    @BeforeAll
    static void up() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        privateKey = generator.generateKeyPair();
        other = generator.generateKeyPair();
        jwk = jwk(privateKey, "k1");
        stub = start();
    }

    @AfterAll
    static void down() { if (stub != null) stub.server.stop(0); }

    @Test
    void verifiesASetAgainstTheJwks() throws Exception {
        Map<String, Object> payload = Jws.verifyCompact(jws(Map.of("a", 1), privateKey, null), List.of(jwk)).payload();
        assertEquals(1L, ((Number) payload.get("a")).longValue());
        SamlError bad = assertThrows(SamlError.class, () -> Jws.verifyCompact(jws(Map.of("a", 1), other, null), List.of(jwk)));
        assertTrue(bad.getMessage().contains("does not verify"));
        SamlError kid = assertThrows(SamlError.class, () -> Jws.verifyCompact(jws(Map.of("a", 1), privateKey, Map.of("alg", "RS256", "kid", "nope")), List.of(jwk)));
        assertTrue(kid.getMessage().contains("no RSA signing key with kid nope"));
        SamlError none = assertThrows(SamlError.class, () -> Jws.verifyCompact(jws(Map.of("a", 1), privateKey, Map.of("alg", "none")), List.of(jwk)));
        assertTrue(none.getMessage().contains("does not verify"));
        SamlError mac = assertThrows(SamlError.class, () -> Jws.verifyCompact(jws(Map.of("a", 1), privateKey, Map.of("alg", "HS256", "kid", "k1")), List.of(jwk)));
        assertTrue(mac.getMessage().contains("does not verify"));
    }

    @Test
    void readsComplexIssSubAndEmailSubjects() {
        Map<String, Object> complex = new LinkedHashMap<>();
        complex.put("format", "complex");
        complex.put("user", Map.of("format", "iss_sub", "iss", "https://i", "sub", "urn:uuid:a"));
        complex.put("session", Map.of("format", "opaque", "id", "S1"));
        assertEquals(Map.of("person", "urn:uuid:a", "idpSession", "S1"), Events.subjectOf(complex, "https://i"));
        assertEquals(Map.of(), Events.subjectOf(Map.of("format", "iss_sub", "iss", "https://other", "sub", "urn:uuid:a"), "https://i"));
        assertEquals(Map.of("email", "A@x.com"), Events.subjectOf(Map.of("format", "email", "email", "A@x.com"), "https://i"));
    }

    @Test
    void createsItsPollStreamOnceAndAcknowledges() {
        List<List<String>> ended = new ArrayList<>();
        List<com.iyasec.saml.ssf.SignalEvent> seen = new ArrayList<>();
        SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> ended.add(new ArrayList<>(ids)))
            .pollIntervalMs(60_000).log(quiet()).on("*", seen::add);
        receiver.start();
        receiver.stop();
        assertEquals(1, stub.created);
        assertEquals("s1", receiver.stream().get("stream_id"));
        receiver.track("L-a1", login("alice", "IDP-A1"));
        receiver.track("L-a2", login("alice", "IDP-A2"));
        receiver.track("L-b1", login("bob", "IDP-B1"));
        String j1 = put(Events.EVENT.get("session_revoked"), complex(stub.url, "alice", "IDP-A1"), null);
        String j2 = put(Events.EVENT.get("credential_change"), complex(stub.url, "bob", null), Map.of("credential_type", "password", "change_type", "update"));
        receiver.pollOnce();
        assertEquals(List.of(List.of("L-a1")), ended);
        com.iyasec.saml.ssf.SignalEvent found = seen.stream().filter(event -> j2.equals(event.jti)).findFirst().orElseThrow();
        assertFalse(found.ended);
        assertEquals(List.of("L-b1"), found.sessions);
        String j3 = put(Events.EVENT.get("account_disabled"), Map.of("format", "iss_sub", "iss", stub.url, "sub", "urn:uuid:alice"), null);
        receiver.pollOnce();
        assertEquals(List.of(List.of("L-a1"), List.of("L-a2")), ended);
        assertTrue(stub.acked.contains(j1) && stub.acked.contains(j2));
        put(Events.EVENT.get("credential_compromise"), Map.of("format", "email", "email", "BOB@example.com"), Map.of("credential_type", "password"));
        receiver.pollOnce();
        assertEquals(List.of("L-b1"), ended.get(2));
        receiver.pollOnce();
        assertTrue(stub.acked.contains(j3));
        SignalsReceiver again = new SignalsReceiver(stub.url, (ids, event) -> { }).log(quiet());
        again.start();
        again.stop();
        assertEquals(1, stub.created);
        assertEquals("s1", again.stream().get("stream_id"));
    }

    @Test
    void refusesAForgedMisaddressedOrForeignSet() {
        List<List<String>> ended = new ArrayList<>();
        MemorySessionIndex index = new MemorySessionIndex();
        SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> ended.add(ids)).sessionIndex(index).log(quiet());
        receiver.start();
        receiver.stop();
        receiver.track("L-c1", login("carol", "IDP-C1"));
        Map<String, Object> subject = complex(stub.url, "carol", "IDP-C1");
        String forged = put(Events.EVENT.get("session_revoked"), subject, null, other, "my-app", null);
        String misaddressed = put(Events.EVENT.get("session_revoked"), subject, null, privateKey, "someone-else", null);
        String foreign = put(Events.EVENT.get("session_revoked"), subject, null, privateKey, "my-app", "https://evil.example");
        receiver.pollOnce();
        assertEquals(List.of(), ended);
        assertEquals(List.of("L-c1"), index.byPerson("urn:uuid:carol"));
        receiver.pollOnce();
        assertTrue(stub.errs.containsKey(forged) && stub.errs.containsKey(misaddressed) && stub.errs.containsKey(foreign));
    }

    @Test
    void namesAllEightCaepAndFourteenRiscEventTypes() {
        assertEquals(8, Events.CAEP_EVENTS.size());
        assertEquals(14, Events.RISC_EVENTS.size());
        assertTrue(Events.CAEP_EVENTS.contains(Events.EVENT.get("risk_level_change")));
        assertTrue(Events.RISC_EVENTS.contains(Events.EVENT.get("opt_out_effective")));
    }

    @Test
    void acknowledgesAValidSetWhoseHandlerThrows() {
        List<String> errors = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        SignalsReceiver.Log log = new SignalsReceiver.Log() {
            public void info(String message) {}
            public void warn(String message) {}
            public void error(String message) { errors.add(message); }
        };
        SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> { throw new IllegalStateException("store down"); }).log(log);
        receiver.on(Events.EVENT.get("credential_change"), event -> { throw new IllegalStateException("handler bug"); });
        receiver.on("*", event -> seen.add(event.jti));
        receiver.start();
        receiver.stop();
        receiver.track("L-d1", login("dave", "IDP-D1"));
        String j1 = put(Events.EVENT.get("credential_change"), complex(stub.url, "dave", null), Map.of("credential_type", "password", "change_type", "update"));
        String j2 = put(Events.EVENT.get("session_revoked"), complex(stub.url, "dave", "IDP-D1"), null);
        receiver.pollOnce();
        receiver.pollOnce();
        receiver.pollOnce();
        assertTrue(stub.acked.contains(j1) && stub.acked.contains(j2));
        assertFalse(stub.errs.containsKey(j1) || stub.errs.containsKey(j2));
        assertEquals(seen.stream().sorted().toList(), List.of(j1, j2).stream().sorted().toList());
        assertTrue(errors.stream().anyMatch(message -> message.matches("(?s).*handler for .*credential-change threw.*")));
        assertTrue(errors.stream().anyMatch(message -> message.contains("onEndSessions threw")));
    }

    @Test
    void neverRunsTwoPollsAtOnce() throws Exception {
        List<String> seen = new ArrayList<>();
        SignalsReceiver receiver = new SignalsReceiver(stub.url, (ids, event) -> { }).log(quiet()).on("*", event -> seen.add(event.jti));
        receiver.start();
        receiver.stop();
        String jti = put(Events.EVENT.get("account_enabled"), Map.of("format", "iss_sub", "iss", stub.url, "sub", "urn:uuid:erin"), null);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 3; i++) threads.add(new Thread(receiver::pollOnce));
        for (Thread thread : threads) thread.start();
        for (Thread thread : threads) thread.join();
        receiver.pollOnce();
        assertEquals(List.of(jti), seen.stream().filter(jti::equals).toList());
    }

    @Test
    void refusesATransmitterWithoutPollDelivery() {
        SignalsReceiver receiver = new SignalsReceiver("http://127.0.0.1:1", (ids, event) -> { }).log(quiet());
        SamlError err = assertThrows(SamlError.class, receiver::start);
        assertEquals("ssf", err.code);
    }

    private static SignalsReceiver.Log quiet() {
        return new SignalsReceiver.Log() {
            public void info(String message) {}
            public void warn(String message) {}
            public void error(String message) {}
        };
    }

    private static SamlLogin login(String person, String sessionIndex) {
        SamlLogin login = new SamlLogin();
        login.nameId = person;
        login.sessionIndex = sessionIndex;
        login.attributes = new LinkedHashMap<>();
        login.attributes.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", List.of("urn:uuid:" + person));
        login.attributes.put("urn:oid:0.9.2342.19200300.100.1.3", List.of(person + "@example.com"));
        return login;
    }

    private static Map<String, Object> complex(String issuer, String person, String session) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("format", "complex");
        subject.put("user", Map.of("format", "iss_sub", "iss", issuer, "sub", "urn:uuid:" + person));
        if (session != null) subject.put("session", Map.of("format", "opaque", "id", session));
        return subject;
    }

    private static String put(String type, Map<String, Object> subId, Map<String, Object> extra) {
        return put(type, subId, extra, privateKey, "my-app", null);
    }

    private static String put(String type, Map<String, Object> subId, Map<String, Object> extra, java.security.KeyPair key, String aud, String iss) {
        String jti = UUID.randomUUID().toString();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event_timestamp", 1);
        if (extra != null) event.putAll(extra);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss == null ? stub.url : iss);
        payload.put("aud", aud);
        payload.put("jti", jti);
        payload.put("iat", 1);
        payload.put("sub_id", subId);
        payload.put("events", Map.of(type, event));
        stub.queue.put(jti, jws(payload, key, null));
        return jti;
    }

    private static String jws(Map<String, Object> payload, java.security.KeyPair key, Map<String, String> header) {
        try {
            Map<String, String> head = header == null ? new LinkedHashMap<>(Map.of("alg", "RS256", "kid", "k1", "typ", "secevent+jwt")) : new LinkedHashMap<>(header);
            String h = b64(Json.stringify(head).getBytes(StandardCharsets.UTF_8));
            String p = b64(Json.stringify(payload).getBytes(StandardCharsets.UTF_8));
            String alg = head.get("alg");
            String sig = alg == null || "none".equals(alg) || "HS256".equals(alg) ? "" : b64(sign(key, (h + "." + p).getBytes(StandardCharsets.UTF_8)));
            return h + "." + p + "." + sig;
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static byte[] sign(java.security.KeyPair key, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    private static Map<String, Object> jwk(java.security.KeyPair key, String kid) {
        RSAPublicKey publicKey = (RSAPublicKey) key.getPublic();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kty", "RSA");
        out.put("n", b64(unsigned(publicKey.getModulus().toByteArray())));
        out.put("e", b64(unsigned(publicKey.getPublicExponent().toByteArray())));
        out.put("kid", kid);
        out.put("alg", "RS256");
        out.put("use", "sig");
        return out;
    }

    private static byte[] unsigned(byte[] bytes) {
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

    private static Transmitter start() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        Transmitter transmitter = new Transmitter(server);
        server.createContext("/", exchange -> dispatch(exchange, transmitter));
        server.setExecutor(Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "stub-ssf");
            thread.setDaemon(true);
            return thread;
        }));
        server.start();
        transmitter.url = "http://127.0.0.1:" + server.getAddress().getPort();
        return transmitter;
    }

    private static void dispatch(HttpExchange exchange, Transmitter transmitter) throws java.io.IOException {
        String path = exchange.getRequestURI().getPath();
        String text = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if ("/.well-known/ssf-configuration".equals(path)) {
            send(exchange, 200, Map.of(
                "issuer", transmitter.url,
                "jwks_uri", transmitter.url + "/jwks",
                "configuration_endpoint", transmitter.url + "/ssf/stream",
                "verification_endpoint", transmitter.url + "/ssf/verify",
                "delivery_methods_supported", List.of("urn:ietf:rfc:8936")
            ));
            return;
        }
        if ("/jwks".equals(path)) {
            send(exchange, 200, Map.of("keys", List.of(jwk)));
            return;
        }
        if ("/ssf/stream".equals(path) && "GET".equals(exchange.getRequestMethod())) {
            send(exchange, 200, transmitter.streams);
            return;
        }
        if ("/ssf/stream".equals(path) && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = asMap(Json.parse(text));
            transmitter.created += 1;
            Map<String, Object> delivery = Map.of("method", ((Map<?, ?>) body.get("delivery")).get("method"), "endpoint_url", transmitter.url + "/ssf/poll/s" + transmitter.created);
            Map<String, Object> stream = new LinkedHashMap<>();
            stream.put("stream_id", "s" + transmitter.created);
            stream.put("iss", transmitter.url);
            stream.put("aud", "my-app");
            stream.put("delivery", delivery);
            stream.put("events_requested", body.get("events_requested"));
            stream.put("events_delivered", body.get("events_requested"));
            transmitter.streams.add(stream);
            send(exchange, 201, stream);
            return;
        }
        if (path.startsWith("/ssf/poll/")) {
            Map<String, Object> body = text.isEmpty() ? new LinkedHashMap<>() : asMap(Json.parse(text));
            Object ack = body.get("ack");
            if (ack instanceof List<?> list) {
                for (Object jti : list) {
                    transmitter.acked.add(String.valueOf(jti));
                    transmitter.queue.remove(String.valueOf(jti));
                }
            }
            Object errs = body.get("setErrs");
            if (errs instanceof Map<?, ?> map) {
                map.forEach((key, value) -> transmitter.errs.put(String.valueOf(key), value));
                for (Object key : map.keySet()) transmitter.queue.remove(String.valueOf(key));
            }
            send(exchange, 200, Map.of("sets", new LinkedHashMap<>(transmitter.queue), "moreAvailable", false));
            return;
        }
        send(exchange, 404, Map.of("err", "not found"));
    }

    private static void send(HttpExchange exchange, int status, Object body) throws java.io.IOException {
        byte[] raw = body == null ? new byte[0] : Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("content-type", "application/json");
        exchange.sendResponseHeaders(status, raw.length);
        exchange.getResponseBody().write(raw);
        exchange.close();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }

    private static final class Transmitter {
        final HttpServer server;
        final Map<String, String> queue = new LinkedHashMap<>();
        final List<String> acked = new ArrayList<>();
        final Map<String, Object> errs = new LinkedHashMap<>();
        final List<Map<String, Object>> streams = new ArrayList<>();
        int created;
        String url = "";
        Transmitter(HttpServer server) { this.server = server; }
    }
}
